from __future__ import annotations

import json
import re
import secrets
import time
from functools import lru_cache
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlparse, urlunparse

import requests

from . import mail_provider
from .config import DATA_DIR
from .register_core import (
    RegistrationResult,
    PlatformRegistrar,
    _random_birthdate,
    _random_name,
    _random_password,
    _generate_pkce,
    _decode_jwt_payload,
    _make_trace_headers,
    build_sentinel_token,
    get_common_headers,
    get_navigate_headers,
    auth_base,
    platform_oauth_audience,
    platform_oauth_client_id,
    request_with_local_retry,
    _response_json,
    save_result,
    exchange_platform_tokens,
    _about_you_page_shape,
    _about_you_consent_fields,
    extract_oauth_callback_params_from_consent_session,
    extract_oauth_callback_params_from_url,
    _is_socks_proxy,
)


DEFAULT_SUB2API_EXPORT_NAME = "export_accounts.json"
DEFAULT_ACCOUNT_ARCHIVE_NAME = "last_sub2api_account_archive.json"
PARTIAL_HERO_PHONE_BIND_RESULT_NAME = "hero_phone_bind_partial_result.json"
HERO_SMS_RESEND_AFTER_SECONDS = 30
HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS = 60
HERO_SMS_RELEASE_AFTER_SECONDS = 120
HERO_SMS_MAX_RETRY_COUNT = 3
SMSBOWER_BASE_URL = "https://smsbower.page/stubs/handler_api.php"
FIVESIM_BASE_URL = "https://5sim.net/v1"


@dataclass
class HeroSMSConfig:
    provider: str = "hero_sms"
    api_key: str = ""
    base_url: str = "https://hero-sms.com/stubs/handler_api.php"
    country: str = "16"
    service: str = "dr"
    min_price: float = 0.0
    max_price: float = 0.05
    wait_timeout: int = 60
    wait_interval: int = 5
    auto_retry: bool = False
    resend_after_seconds: int = HERO_SMS_RESEND_AFTER_SECONDS
    timeout_after_resend_seconds: int = HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS
    release_after_seconds: int = HERO_SMS_RELEASE_AFTER_SECONDS
    max_retry_count: int = HERO_SMS_MAX_RETRY_COUNT


@dataclass
class Sub2APIOAuthFlowConfig:
    proxy: str = ""
    redirect_uri: str = "http://localhost:1455/auth/callback"
    login_hint: str = ""
    account_name: str = ""
    concurrency: int = 10
    priority: int = 1
    rate_multiplier: int = 1
    auto_pause_on_expired: bool = True
    plan_type: str = "free"
    privacy_mode: str = "training_off"
    export_name: str = DEFAULT_SUB2API_EXPORT_NAME
    archive_name: str = DEFAULT_ACCOUNT_ARCHIVE_NAME
    organization_id: str = ""
    hero_sms: HeroSMSConfig | None = None


@dataclass
class Sub2APIOAuthPrepared:
    authorize_url: str
    state: str
    nonce: str
    device_id: str
    code_verifier: str
    code_challenge: str
    client_id: str
    redirect_uri: str
    login_hint: str = ""


@dataclass
class Sub2APIOAuthFlowResult:
    ok: bool
    authorize_url: str = ""
    callback_url: str = ""
    code: str = ""
    export_path: str = ""
    archive_path: str = ""
    saved_result: str = ""
    email: str = ""
    error: str = ""
    payload: dict[str, Any] | None = None
    archive: dict[str, Any] | None = None
    tokens: RegistrationResult | None = None


@dataclass
class PhoneFlowFailure:
    code: str = ""
    message: str = ""
    retryable: bool = False
    recovery_action: str = "stop"


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _merge_url_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            continue
        query[key] = [str(value)]
    merged = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, merged, parsed.fragment))


def build_openai_oauth_authorize_url(config: Sub2APIOAuthFlowConfig) -> Sub2APIOAuthPrepared:
    """Build the manual authorize URL + PKCE bundle for phase-1 OAuth handoff."""
    registrar = PlatformRegistrar(config.proxy)
    try:
        registrar.session.cookies.set("oai-did", registrar.device_id, domain=".auth.openai.com")
        registrar.session.cookies.set("oai-did", registrar.device_id, domain="auth.openai.com")
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        params = {
            "issuer": auth_base,
            "client_id": platform_oauth_client_id,
            "audience": platform_oauth_audience,
            "redirect_uri": config.redirect_uri,
            "device_id": registrar.device_id,
            "screen_hint": "login_or_signup",
            "max_age": "0",
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9",
        }
        if config.login_hint:
            params["login_hint"] = config.login_hint
        authorize_url = f"{auth_base}/api/accounts/authorize?" + "&".join(
            f"{key}={__import__('requests').utils.quote(str(value), safe='')}" for key, value in params.items()
        )
        return Sub2APIOAuthPrepared(
            authorize_url=authorize_url,
            state=state,
            nonce=nonce,
            device_id=registrar.device_id,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            client_id=platform_oauth_client_id,
            redirect_uri=config.redirect_uri,
            login_hint=config.login_hint,
        )
    finally:
        registrar.close()


def normalize_callback_url(callback_or_code: str, redirect_uri: str, state: str = "") -> tuple[str, str]:
    """Accept either a full callback URL or a raw code and normalize both forms."""
    raw = str(callback_or_code or "").strip()
    if not raw:
        raise ValueError("empty_callback_or_code")
    callback_params = extract_oauth_callback_params_from_url(raw)
    if callback_params:
        callback_url = raw
        code = str(callback_params.get("code") or "").strip()
        return callback_url, code
    code = raw
    callback_url = _merge_url_query(redirect_uri, code=code, state=state)
    return callback_url, code


def exchange_callback_code(config: Sub2APIOAuthFlowConfig, prepared: Sub2APIOAuthPrepared, callback_or_code: str) -> RegistrationResult:
    """Exchange the returned callback/code into tokens, with direct token fallback."""
    callback_url, code = normalize_callback_url(callback_or_code, prepared.redirect_uri, prepared.state)
    primary_registrar = PlatformRegistrar(config.proxy)
    fallback_registrar: PlatformRegistrar | None = None
    try:
        result = exchange_platform_tokens(primary_registrar.session, prepared.device_id, prepared.code_verifier, callback_url, config.proxy)
        if not result.callback_url:
            result.callback_url = callback_url
        if not result.ok and code:
            # Fallback: direct token exchange for localhost callback links that do not need session continuation.
            fallback_registrar = PlatformRegistrar(config.proxy)
            resp = fallback_registrar.session.post(
                f"{auth_base}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": prepared.redirect_uri,
                    "client_id": prepared.client_id,
                    "code_verifier": prepared.code_verifier,
                },
                verify=False,
                timeout=60,
            )
            try:
                data = resp.json()
                if not isinstance(data, dict):
                    data = {}
            except Exception:
                data = {}
            if resp.status_code == 200:
                result = RegistrationResult(
                    ok=True,
                    email=str((_decode_jwt_payload(str(data.get("id_token") or "")) or {}).get("email") or (_decode_jwt_payload(str(data.get("access_token") or "")) or {}).get("https://api.openai.com/profile", {}).get("email") or "").strip(),
                    access_token=str(data.get("access_token") or "").strip(),
                    refresh_token=str(data.get("refresh_token") or "").strip(),
                    id_token=str(data.get("id_token") or "").strip(),
                    callback_url=callback_url,
                )
            else:
                result = RegistrationResult(ok=False, callback_url=callback_url, error=f"oauth_token_http_{resp.status_code}")
        return result
    finally:
        primary_registrar.close()
        if fallback_registrar is not None:
            fallback_registrar.close()


def _extract_account_identity(result: RegistrationResult, organization_id: str = "", plan_type: str = "free") -> dict[str, Any]:
    access_payload = _decode_jwt_payload(result.access_token or "") or {}
    id_payload = _decode_jwt_payload(result.id_token or "") or {}
    auth_payload = access_payload.get("https://api.openai.com/auth") or {}
    profile_payload = access_payload.get("https://api.openai.com/profile") or {}
    account_id = ""
    mailbox = result.mailbox or {}
    if isinstance(mailbox, dict):
        account_id = str(mailbox.get("account_id") or "").strip()
    return {
        "email": str(result.email or profile_payload.get("email") or id_payload.get("email") or "").strip(),
        "chatgpt_account_id": account_id,
        "chatgpt_user_id": str(auth_payload.get("user_id") or "").strip(),
        "client_id": str(access_payload.get("client_id") or platform_oauth_client_id).strip(),
        "expires_at": int(access_payload.get("exp") or 0),
        "organization_id": str(organization_id or "").strip(),
        "plan_type": str(plan_type or "free").strip() or "free",
        "name": str(id_payload.get("name") or "").strip(),
    }




def _normalize_sub2api_origin(raw_url: str) -> str:
    value = str(raw_url or "").strip()
    if not value:
        return ""
    try:
        parsed = urlparse(value)
        if not parsed.scheme or not parsed.netloc:
            parsed = urlparse(f"http://{value}")
        if not parsed.scheme or not parsed.netloc:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        return ""


def _request_codex2api_json(
    codex2api_url: str,
    *,
    path: str,
    admin_key: str,
    method: str = "POST",
    body: dict[str, Any] | None = None,
    timeout: int = 30,
) -> Any:
    origin = _normalize_sub2api_origin(codex2api_url)
    if not origin:
        raise ValueError("invalid_codex2api_url")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-Admin-Key": str(admin_key or "").strip(),
    }
    response = requests.request(
        method.upper(),
        f"{origin}{path}",
        headers=headers,
        json=body,
        timeout=max(5, int(timeout or 30)),
        verify=False,
    )
    try:
        payload = response.json()
    except Exception:
        payload = {}
    if response.status_code >= 400:
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("message") or payload.get("detail") or payload.get("error") or payload.get("reason") or "").strip()
        raise RuntimeError(detail or f"codex2api_http_{response.status_code}")
    return payload


def _extract_codex2api_account_id(data: Any, *, email: str = "", name: str = "") -> int:
    targets = {str(email or "").strip().lower(), str(name or "").strip().lower()} - {""}
    candidates: list[Any] = []
    if isinstance(data, dict):
        for key in ("account", "item", "data"):
            value = data.get(key)
            if isinstance(value, dict):
                candidates.append(value)
            elif isinstance(value, list):
                candidates.extend(value)
        for key in ("accounts", "items", "success"):
            value = data.get(key)
            if isinstance(value, list):
                candidates.extend(value)
        candidates.append(data)
    elif isinstance(data, list):
        candidates.extend(data)
    for item in candidates:
        if not isinstance(item, dict):
            continue
        raw_id = item.get("id") or item.get("account_id")
        if not raw_id:
            continue
        item_email = str(item.get("email") or "").strip().lower()
        item_name = str(item.get("name") or "").strip().lower()
        if not targets or item_email in targets or item_name in targets:
            try:
                return int(raw_id)
            except Exception:
                continue
    return 0


def _find_codex2api_account_id(codex2api_url: str, *, admin_key: str, email: str = "", name: str = "") -> int:
    data = _request_codex2api_json(codex2api_url, path="/api/admin/accounts", admin_key=admin_key, method="GET", body=None)
    return _extract_codex2api_account_id(data, email=email, name=name)


def _refresh_codex2api_account(codex2api_url: str, *, admin_key: str, account_id: int) -> dict[str, Any]:
    if int(account_id or 0) <= 0:
        return {"ok": False, "message": "codex2api_account_id_missing"}
    data = _request_codex2api_json(
        codex2api_url,
        path=f"/api/admin/accounts/{int(account_id)}/refresh",
        admin_key=admin_key,
        method="POST",
        body={},
        timeout=60,
    )
    return {"ok": True, "message": str((data or {}).get("message") or "Codex2API account refreshed"), "raw": data}


def import_result_to_codex2api(
    result: RegistrationResult,
    *,
    codex2api_url: str,
    admin_key: str,
    account_name: str = "",
    proxy_url: str = "",
) -> dict[str, Any]:
    refresh_token = str(result.refresh_token or "").strip()
    access_token = str(result.access_token or "").strip()
    identity = _extract_account_identity(result)
    name = str(account_name or identity.get("email") or result.email or "codex-account").strip()
    if access_token:
        payload = {"name": name, "access_token": access_token}
        if str(proxy_url or "").strip():
            payload["proxy_url"] = str(proxy_url).strip()
        data = _request_codex2api_json(
            codex2api_url,
            path="/api/admin/accounts/at",
            admin_key=admin_key,
            method="POST",
            body=payload,
        )
        return {
            "ok": True,
            "message": str((data or {}).get("message") or "Codex2API access token account imported"),
            "success": (data or {}).get("success"),
            "failed": (data or {}).get("failed"),
            "duplicate": (data or {}).get("duplicate"),
            "mode": "access_token",
            "raw": data,
        }
    if refresh_token:
        payload = {"name": name, "refresh_token": refresh_token}
        if str(proxy_url or "").strip():
            payload["proxy_url"] = str(proxy_url).strip()
        data = _request_codex2api_json(
            codex2api_url,
            path="/api/admin/accounts",
            admin_key=admin_key,
            method="POST",
            body=payload,
        )
        refresh_result = {"ok": False, "message": "codex2api_refresh_not_attempted"}
        account_id = _extract_codex2api_account_id(data, email=str(identity.get("email") or result.email or ""), name=name)
        if not account_id:
            account_id = _find_codex2api_account_id(codex2api_url, admin_key=admin_key, email=str(identity.get("email") or result.email or ""), name=name)
        if account_id:
            refresh_result = _refresh_codex2api_account(codex2api_url, admin_key=admin_key, account_id=account_id)
        return {
            "ok": bool(refresh_result.get("ok")),
            "message": str((refresh_result or {}).get("message") or (data or {}).get("message") or "Codex2API refresh token account imported"),
            "success": (data or {}).get("success"),
            "failed": (data or {}).get("failed"),
            "duplicate": (data or {}).get("duplicate"),
            "account_id": account_id,
            "refresh": refresh_result,
            "mode": "refresh_token",
            "raw": data,
        }
    raise RuntimeError("codex2api_token_missing")


def build_sub2api_import_payload(
    result: RegistrationResult,
    *,
    concurrency: int = 10,
    priority: int = 1,
    rate_multiplier: int = 1,
    auto_pause_on_expired: bool = True,
    organization_id: str = "",
    plan_type: str = "free",
    privacy_mode: str = "training_off",
    account_name: str = "",
) -> dict[str, Any]:
    identity = _extract_account_identity(result, organization_id=organization_id, plan_type=plan_type)
    email = identity["email"]
    return {
        "exported_at": _utc_now_iso(),
        "proxies": [],
        "accounts": [
            {
                "name": account_name or email,
                "platform": "openai",
                "type": "oauth",
                "credentials": {
                    "access_token": result.access_token,
                    "chatgpt_account_id": identity["chatgpt_account_id"],
                    "chatgpt_user_id": identity["chatgpt_user_id"],
                    "client_id": identity["client_id"],
                    "email": email,
                    "expires_at": identity["expires_at"],
                    "id_token": result.id_token,
                    "organization_id": identity["organization_id"],
                    "plan_type": identity["plan_type"],
                    "refresh_token": result.refresh_token,
                },
                "extra": {
                    "email": email,
                    "openai_oauth_responses_websockets_v2_enabled": False,
                    "openai_oauth_responses_websockets_v2_mode": "off",
                    "privacy_mode": privacy_mode,
                },
                "concurrency": int(concurrency),
                "priority": int(priority),
                "rate_multiplier": int(rate_multiplier),
                "auto_pause_on_expired": bool(auto_pause_on_expired),
            }
        ],
    }


def build_account_archive(
    prepared: Sub2APIOAuthPrepared,
    result: RegistrationResult,
    *,
    callback_url: str,
    phone_number: str = "",
    phone_country: str = "CO",
    hero_sms_order_id: str = "",
    hero_sms_price: float | None = None,
    email_password: str = "",
    mail_provider_name: str = "",
    organization_id: str = "",
    plan_type: str = "free",
) -> dict[str, Any]:
    identity = _extract_account_identity(result, organization_id=organization_id, plan_type=plan_type)
    callback_params = extract_oauth_callback_params_from_url(callback_url) or {}
    return {
        "created_at": _utc_now_iso(),
        "platform": "openai",
        "signup_method": "oauth_manual_or_browser_assist",
        "phone": {
            "country": phone_country,
            "phone_number": phone_number,
            "provider": "hero-sms" if phone_number or hero_sms_order_id else "",
            "order_id": hero_sms_order_id,
            "price": hero_sms_price,
        },
        "email": {
            "address": identity["email"],
            "password": email_password,
            "mail_provider": mail_provider_name,
        },
        "oauth": {
            "authorize_url": prepared.authorize_url,
            "callback_url": callback_url,
            "code": str(callback_params.get("code") or "").strip(),
            "state": prepared.state,
            "redirect_uri": prepared.redirect_uri,
            "client_id": prepared.client_id,
            "device_id": prepared.device_id,
        },
        "tokens": {
            "access_token": result.access_token,
            "refresh_token": result.refresh_token,
            "id_token": result.id_token,
        },
        "profile": {
            "chatgpt_user_id": identity["chatgpt_user_id"],
            "chatgpt_account_id": identity["chatgpt_account_id"],
            "client_id": identity["client_id"],
            "organization_id": identity["organization_id"],
            "expires_at": identity["expires_at"],
            "plan_type": identity["plan_type"],
            "name": identity["name"],
        },
    }


def save_sub2api_export(payload: dict[str, Any], filename: str = DEFAULT_SUB2API_EXPORT_NAME) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def save_account_archive(archive: dict[str, Any], filename: str = DEFAULT_ACCOUNT_ARCHIVE_NAME) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / filename
    path.write_text(json.dumps(archive, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _hero_sms_request(config: HeroSMSConfig, params: dict[str, Any]) -> Any:
    base_url = str(config.base_url or "https://hero-sms.com/stubs/handler_api.php").strip()
    query = {"api_key": str(config.api_key or "").strip(), **params}
    response = requests.get(base_url, params=query, timeout=30)
    text = response.text.strip()
    try:
        payload = response.json()
    except Exception:
        payload = text
    if response.status_code >= 400:
        raise RuntimeError(f"{_sms_provider_label(config)} HTTP {response.status_code}: {text[:300]}")
    return payload


def _5sim_request(config: HeroSMSConfig, path: str, params: dict[str, Any] | None = None) -> Any:
    base_url = str(config.base_url or FIVESIM_BASE_URL).strip().rstrip("/")
    clean_path = "/" + str(path or "").strip().lstrip("/")
    headers = {
        "Authorization": f"Bearer {str(config.api_key or '').strip()}",
        "Accept": "application/json",
    }
    response = requests.get(f"{base_url}{clean_path}", params=params or {}, headers=headers, timeout=30)
    text = response.text.strip()
    try:
        payload = response.json()
    except Exception:
        payload = text
    if response.status_code >= 400:
        raise RuntimeError(f"5sim HTTP {response.status_code}: {text[:300]}")
    return payload


def _normalize_sms_provider(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    if normalized in {"5sim", "five_sim", "fivesim", "five"}:
        return "5sim"
    if normalized in {"smsbower", "sms_bower", "smsbower_page"}:
        return "smsbower"
    return "hero_sms"


def _is_5sim_config(config: HeroSMSConfig) -> bool:
    provider = _normalize_sms_provider(getattr(config, "provider", ""))
    base_url = str(getattr(config, "base_url", "") or "").lower()
    return provider == "5sim" or "5sim.net" in base_url


def _is_smsbower_config(config: HeroSMSConfig) -> bool:
    provider = _normalize_sms_provider(getattr(config, "provider", ""))
    base_url = str(getattr(config, "base_url", "") or "").lower()
    return provider == "smsbower" or "smsbower" in base_url


def _sms_provider_label(config: HeroSMSConfig) -> str:
    if _is_5sim_config(config):
        return "5sim"
    return "SMSBower" if _is_smsbower_config(config) else "HeroSMS"


def _hero_sms_text(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.strip()
    if isinstance(payload, dict):
        if payload.get("status") and payload.get("message"):
            return f"{payload.get('status')}:{payload.get('message')}"
        if payload.get("activationId") or payload.get("phoneNumber"):
            return f"ACCESS_NUMBER:{payload.get('activationId') or payload.get('id')}:{payload.get('phoneNumber') or payload.get('number')}"
        if payload.get("sms"):
            return json.dumps(payload, ensure_ascii=False)
    return json.dumps(payload, ensure_ascii=False) if payload is not None else ""


def _extract_sms_code(value: Any) -> str:
    text = _hero_sms_text(value)
    if isinstance(value, dict):
        candidates = [
            value.get("code"),
            value.get("sms_code"),
            (value.get("sms") or {}).get("code") if isinstance(value.get("sms"), dict) else "",
            (value.get("sms") or {}).get("text") if isinstance(value.get("sms"), dict) else "",
        ]
        if isinstance(value.get("sms"), list):
            for item in value.get("sms") or []:
                if not isinstance(item, dict):
                    continue
                candidates.extend([item.get("code"), item.get("text")])
        for candidate in candidates:
            match = re.search(r"\b(\d{4,8})\b", str(candidate or ""))
            if match:
                return match.group(1)
    match = re.search(r"(?:STATUS_OK|code|sms)[^0-9]{0,30}(\d{4,8})", text, re.I)
    if match:
        return match.group(1)
    match = re.search(r"\b(\d{4,8})\b", text)
    return match.group(1) if match else ""


def _extract_5sim_sms_code(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    sms_rows = value.get("sms")
    if isinstance(sms_rows, dict):
        sms_rows = [sms_rows]
    if not isinstance(sms_rows, list):
        return ""
    for item in sms_rows:
        if not isinstance(item, dict):
            continue
        for candidate in (item.get("code"), item.get("text")):
            match = re.search(r"\b(\d{4,8})\b", str(candidate or ""))
            if match:
                return match.group(1)
    return ""


def _normalize_hero_sms_price(value: Any) -> float | None:
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        number = float(value)
        return round(number, 4) if number > 0 else None
    match = re.search(r"(\d+(?:\.\d+)?)", str(value).strip())
    if not match:
        return None
    number = float(match.group(1))
    return round(number, 4) if number > 0 else None


def _resolve_hero_sms_stock_state(payload: Any) -> tuple[bool, int]:
    if not isinstance(payload, dict):
        return False, 0
    if payload.get("physicalCount") is not None:
        try:
            physical_count = int(float(payload.get("physicalCount")))
        except Exception:
            physical_count = 0
        return True, max(physical_count, 0)
    stock_candidates = []
    for key in ("count", "stock", "available", "quantity", "qty", "left", "free"):
        try:
            numeric = int(float(payload.get(key)))
        except Exception:
            continue
        stock_candidates.append(numeric)
    if not stock_candidates:
        return False, 0
    return True, max(stock_candidates)


def _resolve_hero_sms_display_quantity(payload: Any) -> int | None:
    if not isinstance(payload, dict):
        return None
    for key in ("count", "stock", "available", "quantity", "qty", "left", "free", "physicalCount"):
        try:
            value = payload.get(key)
            if value is None or value == "":
                continue
            return max(int(float(value)), 0)
        except Exception:
            continue
    return None


def _collect_hero_sms_price_candidates(payload: Any, *, include_zero_stock: bool = False, candidates: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows = candidates if candidates is not None else []
    if isinstance(payload, list):
        for entry in payload:
            _collect_hero_sms_price_candidates(entry, include_zero_stock=include_zero_stock, candidates=rows)
        return rows
    if not isinstance(payload, dict):
        return rows

    cost = _normalize_hero_sms_price(payload.get("cost"))
    if cost is not None:
        has_stock, stock_count = _resolve_hero_sms_stock_state(payload)
        display_quantity = _resolve_hero_sms_display_quantity(payload)
        if include_zero_stock or (not has_stock or stock_count > 0):
            rows.append(
                {
                    "price": cost,
                    "stock": stock_count if has_stock else None,
                    "display_quantity": display_quantity,
                }
            )

    for key, value in payload.items():
        keyed_price = _normalize_hero_sms_price(key)
        if keyed_price is None:
            continue
        if isinstance(value, dict):
            has_stock, stock_count = _resolve_hero_sms_stock_state(value)
            display_quantity = _resolve_hero_sms_display_quantity(value)
            if has_stock and (include_zero_stock or stock_count > 0):
                rows.append({"price": keyed_price, "stock": stock_count, "display_quantity": display_quantity})
            continue
        try:
            numeric_count = int(float(value))
        except Exception:
            continue
        if include_zero_stock or numeric_count > 0:
            rows.append({"price": keyed_price, "stock": numeric_count, "display_quantity": numeric_count})

    for value in payload.values():
        _collect_hero_sms_price_candidates(value, include_zero_stock=include_zero_stock, candidates=rows)
    return rows


def _build_sorted_unique_price_candidates(values: list[Any]) -> list[float]:
    normalized = []
    for value in values:
        price = _normalize_hero_sms_price(value)
        if price is None:
            continue
        normalized.append(round(float(price), 4))
    return sorted(set(normalized))


def _fetch_hero_sms_price_payloads(config: HeroSMSConfig) -> tuple[list[Any], list[dict[str, str]]]:
    payloads: list[Any] = []
    errors: list[dict[str, str]] = []
    actions = [
        ("getPricesExtended", {"freePrice": "true"}),
        ("getPrices", {}),
    ]
    for action, extra_query in actions:
        try:
            payload = _hero_sms_request(
                config,
                {
                    "action": action,
                    "service": str(config.service or "dr"),
                    "country": str(config.country or "52"),
                    **extra_query,
                },
            )
            payloads.append(payload)
        except Exception as exc:
            errors.append({"action": action, "message": str(exc)})
    return payloads, errors


def fetch_hero_sms_price_summary(config: HeroSMSConfig, *, country_label: str = "") -> dict[str, Any]:
    if _is_5sim_config(config):
        country = str(config.country or "england").strip() or "england"
        service = str(config.service or "openai").strip() or "openai"
        payload = _5sim_request(config, f"/guest/products/{quote(country, safe='')}/any")
        product_payload = payload.get(service) if isinstance(payload, dict) else {}
        if not isinstance(product_payload, dict):
            product_payload = {}
        price = _normalize_hero_sms_price(
            product_payload.get("Price")
            or product_payload.get("price")
            or product_payload.get("cost")
        )
        quantity = None
        for key in ("Qty", "qty", "count", "quantity", "stock"):
            try:
                raw_quantity = product_payload.get(key)
                if raw_quantity is None or raw_quantity == "":
                    continue
                quantity = max(int(float(raw_quantity)), 0)
                break
            except Exception:
                continue
        tiers = [{"price": price, "stock": quantity, "quantity": quantity}] if price is not None else []
        return {
            "country": country,
            "country_label": str(country_label or country).strip(),
            "service": service,
            "min_price": _normalize_hero_sms_price(getattr(config, "min_price", 0.0)),
            "max_price": _normalize_hero_sms_price(config.max_price),
            "lowest_price": price,
            "tier_count": len(tiers),
            "tiers": tiers,
            "effective_prices": [price] if price is not None else [],
            "effective_price_count": 1 if price is not None else 0,
            "min_catalog_price": price,
            "synthetic_user_limit_probe": False,
            "errors": [],
            "summary": (
                f"5sim {service}：{price:.4f}"
                + (f"(x{quantity})" if quantity is not None else "")
                if price is not None
                else "未获取到可解析的价格档位"
            ),
            "raw": payload,
        }
    payloads, errors = _fetch_hero_sms_price_payloads(config)
    payload = payloads[-1] if payloads else {}
    raw_candidates = []
    for item in payloads:
        raw_candidates.extend(_collect_hero_sms_price_candidates(item, include_zero_stock=True))
    by_price: dict[float, int | None] = {}
    by_display_quantity: dict[float, int | None] = {}
    for row in raw_candidates:
        price = float(row["price"])
        stock = row.get("stock")
        display_quantity = row.get("display_quantity")
        if price not in by_price:
            by_price[price] = stock
            by_display_quantity[price] = display_quantity
            continue
        if stock is None:
            continue
        current = by_price[price]
        by_price[price] = stock if current is None else max(int(current), int(stock))
        current_display = by_display_quantity.get(price)
        if display_quantity is not None:
            by_display_quantity[price] = display_quantity if current_display is None else max(int(current_display), int(display_quantity))
    tiers = [
        {"price": price, "stock": by_price[price], "quantity": by_display_quantity.get(price)}
        for price in sorted(by_price)
    ]
    in_stock_candidates = _build_sorted_unique_price_candidates(
        [row["price"] for item in payloads for row in _collect_hero_sms_price_candidates(item, include_zero_stock=False)]
    )
    all_catalog_candidates = _build_sorted_unique_price_candidates([row["price"] for row in raw_candidates])
    merged_candidates = _build_sorted_unique_price_candidates(in_stock_candidates + all_catalog_candidates) if in_stock_candidates else []
    min_catalog_price = all_catalog_candidates[0] if all_catalog_candidates else (merged_candidates[0] if merged_candidates else None)
    user_min = _normalize_hero_sms_price(getattr(config, "min_price", 0.0))
    user_limit = _normalize_hero_sms_price(config.max_price)
    synthetic_user_limit_probe = False
    if user_min is not None:
        merged_candidates = [price for price in merged_candidates if price >= user_min]
    if user_limit is not None:
        bounded = [price for price in merged_candidates if price <= user_limit]
        if bounded:
            effective_prices = bounded
        else:
            effective_prices = [user_limit]
            synthetic_user_limit_probe = True
    elif merged_candidates:
        effective_prices = merged_candidates
    else:
        effective_prices = [None]
    lowest_price = effective_prices[0] if effective_prices and effective_prices[0] is not None else None
    tier_text = ", ".join(
        f"{item['price']:.4f}(x{item['quantity'] if item.get('quantity') is not None else item['stock'] if item['stock'] is not None else '?'})"
        for item in tiers
    )
    effective_text = ", ".join(f"{price:.4f}" for price in effective_prices if price is not None)
    return {
        "country": str(config.country or "").strip(),
        "country_label": str(country_label or config.country or "").strip(),
        "service": str(config.service or "dr"),
        "min_price": user_min,
        "max_price": user_limit,
        "lowest_price": lowest_price,
        "tier_count": len(tiers),
        "tiers": tiers,
        "effective_prices": effective_prices,
        "effective_price_count": len([price for price in effective_prices if price is not None]),
        "min_catalog_price": min_catalog_price,
        "synthetic_user_limit_probe": synthetic_user_limit_probe,
        "errors": errors,
        "summary": (
            (
                f"有效价格计划：{effective_text or '无'}"
                + (f"；目录最低价：{min_catalog_price:.4f}" if min_catalog_price is not None else "")
                + (f"；目录档位：{tier_text}" if tier_text else "")
                + ("；当前为按最高价探测的虚拟档位" if synthetic_user_limit_probe else "")
            )
            if tiers or effective_text
            else "未获取到可解析的价格档位"
        ),
        "raw": payload,
    }


def fetch_hero_sms_country_catalog(config: HeroSMSConfig) -> list[dict[str, Any]]:
    payload = _hero_sms_request(
        config,
        {
            "action": "getPrices",
            "service": str(config.service or "dr"),
        },
    )
    if not isinstance(payload, dict):
        return []
    items: list[dict[str, Any]] = []
    for raw_country_id, country_payload in payload.items():
        country_id = str(raw_country_id or "").strip()
        if not country_id.isdigit():
            continue
        service_payload = country_payload
        if isinstance(country_payload, dict) and str(config.service or "dr") in country_payload:
            service_payload = country_payload.get(str(config.service or "dr"))
        raw_candidates = _collect_hero_sms_price_candidates(service_payload, include_zero_stock=True)
        by_price: dict[float, int | None] = {}
        by_display_quantity: dict[float, int | None] = {}
        for row in raw_candidates:
            price = float(row["price"])
            stock = row.get("stock")
            display_quantity = row.get("display_quantity")
            if price not in by_price:
                by_price[price] = stock
                by_display_quantity[price] = display_quantity
                continue
            if stock is None:
                continue
            current = by_price[price]
            by_price[price] = stock if current is None else max(int(current), int(stock))
            current_display = by_display_quantity.get(price)
            if display_quantity is not None:
                by_display_quantity[price] = display_quantity if current_display is None else max(int(current_display), int(display_quantity))
        tiers = [
            {"price": price, "stock": by_price[price], "quantity": by_display_quantity.get(price)}
            for price in sorted(by_price)
        ]
        items.append(
            {
                "id": country_id,
                "tiers": tiers,
            }
        )
    items.sort(key=lambda item: int(item["id"]))
    return items


def fetch_hero_sms_countries(config: HeroSMSConfig) -> list[dict[str, Any]]:
    if _is_5sim_config(config):
        payload = _5sim_request(config, "/guest/countries")
        if not isinstance(payload, dict):
            return []
        zh_lookup = fetch_country_name_zh_map()
        items: list[dict[str, Any]] = []
        for country_slug, row in payload.items():
            if not isinstance(row, dict):
                continue
            slug = str(country_slug or "").strip()
            if not slug:
                continue
            eng = str(row.get("text_en") or row.get("eng") or row.get("name") or slug).strip()
            rus = str(row.get("text_ru") or row.get("rus") or "").strip()
            chn = str(zh_lookup.get(eng) or "").strip()
            label = f"{chn}（{eng}）" if chn and eng else (chn or eng or rus or slug)
            items.append(
                {
                    "id": slug,
                    "eng": eng,
                    "chn": chn,
                    "name_en": eng,
                    "label": label,
                    "visible": True,
                }
            )
        items.sort(key=lambda item: str(item.get("label") or item.get("id") or "").lower())
        return items
    payload = _hero_sms_request(
        config,
        {
            "action": "getCountries",
        },
    )
    if isinstance(payload, dict):
        rows = list(payload.values())
    elif isinstance(payload, list):
        rows = payload
    else:
        return []
    items: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        country_id = str(row.get("id") or "").strip()
        eng = str(row.get("eng") or "").strip()
        chn = str(row.get("chn") or "").strip()
        if not country_id.isdigit() or (not eng and not chn):
            continue
        visible_raw = row.get("visible")
        if visible_raw is None or visible_raw == "":
            visible = True
        else:
            try:
                visible = bool(int(visible_raw))
            except Exception:
                visible = bool(visible_raw)
        items.append(
            {
                "id": country_id,
                "eng": eng,
                "chn": chn,
                "label": chn or eng,
                "visible": visible,
            }
        )
    items.sort(key=lambda item: int(item["id"]))
    return items


def fetch_hero_sms_quote_list(config: HeroSMSConfig) -> dict[str, Any]:
    url = f"https://hero-sms.com/api/v1/left-menu/service/{str(config.service or 'dr')}/country/{str(config.country or '16')}/offers"
    response = requests.get(url, timeout=30)
    payload = response.json() if response.ok else {}
    if response.status_code >= 400:
        raise RuntimeError(f"hero_sms_offers_http_{response.status_code}")
    data = ((payload.get("data") or {}).get(str(config.service or "dr")) or {}) if isinstance(payload, dict) else {}
    operators = list(data.get("operators") or []) if isinstance(data, dict) else []
    target = None
    for item in operators:
        if str((item or {}).get("name") or "").strip().lower() == "any":
            target = item
            break
    if target is None and operators:
        target = operators[0]
    if not operators:
        return {
            "operator_name": "",
            "operator_label": "",
            "quote_list": [],
            "quote_list_by_operator": [],
            "rent_list": [],
            "raw": payload,
        }

    quote_list_by_operator: list[dict[str, Any]] = []
    quote_quantity_by_price: dict[float, int] = {}
    rent_list: list[dict[str, Any]] = []
    for operator in operators:
        if not isinstance(operator, dict):
            continue
        operator_name = str(operator.get("name") or "").strip()
        operator_label = str(operator.get("localName") or operator_name).strip()
        free_price_offers = operator.get("freePriceOffers")
        if isinstance(free_price_offers, dict):
            for price, count in free_price_offers.items():
                normalized_price = _normalize_hero_sms_price(price)
                if normalized_price is None:
                    continue
                try:
                    quantity = max(int(float(count)), 0)
                except Exception:
                    quantity = 0
                quote_list_by_operator.append(
                    {
                        "operator_name": operator_name,
                        "operator_label": operator_label,
                        "price": normalized_price,
                        "quantity": quantity,
                    }
                )
                quote_quantity_by_price[normalized_price] = quote_quantity_by_price.get(normalized_price, 0) + quantity
        rent_offers = operator.get("rentOffers") if isinstance(operator, dict) else {}
        current_rent = (rent_offers or {}).get("0") if isinstance(rent_offers, dict) else {}
        if isinstance(current_rent, dict):
            for hours, info in current_rent.items():
                if not isinstance(info, dict):
                    continue
                normalized_price = _normalize_hero_sms_price(info.get("price"))
                if normalized_price is None:
                    continue
                try:
                    quantity = max(int(float(info.get("count") or 0)), 0)
                except Exception:
                    quantity = 0
                try:
                    normalized_hours = int(hours)
                except Exception:
                    continue
                rent_list.append(
                    {
                        "operator_name": operator_name,
                        "operator_label": operator_label,
                        "hours": normalized_hours,
                        "price": normalized_price,
                        "quantity": quantity,
                    }
                )

    quote_list = [{"price": price, "quantity": quote_quantity_by_price.get(price, 0)} for price in sorted(quote_quantity_by_price, reverse=True)]
    quote_list_by_operator.sort(key=lambda item: (item["price"], item["operator_label"]), reverse=True)
    rent_list.sort(key=lambda item: item["hours"])
    return {
        "operator_name": str((target or {}).get("name") or "").strip(),
        "operator_label": str((target or {}).get("localName") or (target or {}).get("name") or "").strip(),
        "quote_list": quote_list,
        "quote_list_by_operator": quote_list_by_operator,
        "rent_list": rent_list,
        "operator_count": len([item for item in operators if isinstance(item, dict)]),
        "raw": payload,
    }


@lru_cache(maxsize=1)
def fetch_country_name_zh_map() -> dict[str, str]:
    manual = {
        "Azerbaijan": "阿塞拜疆",
        "Bolivia": "玻利维亚",
        "Bosnia": "波黑",
        "Cambodia": "柬埔寨",
        "Cameroon": "喀麦隆",
        "Canada": "加拿大",
        "Cape Verde": "佛得角",
        "Chad": "乍得",
        "Chile": "智利",
        "China": "中国",
        "Colombia": "哥伦比亚",
        "Comoros": "科摩罗",
        "Congo": "刚果（布）",
        "Costa Rica": "哥斯达黎加",
        "Croatia": "克罗地亚",
        "Cyprus": "塞浦路斯",
        "Czech": "捷克",
        "Czechia": "捷克",
        "Denmark": "丹麦",
        "Djibouti": "吉布提",
        "Dominican Republic": "多米尼加共和国",
        "DR Congo": "刚果（金）",
        "East Timor": "东帝汶",
        "Ecuador": "厄瓜多尔",
        "Egypt": "埃及",
        "England": "英格兰",
        "France": "法国",
        "Germany": "德国",
        "Hong Kong": "中国香港",
        "Indonesia": "印度尼西亚",
        "Ivory Coast": "科特迪瓦",
        "Kazakhstan": "哈萨克斯坦",
        "Kyrgyzstan": "吉尔吉斯斯坦",
        "Laos": "老挝",
        "Macao": "中国澳门",
        "Moldova": "摩尔多瓦",
        "New Caledonia": "新喀里多尼亚",
        "Palestine": "巴勒斯坦",
        "Papua": "巴布亚新几内亚",
        "Philippines": "菲律宾",
        "Puerto Rico": "波多黎各",
        "Reunion": "留尼汪",
        "Russia": "俄罗斯",
        "Saint Lucia": "圣卢西亚",
        "Salvador": "萨尔瓦多",
        "Sao Tome and Principe": "圣多美和普林西比",
        "Singapore": "新加坡",
        "Solomon Islands": "所罗门群岛",
        "South Africa": "南非",
        "Sri Lanka": "斯里兰卡",
        "Swaziland": "斯威士兰",
        "Syria": "叙利亚",
        "Taiwan": "中国台湾",
        "Tanzania": "坦桑尼亚",
        "Thailand": "泰国",
        "Timor-Leste": "东帝汶",
        "Trinidad and Tobago": "特立尼达和多巴哥",
        "Ukraine": "乌克兰",
        "United Kingdom": "英国",
        "USA": "美国（实体）",
        "USA (virtual)": "美国（虚拟）",
        "USA (physical)": "美国（实体）",
        "Venezuela": "委内瑞拉",
        "Vietnam": "越南",
        "Western Sahara": "西撒哈拉",
    }
    try:
        response = requests.get(
            "https://restcountries.com/v3.1/all?fields=name,translations,altSpellings",
            timeout=30,
        )
        payload = response.json() if response.ok else []
    except Exception:
        payload = []
    lookup = dict(manual)
    if isinstance(payload, list):
        for row in payload:
            if not isinstance(row, dict):
                continue
            zh = ((row.get("translations") or {}).get("zho") or {})
            zh_name = str(zh.get("common") or zh.get("official") or "").strip()
            if not zh_name:
                continue
            names = set()
            name_info = row.get("name") or {}
            for key in ("common", "official"):
                value = str(name_info.get(key) or "").strip()
                if value:
                    names.add(value)
            for alt in row.get("altSpellings") or []:
                value = str(alt or "").strip()
                if value:
                    names.add(value)
            for name in names:
                lookup.setdefault(name, zh_name)
    return lookup


def _resolve_hero_sms_price_candidates_for_retry(config: HeroSMSConfig) -> list[float]:
    candidates: list[float] = []
    try:
        quote = fetch_hero_sms_quote_list(config)
        rows: Any = []
        if isinstance(quote, dict):
            rows = quote.get("quote_list_by_operator") or quote.get("quote_list")
        if isinstance(rows, list):
            for row in rows:
                if not isinstance(row, dict):
                    continue
                price = _normalize_hero_sms_price(row.get("price"))
                quantity = max(0, int(float(row.get("quantity") or 0))) if row.get("quantity") is not None else 0
                if price is None or quantity <= 0:
                    continue
                candidates.append(price)
    except Exception:
        candidates = []

    # Fallback to getPrices tiers when website quote list is unavailable.
    if not candidates:
        try:
            summary = fetch_hero_sms_price_summary(config)
            for row in summary.get("tiers") or []:
                if not isinstance(row, dict):
                    continue
                price = _normalize_hero_sms_price(row.get("price"))
                quantity = row.get("quantity")
                stock = row.get("stock")
                has_supply = False
                for value in (quantity, stock):
                    try:
                        if int(float(value or 0)) > 0:
                            has_supply = True
                            break
                    except Exception:
                        continue
                if price is None or not has_supply:
                    continue
                candidates.append(price)
        except Exception:
            candidates = []

    min_limit = _normalize_hero_sms_price(getattr(config, "min_price", 0.0))
    unique_sorted = sorted(set(round(float(price), 4) for price in candidates if min_limit is None or float(price) >= float(min_limit)))
    user_limit = _normalize_hero_sms_price(config.max_price)
    if user_limit is not None:
        bounded = [price for price in unique_sorted if price <= user_limit]
        if bounded:
            return bounded
        return [round(float(user_limit), 4)]
    return unique_sorted


def acquire_hero_sms_phone(
    config: HeroSMSConfig,
    *,
    max_price_override: float | None = None,
    allow_wrong_price_retry: bool = True,
) -> dict[str, str]:
    if not str(config.api_key or "").strip():
        raise RuntimeError("missing_sms_api_key")
    price_limit = _normalize_hero_sms_price(max_price_override)
    if price_limit is None:
        price_limit = _normalize_hero_sms_price(config.max_price)
    min_limit = _normalize_hero_sms_price(getattr(config, "min_price", 0.0))
    if price_limit is not None and min_limit is not None and float(min_limit) > float(price_limit) + 1e-9:
        raise RuntimeError(f"{_normalize_sms_provider(getattr(config, 'provider', 'hero_sms'))}_get_number_failed: minPrice_gt_maxPrice (minPrice={float(min_limit):.4f}, maxPrice={float(price_limit):.4f})")

    if _is_5sim_config(config):
        country = str(config.country or "england").strip() or "england"
        product = str(config.service or "openai").strip() or "openai"
        params: dict[str, Any] = {}
        if price_limit is not None and price_limit > 0:
            params["maxPrice"] = float(price_limit)
        payload = _5sim_request(
            config,
            f"/user/buy/activation/{quote(country, safe='')}/any/{quote(product, safe='')}",
            params,
        )
        activation_id = str((payload or {}).get("id") or "").strip() if isinstance(payload, dict) else ""
        phone_number = str((payload or {}).get("phone") or (payload or {}).get("number") or "").strip() if isinstance(payload, dict) else ""
        if not activation_id or not phone_number:
            text = _hero_sms_text(payload)
            lowered = text.lower()
            if "no free phones" in lowered or "no numbers" in lowered or "not enough" in lowered:
                raise RuntimeError(f"5sim_get_number_failed: NO_NUMBERS")
            raise RuntimeError(f"5sim_get_number_failed: {text[:300]}")
        if not phone_number.startswith("+"):
            phone_number = f"+{re.sub(r'[^0-9]', '', phone_number)}"
        result = {"activation_id": activation_id, "phone_number": phone_number}
        price = str((payload or {}).get("price") or (payload or {}).get("cost") or "").strip() if isinstance(payload, dict) else ""
        if price:
            result["price"] = price
        return result

    params: dict[str, Any] = {
        "action": "getNumberV2" if _is_smsbower_config(config) else "getNumber",
        "service": str(getattr(config, "service", "") or "dr"),
        "country": str(config.country or "52"),
    }
    if price_limit is not None and price_limit > 0:
        params["maxPrice"] = float(price_limit)
    payload = _hero_sms_request(config, params)
    text = _hero_sms_text(payload)
    match = re.search(r"ACCESS_NUMBER:([^:]+):(.+)", text, re.I)
    if not match and isinstance(payload, dict):
        activation_id = str(payload.get("activationId") or payload.get("id") or "").strip()
        phone_number = str(payload.get("phoneNumber") or payload.get("number") or "").strip()
        if activation_id and phone_number:
            match = re.match(r"(.+)", f"ACCESS_NUMBER:{activation_id}:{phone_number}")
    if not match:
        lowered = str(text or "").lower()
        wrong_price_match = re.search(r"WRONG_MAX_PRICE[:=]\s*([0-9]+(?:\.[0-9]+)?)", str(text or ""), re.I)
        if (not _is_smsbower_config(config)) and allow_wrong_price_retry and wrong_price_match:
            suggested_price = _normalize_hero_sms_price(wrong_price_match.group(1))
            current_price = _normalize_hero_sms_price(price_limit)
            user_limit = _normalize_hero_sms_price(config.max_price)
            effective_limit = current_price if current_price is not None else user_limit
            if (
                suggested_price is not None
                and (effective_limit is None or float(suggested_price) <= float(effective_limit) + 1e-9)
                and (current_price is None or abs(float(suggested_price) - float(current_price)) > 1e-9)
            ):
                return acquire_hero_sms_phone(
                    config,
                    max_price_override=float(suggested_price),
                    allow_wrong_price_retry=False,
                )
            if suggested_price is not None and effective_limit is not None and float(suggested_price) > float(effective_limit) + 1e-9:
                raise RuntimeError(
                    f"hero_sms_get_number_failed: WRONG_MAX_PRICE (maxPrice={float(effective_limit):.4f}, required={float(suggested_price):.4f})"
                )
        if "no_numbers" in lowered or "no numbers" in lowered:
            try:
                quote_data = fetch_hero_sms_quote_list(config) if not _is_smsbower_config(config) else {}
                prices = [
                    _normalize_hero_sms_price(row.get("price"))
                    for row in (quote_data.get("quote_list") or [])
                    if isinstance(row, dict)
                ]
                prices = [value for value in prices if value is not None]
            except Exception:
                prices = []
            min_available = min(prices) if prices else None
            if price_limit is not None and min_available is not None and min_available > price_limit:
                raise RuntimeError(
                    f"{_normalize_sms_provider(getattr(config, 'provider', 'hero_sms'))}_get_number_failed: NO_NUMBERS (minPrice={float(min_limit or 0):.4f}, maxPrice={price_limit:.4f}, minAvailable={min_available:.4f})"
                )
            if price_limit is not None:
                raise RuntimeError(f"{_normalize_sms_provider(getattr(config, 'provider', 'hero_sms'))}_get_number_failed: NO_NUMBERS (minPrice={float(min_limit or 0):.4f}, maxPrice={price_limit:.4f})")
            raise RuntimeError(f"{_normalize_sms_provider(getattr(config, 'provider', 'hero_sms'))}_get_number_failed: NO_NUMBERS")
        raise RuntimeError(f"{_normalize_sms_provider(getattr(config, 'provider', 'hero_sms'))}_get_number_failed: {text[:300]}")
    activation_id = str(match.group(1) or "").strip()
    phone_number = str(match.group(2) or "").strip()
    if not phone_number.startswith("+"):
        phone_number = f"+{re.sub(r'[^0-9]', '', phone_number)}"
    price = ""
    if isinstance(payload, dict):
        for key in ("activationCost", "activation_cost", "price", "cost", "activationPrice", "activation_price"):
            value = str(payload.get(key) or "").strip()
            if value:
                price = value
                break
    if not price and (not _is_smsbower_config(config)) and price_limit is not None and price_limit > 0:
        price = f"≤{float(price_limit):.4f}"
    result = {"activation_id": activation_id, "phone_number": phone_number}
    if price:
        result["price"] = price
    return result


def poll_hero_sms_code(
    config: HeroSMSConfig,
    activation_id: str,
    *,
    on_resend: Any = None,
    timeout_after_resend: int | None = None,
    on_progress: Any = None,
    progress_interval: int = 15,
) -> str:
    resend_after = max(1, int(getattr(config, "resend_after_seconds", HERO_SMS_RESEND_AFTER_SECONDS) or HERO_SMS_RESEND_AFTER_SECONDS))
    release_after = max(1, int(getattr(config, "release_after_seconds", HERO_SMS_RELEASE_AFTER_SECONDS) or HERO_SMS_RELEASE_AFTER_SECONDS))
    timeout_after_resend_default = max(1, int(getattr(config, "timeout_after_resend_seconds", HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS) or HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS))
    wait_timeout = max(15, int(config.wait_timeout or release_after))
    effective_timeout_after_resend = (
        int(timeout_after_resend)
        if timeout_after_resend is not None
        else (timeout_after_resend_default if callable(on_resend) else None)
    )
    deadline = datetime.now(timezone.utc).timestamp() + wait_timeout
    interval = max(1, int(config.wait_interval or 5))
    heartbeat_interval = max(1, int(progress_interval or 15))
    start_ts = datetime.now(timezone.utc).timestamp()
    next_progress_ts = start_ts + heartbeat_interval
    resend_ts = 0.0
    resent = False
    while datetime.now(timezone.utc).timestamp() < deadline:
        if _is_5sim_config(config):
            payload = _5sim_request(config, f"/user/check/{quote(str(activation_id), safe='')}")
            code = _extract_5sim_sms_code(payload)
        else:
            payload = _hero_sms_request(config, {"action": "getStatus", "id": activation_id})
            code = _extract_sms_code(payload)
        if code:
            return code
        text = _hero_sms_text(payload)
        if re.search(r"STATUS_CANCEL|STATUS_BANNED|NO_ACTIVATION|BAD_STATUS|ERROR|CANCELED|CANCELLED|BANNED|TIMEOUT", text, re.I):
            raise RuntimeError(f"sms_terminal_status: {text[:300]}")
        elapsed = max(0, int(datetime.now(timezone.utc).timestamp() - start_ts))
        if (not resent) and elapsed >= resend_after:
            if callable(on_resend):
                on_resend()
            resent = True
            resend_ts = datetime.now(timezone.utc).timestamp()
            if effective_timeout_after_resend is not None:
                deadline = min(deadline, resend_ts + max(1, int(effective_timeout_after_resend)))
        now_ts = datetime.now(timezone.utc).timestamp()
        if callable(on_progress) and now_ts >= next_progress_ts:
            remaining = max(0, int(deadline - now_ts))
            on_progress(
                {
                    "elapsed": max(0, int(now_ts - start_ts)),
                    "wait_timeout": wait_timeout,
                    "remaining": remaining,
                    "resent": resent,
                    "resend_after_seconds": resend_after,
                    "after_resend_elapsed": max(0, int(now_ts - resend_ts)) if resent and resend_ts else 0,
                    "timeout_after_resend": int(effective_timeout_after_resend) if effective_timeout_after_resend is not None else None,
                }
            )
            next_progress_ts = now_ts + heartbeat_interval
        time.sleep(interval)
    raise RuntimeError("sms_code_timeout")


def set_hero_sms_status(config: HeroSMSConfig, activation_id: str, status: int) -> None:
    if not activation_id:
        return
    try:
        if _is_5sim_config(config):
            status_int = int(status)
            if status_int == 6:
                _5sim_request(config, f"/user/finish/{quote(str(activation_id), safe='')}")
            elif status_int == 8:
                _5sim_request(config, f"/user/cancel/{quote(str(activation_id), safe='')}")
            return
        _hero_sms_request(config, {"action": "setStatus", "id": activation_id, "status": int(status)})
    except Exception:
        return


def _phone_activation_acquire(
    config: HeroSMSConfig,
    *,
    max_price_override: float | None = None,
) -> dict[str, str]:
    activation = acquire_hero_sms_phone(config, max_price_override=max_price_override)
    return {
        "activation_id": str(activation.get("activation_id") or "").strip(),
        "phone_number": str(activation.get("phone_number") or "").strip(),
    }


def _phone_activation_reuse(phone_number: str, activation_id: str) -> dict[str, str]:
    return {
        "activation_id": str(activation_id or "").strip(),
        "phone_number": str(phone_number or "").strip(),
    }


def _phone_activation_poll_code(config: HeroSMSConfig, activation_id: str) -> str:
    return poll_hero_sms_code(config, activation_id)


def _phone_activation_complete(config: HeroSMSConfig, activation_id: str) -> None:
    set_hero_sms_status(config, activation_id, 6)


def _phone_activation_cancel(config: HeroSMSConfig, activation_id: str) -> None:
    set_hero_sms_status(config, activation_id, 8)


def _phone_activation_reactivate(config: HeroSMSConfig, activation_id: str) -> None:
    set_hero_sms_status(config, activation_id, 3)


def _auth_json_headers(registrar: PlatformRegistrar, referer: str, sentinel_flow: str) -> dict[str, str]:
    headers = get_common_headers()
    headers["accept"] = "application/json"
    headers["content-type"] = "application/json"
    headers["referer"] = referer
    headers["oai-device-id"] = registrar.device_id
    headers.update(_make_trace_headers())
    try:
        headers["OpenAI-Sentinel-Token"] = registrar._ensure_sentinel_token(sentinel_flow)
    except Exception as exc:
        headers["x-openai-sentinel-error"] = str(exc)
    return headers


def _contains_whatsapp_marker(payload: Any) -> bool:
    text = json.dumps(payload, ensure_ascii=False).lower() if isinstance(payload, (dict, list)) else str(payload or "").lower()
    return "whatsapp" in text


def _fetch_phone_verification_page_text(registrar: PlatformRegistrar, candidate_url: str = "") -> str:
    urls = []
    if candidate_url:
        urls.append(candidate_url)
    urls.extend(
        [
            f"{auth_base}/phone-verification",
            f"{auth_base}/add-phone",
        ]
    )
    for url in urls:
        target = f"{auth_base}{url}" if str(url).startswith("/") else str(url)
        response, _ = request_with_local_retry(
            registrar.session,
            "get",
            target,
            headers=get_navigate_headers(),
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            continue
        try:
            text = str(response.text or "")
        except Exception:
            text = ""
        if text:
            return text
    return ""


def _is_static_flow_asset(url: str) -> bool:
    lowered = str(url or "").strip().lower()
    if not lowered:
        return False
    if "oaistatic.com/assets/" in lowered:
        return True
    return bool(re.search(r"\.(?:svg|png|jpg|jpeg|gif|webp|ico|css|js|map|woff2?|ttf|eot)(?:[?#].*)?$", lowered))


def _sanitize_flow_candidate(candidate: str) -> str:
    normalized = str(candidate or "").strip().strip('"\'')
    if not normalized:
        return ""
    if normalized.startswith("\\/"):
        normalized = normalized.replace("\\/", "/")
    normalized = normalized.replace("&amp;", "&")
    normalized = normalized.rstrip('.,;)]}"\'')
    if normalized.startswith("/"):
        normalized = f"{auth_base}{normalized}"
    if not normalized.startswith(("http://", "https://")):
        return ""
    if _is_static_flow_asset(normalized):
        return ""
    parsed = urlparse(normalized)
    if not parsed.scheme or not parsed.netloc:
        return ""
    return urlunparse(parsed)


def _iter_flow_url_candidates(value: Any) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()

    def _push(candidate: str) -> None:
        normalized = _sanitize_flow_candidate(candidate)
        if not normalized:
            return
        if normalized in seen:
            return
        seen.add(normalized)
        candidates.append(normalized)

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for item in node.values():
                _walk(item)
            return
        if isinstance(node, (list, tuple, set)):
            for item in node:
                _walk(item)
            return
        text = str(node or "")
        if not text:
            return
        variants = [text]
        if "\\/" in text:
            variants.append(text.replace("\\/", "/"))
        for variant in variants:
            for match in re.finditer(r"https?://[^\"'\s<>\\]+", variant, re.I):
                _push(str(match.group(0) or ""))
            for match in re.finditer(r"(?<![A-Za-z0-9.:])/(?:authorize/resume|sign-in-with-chatgpt/codex/consent|u/[A-Za-z0-9_./-]+|create-account/[A-Za-z0-9_./-]+|add-email(?:[/?][^\"'\s<>\\]*)?|auth/callback\?[^\"'\s<>\\]+)[^\"'\s<>\\]*", variant, re.I):
                _push(str(match.group(0) or ""))

    _walk(value)
    return candidates


def _flow_url_priority(url: str) -> tuple[int, int]:
    normalized = str(url or "").strip()
    lowered = normalized.lower()
    if not normalized or _is_static_flow_asset(normalized):
        return (99, 0)
    if extract_oauth_callback_params_from_url(normalized):
        return (0, -len(normalized))
    if any(token in lowered for token in (
        "/authorize/resume",
        "/sign-in-with-chatgpt/codex/consent",
        "/add-email",
        "/add-phone",
        "/phone-verification",
        "/create-account/",
        "/u/signup",
        "/about-you",
    )):
        return (1, -len(normalized))
    if lowered.startswith(auth_base.lower()):
        return (5, -len(normalized))
    return (10, -len(normalized))


def _choose_preferred_flow_url(candidates: list[str], fallback: str = "") -> str:
    ranked: list[str] = [candidate for candidate in candidates if not _is_static_flow_asset(candidate)]
    normalized_fallback = str(fallback or "").strip()
    if normalized_fallback and not _is_static_flow_asset(normalized_fallback):
        ranked.append(normalized_fallback)
    if not ranked:
        return normalized_fallback
    ranked = sorted(dict.fromkeys(ranked), key=_flow_url_priority)
    return ranked[0]


def _extract_callback_url_from_text(text: str) -> str:
    for candidate in sorted(_iter_flow_url_candidates(text), key=_flow_url_priority):
        normalized = _sanitize_flow_candidate(candidate)
        if normalized and extract_oauth_callback_params_from_url(normalized):
            return normalized
    return ""


def _probe_phone_signup_password_page(registrar: PlatformRegistrar, phone_number: str) -> dict[str, Any]:
    target = str((registrar.last_authorize or {}).get("final_url") or "").strip() or f"{auth_base}/create-account/password"
    response, error = request_with_local_retry(
        registrar.session,
        "get",
        target,
        headers=get_navigate_headers(),
        allow_redirects=True,
        verify=False,
    )
    if response is None:
        return {
            "ok": False,
            "matched": False,
            "url": target,
            "final_url": target,
            "status": 0,
            "error": error,
            "title": "",
            "text": "",
        }
    final_url = str(getattr(response, "url", "") or target)
    status = int(getattr(response, "status_code", 0) or 0)
    try:
        text = str(getattr(response, "text", "") or "")
    except Exception:
        text = ""
    phone_value = str(phone_number or "").strip()
    title_match = re.search(r"<title>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", str(title_match.group(1) or "")).strip() if title_match else ""
    normalized_phone_digits = re.sub(r"\D+", "", phone_value)
    html_phone_digits = re.sub(r"\D+", "", text)
    password_route_like = any(token in final_url for token in (
        "/create-account/password",
        "/log-in/password",
        "/u/signup/password",
    ))
    password_content_like = (
        "create-account/password" in text
        or "log-in/password" in text
        or 'type="password"' in text
        or "Enter your password" in text
        or "Create your password" in text
        or "Continue with password" in text
        or "title=\"Enter your password - OpenAI\"" in text
    )
    matched = bool(
        status == 200
        and password_route_like
        and password_content_like
        and (
            not normalized_phone_digits
            or normalized_phone_digits in html_phone_digits
            or f'name="username" value="{phone_value}"' in text
        )
    )
    return {
        "ok": status == 200,
        "matched": matched,
        "url": target,
        "final_url": final_url,
        "status": status,
        "error": error,
        "title": title,
        "text": text,
    }


def _load_continue_page(registrar: PlatformRegistrar, continue_url: str) -> dict[str, Any]:
    target = str(continue_url or "").strip()
    if not target:
        return {
            "ok": False,
            "continue_url": "",
            "page_type": "",
            "callback_url": "",
            "location": "",
            "text": "",
            "json": {},
        }
    response, error = request_with_local_retry(
        registrar.session,
        "get",
        target,
        headers=get_navigate_headers(),
        allow_redirects=True,
        verify=False,
    )
    if response is None:
        return {
            "ok": False,
            "continue_url": target,
            "page_type": "",
            "callback_url": "",
            "location": "",
            "text": "",
            "json": {},
            "error": error,
        }
    final_url = str(getattr(response, "url", "") or target)
    location = str(getattr(response, "headers", {}).get("Location") or "").strip()
    if _is_static_flow_asset(final_url):
        final_url = target
    body = _response_json(response) if response is not None else {}
    page_type = str((body.get("page") or {}).get("type") or "").strip() if isinstance(body, dict) else ""
    try:
        text = str(getattr(response, "text", "") or "")
    except Exception:
        text = ""
    flow_candidates = _iter_flow_url_candidates([body, text, location, final_url, target])
    callback_url = ""
    for candidate in sorted(flow_candidates, key=_flow_url_priority):
        if extract_oauth_callback_params_from_url(candidate):
            callback_url = candidate
            break
    non_callback_candidates = [candidate for candidate in flow_candidates if not extract_oauth_callback_params_from_url(candidate)]
    resolved_continue_url = _choose_preferred_flow_url(non_callback_candidates, fallback=final_url or target)
    return {
        "ok": True,
        "continue_url": resolved_continue_url or final_url,
        "page_type": page_type,
        "callback_url": callback_url,
        "location": location,
        "text": text,
        "json": body,
    }


def _build_plain_retry_session(proxy: str = "") -> requests.Session:
    session = requests.Session()
    session.verify = False
    adapter = requests.adapters.HTTPAdapter(max_retries=2, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    normalized_proxy = str(proxy or "").strip()
    if normalized_proxy and not _is_socks_proxy(normalized_proxy):
        session.proxies.update({"http": normalized_proxy, "https": normalized_proxy})
    return session


def _resolve_oauth_callback(registrar: PlatformRegistrar, candidate_url: str, state: str, *, max_steps: int = 12, request_timeout: int = 8, include_codex_consent: bool = True) -> str:
    urls: list[str] = []
    seen: set[str] = set()

    def _enqueue(url: str) -> None:
        normalized = str(url or "").strip()
        if not normalized:
            return
        if normalized.startswith("/"):
            normalized = f"{auth_base}{normalized}"
        if normalized in seen:
            return
        seen.add(normalized)
        urls.append(normalized)

    def _try_with_session(active_session: Any, device_id: str) -> str:
        pending = list(urls)
        local_seen = set(seen)
        steps = 0
        while pending and steps < max(1, int(max_steps or 12)):
            steps += 1
            url = pending.pop(0)
            try:
                response = active_session.request(
                    "GET",
                    url,
                    headers=get_navigate_headers(),
                    allow_redirects=True,
                    verify=False,
                    timeout=max(3, int(request_timeout or 8)),
                )
            except Exception:
                response = None
            final_url = str(getattr(response, "url", "") or "")
            location = str(getattr(response, "headers", {}).get("Location") or "")
            body = _response_json(response) if response is not None else {}
            try:
                text = str(getattr(response, "text", "") or "")
            except Exception:
                text = ""
            for candidate in _iter_flow_url_candidates([final_url, location, body, text]):
                normalized_candidate = _sanitize_flow_candidate(candidate)
                if normalized_candidate and extract_oauth_callback_params_from_url(normalized_candidate):
                    return normalized_candidate
                if normalized_candidate and normalized_candidate not in local_seen:
                    local_seen.add(normalized_candidate)
                    pending.append(normalized_candidate)
            if include_codex_consent:
                consent_candidate = final_url or location or url
                try:
                    callback_params = extract_oauth_callback_params_from_consent_session(
                        active_session,
                        consent_candidate,
                        device_id,
                    )
                except Exception:
                    callback_params = None
                if callback_params:
                    code = str(callback_params.get("code") or "").strip()
                    cb_state = str(callback_params.get("state") or state or "").strip()
                    if code and cb_state:
                        return f"http://localhost:1455/auth/callback?code={code}&state={cb_state}"
                    if code:
                        return f"http://localhost:1455/auth/callback?code={code}"
            try:
                if response is not None and 200 <= int(getattr(response, 'status_code', 0) or 0) < 400:
                    hidden = _extract_form_inputs(text)
            except Exception:
                hidden = ("", {}, "", "")
            try:
                action, fields, email_name, code_name = hidden
            except Exception:
                action, fields, email_name, code_name = "", {}, "", ""
            if action:
                form_action = action if action.startswith('http') else f"{auth_base}{action}" if action.startswith('/') else action
                payload = dict(fields)
                if email_name and "email" not in payload:
                    payload[email_name] = ""
                if code_name and code_name not in payload:
                    payload[code_name] = ""
                if "code" in payload:
                    payload["code"] = str(payload.get("code") or "").strip()
                if "state" in payload and not payload.get("state"):
                    payload["state"] = state
                form_method = 'post'
                try:
                    form_resp = active_session.request(
                        form_method.upper(),
                        form_action,
                        data=payload if form_method == 'post' else None,
                        headers=get_navigate_headers(),
                        allow_redirects=True,
                        verify=False,
                        timeout=max(3, int(request_timeout or 8)),
                    )
                except Exception:
                    form_resp = None
                form_final = str(getattr(form_resp, 'url', '') or '')
                form_loc = str(getattr(form_resp, 'headers', {}).get('Location') or '')
                form_body = _response_json(form_resp) if form_resp is not None else {}
                try:
                    form_text = str(getattr(form_resp, 'text', '') or '')
                except Exception:
                    form_text = ''
                for candidate in _iter_flow_url_candidates([form_final, form_loc, form_body, form_text]):
                    normalized_candidate = _sanitize_flow_candidate(candidate)
                    if normalized_candidate and extract_oauth_callback_params_from_url(normalized_candidate):
                        return normalized_candidate
                if include_codex_consent:
                    try:
                        form_callback_params = extract_oauth_callback_params_from_consent_session(
                            active_session,
                            form_final or form_loc or form_action,
                            device_id,
                        )
                    except Exception:
                        form_callback_params = None
                    if form_callback_params:
                        code = str(form_callback_params.get('code') or '').strip()
                        cb_state = str(form_callback_params.get('state') or state or '').strip()
                        if code and cb_state:
                            return f"http://localhost:1455/auth/callback?code={code}&state={cb_state}"
                        if code:
                            return f"http://localhost:1455/auth/callback?code={code}"
        return ""

    if candidate_url:
        if extract_oauth_callback_params_from_url(candidate_url):
            return candidate_url
        _enqueue(candidate_url)
    if state:
        _enqueue(f"{auth_base}/authorize/resume?state={state}")
        if include_codex_consent:
            _enqueue(f"{auth_base}/sign-in-with-chatgpt/codex/consent?state={state}")
    if include_codex_consent:
        _enqueue(f"{auth_base}/sign-in-with-chatgpt/codex/consent")

    try:
        callback_url = _try_with_session(registrar.session, registrar.device_id)
        if callback_url:
            return callback_url
    except Exception as exc:
        message = str(exc or "").strip().lower()
        if "tls connect error" not in message and "openssl_internal" not in message:
            raise
        plain_session = _build_plain_retry_session(str(getattr(registrar, "proxy", "") or ""))
        try:
            plain_session.cookies.update(registrar.session.cookies)
            callback_url = _try_with_session(plain_session, registrar.device_id)
            if callback_url:
                return callback_url
        finally:
            plain_session.close()
    return ""


def _extract_attr(attrs: str, name: str) -> str:
    text = str(attrs or "")
    match = re.search(rf'{re.escape(name)}\s*=\s*["\']([^"\']*)["\']', text, re.I | re.S)
    if not match:
        match = re.search(rf'{re.escape(name)}\s*=\s*([^\s"\'<>`]+)', text, re.I | re.S)
    return str(match.group(1) or "").strip() if match else ""


def _strip_html_tags(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", str(value or ""))


def _extract_form_inputs(html_text: str) -> tuple[str, dict[str, str], str, str]:
    text = str(html_text or "")
    form_matches = list(re.finditer(r"<form\b([^>]*)>(.*?)</form>", text, re.I | re.S))
    if not form_matches:
        return "", {}, "", ""

    def _score_form(match: re.Match[str]) -> tuple[int, int]:
        attrs = match.group(1) or ""
        body = match.group(2) or ""
        haystack = f"{attrs}\n{_strip_html_tags(body)}".lower()
        score = 0
        for token, weight in [
            ("codex", 30),
            ("consent", 24),
            ("authorize", 24),
            ("authorise", 24),
            ("allow", 18),
            ("approve", 18),
            ("agree", 12),
            ("continue", 10),
            ("confirm", 10),
            ("submit", 5),
            ("state", 4),
        ]:
            if token in haystack:
                score += weight
        if re.search(r"<button\b|type\s*=\s*[\"']submit[\"']", body, re.I):
            score += 8
        if re.search(r"name\s*=\s*[\"'](?:email|code|otp|state)[\"']", body, re.I):
            score += 4
        if re.search(r"<input\b[^>]*(?:type\s*=\s*[\"']email[\"']|name\s*=\s*[\"'][^\"']*email[^\"']*[\"'])", body, re.I):
            score += 35
        if re.search(r"<input\b[^>]*name\s*=\s*[\"'][^\"']*(?:code|otp)[^\"']*[\"']", body, re.I):
            score += 28
        return score, len(body)

    form_match = max(form_matches, key=_score_form)
    form_attrs = form_match.group(1) or ""
    form_body = form_match.group(2) or ""
    action = _extract_attr(form_attrs, "action")
    form_id = _extract_attr(form_attrs, "id")
    hidden: dict[str, str] = {}
    email_name = ""
    code_name = ""
    submit_choice: tuple[int, str, str, str] | None = None

    def _submit_score(label: str, input_type: str) -> int:
        haystack = f"{label} {input_type}".lower()
        score = 0
        for token, weight in [
            ("codex", 40),
            ("authorize", 35),
            ("authorise", 35),
            ("allow", 30),
            ("approve", 30),
            ("consent", 24),
            ("agree", 18),
            ("confirm", 16),
            ("continue", 12),
            ("submit", 6),
        ]:
            if token in haystack:
                score += weight
        return score

    input_attrs: list[str] = []
    seen_inputs: set[str] = set()
    for input_match in re.finditer(r"<input\b([^>]*)>", form_body, re.I | re.S):
        markup = input_match.group(0)
        if markup not in seen_inputs:
            seen_inputs.add(markup)
            input_attrs.append(input_match.group(1) or "")
    if form_id:
        for input_match in re.finditer(r"<input\b([^>]*)>", text, re.I | re.S):
            attrs = input_match.group(1) or ""
            markup = input_match.group(0)
            if markup not in seen_inputs and _extract_attr(attrs, "form") == form_id:
                seen_inputs.add(markup)
                input_attrs.append(attrs)

    has_explicit_marker = bool(re.search(r"isExplicitConsentRequired", text, re.I))

    def _include_checkbox_like(name: str, attrs: str) -> bool:
        haystack = f"{name} {attrs}".lower()
        return bool(
            re.search(r"\bchecked\b", attrs, re.I)
            or re.search(r"(?:^|\s)required(?:\s|=|$)", attrs, re.I)
            or re.search(r"consent|agree|terms|privacy|policy|checkbox|accept", haystack)
            or has_explicit_marker
        )

    for attrs in input_attrs:
        name = _extract_attr(attrs, "name")
        if not name:
            continue
        input_type = _extract_attr(attrs, "type").lower()
        value = _extract_attr(attrs, "value")
        if input_type in ("hidden", "checkbox", "radio"):
            if input_type not in ("checkbox", "radio") or _include_checkbox_like(name, attrs):
                hidden[name] = value if value != "" or input_type == "hidden" else "on"
        if input_type in ("submit", "button", "image"):
            score = _submit_score(f"{name} {value}", input_type)
            candidate = (score, name, value, _extract_attr(attrs, "formaction"))
            if submit_choice is None or candidate[0] > submit_choice[0]:
                submit_choice = candidate
        if not email_name and (input_type == "email" or "email" in name.lower()):
            email_name = name
        if not code_name and ("code" in name.lower() or "otp" in name.lower()):
            code_name = name

    button_matches: list[tuple[str, str]] = []
    seen_buttons: set[str] = set()
    for button_match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", form_body, re.I | re.S):
        markup = button_match.group(0)
        if markup not in seen_buttons:
            seen_buttons.add(markup)
            button_matches.append((button_match.group(1) or "", button_match.group(2) or ""))
    if form_id:
        for button_match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", text, re.I | re.S):
            attrs = button_match.group(1) or ""
            markup = button_match.group(0)
            if markup not in seen_buttons and _extract_attr(attrs, "form") == form_id:
                seen_buttons.add(markup)
                button_matches.append((attrs, button_match.group(2) or ""))

    for attrs, body in button_matches:
        button_type = _extract_attr(attrs, "type").lower() or "submit"
        if button_type not in ("", "submit"):
            continue
        name = _extract_attr(attrs, "name")
        value = _extract_attr(attrs, "value") or _strip_html_tags(body).strip()
        score = _submit_score(f"{name} {value}", button_type)
        candidate = (score, name, value, _extract_attr(attrs, "formaction"))
        if submit_choice is None or candidate[0] > submit_choice[0]:
            submit_choice = candidate

    if submit_choice:
        if submit_choice[1] and submit_choice[1] not in hidden:
            hidden[submit_choice[1]] = submit_choice[2]
        if submit_choice[3]:
            action = submit_choice[3]
    return action, hidden, email_name, code_name


def _extract_add_email_code_form_inputs(html_text: str) -> tuple[str, dict[str, str], str, str]:
    text = str(html_text or "")
    form_matches = list(re.finditer(r"<form\b([^>]*)>(.*?)</form>", text, re.I | re.S))
    if not form_matches:
        return _extract_form_inputs(text)

    def _score_form(match: re.Match[str]) -> tuple[int, int]:
        attrs = match.group(1) or ""
        body = match.group(2) or ""
        haystack = f"{attrs}\n{_strip_html_tags(body)}".lower()
        score = 0
        for token, weight in [
            ("email-verification", 44),
            ("email verification", 44),
            ("add-email/verify", 42),
            ("email-otp", 38),
            ("otp", 34),
            ("verification code", 30),
            ("code", 24),
            ("verify", 22),
            ("confirm", 12),
            ("continue", 8),
        ]:
            if token in haystack:
                score += weight
        if re.search(r"<input\b[^>]*name\s*=\s*[\"'][^\"']*(?:code|otp)[^\"']*[\"']", body, re.I):
            score += 80
        if re.search(r"<input\b[^>]*(?:type\s*=\s*[\"']email[\"']|name\s*=\s*[\"'][^\"']*email[^\"']*[\"'])", body, re.I):
            score -= 45
        return score, len(body)

    form_match = max(form_matches, key=_score_form)
    form_attrs = form_match.group(1) or ""
    form_body = form_match.group(2) or ""
    action = _extract_attr(form_attrs, "action")
    hidden: dict[str, str] = {}
    email_name = ""
    code_name = ""
    submit_choice: tuple[int, str, str, str] | None = None

    def _submit_score(label: str, input_type: str) -> int:
        haystack = f"{label} {input_type}".lower()
        score = 0
        for token, weight in [
            ("verify", 35),
            ("verification", 30),
            ("code", 26),
            ("otp", 26),
            ("confirm", 18),
            ("continue", 10),
            ("submit", 6),
        ]:
            if token in haystack:
                score += weight
        for token, weight in [("send", -18), ("resend", -14), ("email", -8)]:
            if token in haystack:
                score += weight
        return score

    for input_match in re.finditer(r"<input\b([^>]*)>", form_body, re.I | re.S):
        attrs = input_match.group(1) or ""
        name = _extract_attr(attrs, "name")
        if not name:
            continue
        input_type = _extract_attr(attrs, "type").lower()
        value = _extract_attr(attrs, "value")
        if input_type in ("hidden", "checkbox", "radio"):
            if input_type not in ("checkbox", "radio") or re.search(r"\bchecked\b", attrs, re.I):
                hidden[name] = value
        if input_type in ("submit", "button", "image"):
            candidate = (_submit_score(f"{name} {value}", input_type), name, value, _extract_attr(attrs, "formaction"))
            if submit_choice is None or candidate[0] > submit_choice[0]:
                submit_choice = candidate
        if not email_name and (input_type == "email" or "email" in name.lower()):
            email_name = name
        if not code_name and ("code" in name.lower() or "otp" in name.lower()):
            code_name = name

    for button_match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", form_body, re.I | re.S):
        attrs = button_match.group(1) or ""
        button_type = _extract_attr(attrs, "type").lower() or "submit"
        if button_type not in ("", "submit"):
            continue
        name = _extract_attr(attrs, "name")
        value = _extract_attr(attrs, "value") or _strip_html_tags(button_match.group(2) or "").strip()
        candidate = (_submit_score(f"{name} {value}", button_type), name, value, _extract_attr(attrs, "formaction"))
        if submit_choice is None or candidate[0] > submit_choice[0]:
            submit_choice = candidate

    if submit_choice:
        if submit_choice[1] and submit_choice[1] not in hidden:
            hidden[submit_choice[1]] = submit_choice[2]
        if submit_choice[3]:
            action = submit_choice[3]
    return action, hidden, email_name, code_name


def _submit_about_you_form(
    registrar: PlatformRegistrar,
    *,
    page_url: str,
    page_html: str,
    full_name: str,
    birthdate: str,
) -> tuple[str, str]:
    target = str(page_url or '').strip()
    if not target:
        raise RuntimeError('about_you_page_url_missing')

    html_candidates: list[str] = [str(page_html or '')]
    refresh_urls = [
        target,
        _merge_url_query(target, _data='routes/about-you') if '/about-you' in target else '',
        _merge_url_query(target, _data='routes/_auth/about-you') if '/about-you' in target else '',
    ]
    for refresh_url in dict.fromkeys([url for url in refresh_urls if url]):
        try:
            response, _ = request_with_local_retry(
                registrar.session,
                'get',
                refresh_url,
                headers=get_navigate_headers(),
                allow_redirects=True,
                verify=False,
            )
            if response is None:
                continue
            fresh_html = str(getattr(response, 'text', '') or '')
            if fresh_html and fresh_html not in html_candidates:
                html_candidates.append(fresh_html)
        except Exception:
            continue

    selected_html = ''
    for candidate_html in html_candidates:
        if re.search(r'<form\b', candidate_html, re.I) or re.search(r'name\s*=\s*["\'](?:name|birthdate|birthday|age)["\']', candidate_html, re.I):
            selected_html = candidate_html
            break
    if not selected_html:
        selected_html = html_candidates[-1] if html_candidates else ''

    action, hidden, _, _ = _extract_form_inputs(selected_html)
    try:
        birth_year = int(str(birthdate or '').split('-', 1)[0])
        age_value = max(18, datetime.now(timezone.utc).year - birth_year)
    except Exception:
        age_value = 21

    shape = _about_you_page_shape(selected_html)
    preferred = str(shape.get('preferred') or 'unknown')
    birthday_fields = list(shape.get('birthday_fields') or ['birthdate', 'birthday'])

    base_payload = dict(hidden)
    base_payload.update(_about_you_consent_fields(selected_html))
    for field_name in ('age', 'birthday', 'birthdate'):
        base_payload.pop(field_name, None)
    candidate_payloads: list[dict[str, str]] = []

    def _add_payload(extra: dict[str, str]) -> None:
        payload = dict(base_payload)
        payload.update({key: str(value) for key, value in extra.items() if value not in (None, '')})
        if payload not in candidate_payloads:
            candidate_payloads.append(payload)

    detected_name = bool(re.search(r'name\s*=\s*["\']name["\']', selected_html, re.I) or re.search(r'autocomplete\s*=\s*["\']name["\']', selected_html, re.I))
    detected_birthday = bool(re.search(r'name\s*=\s*["\'](?:birthday|birthdate)["\']', selected_html, re.I))
    detected_age = bool(re.search(r'name\s*=\s*["\']age["\']', selected_html, re.I))

    if preferred == 'age':
        _add_payload({'name': full_name, 'age': str(age_value)})
        for field_name in birthday_fields:
            _add_payload({'name': full_name, field_name: birthdate})
    elif preferred == 'birthday':
        for field_name in birthday_fields:
            _add_payload({'name': full_name, field_name: birthdate})
        _add_payload({'name': full_name, 'age': str(age_value)})
    else:
        if detected_name or detected_birthday:
            for field_name in birthday_fields:
                _add_payload({'name': full_name, field_name: birthdate})
        if detected_name or detected_age:
            _add_payload({'name': full_name, 'age': str(age_value)})

    for field_name in birthday_fields:
        _add_payload({'name': full_name, field_name: birthdate})
    _add_payload({'name': full_name, 'age': str(age_value)})
    _add_payload({'name': full_name, 'birthday': birthdate, 'age': str(age_value)})
    _add_payload({'name': full_name, 'birthday': birthdate, 'allCheckboxes': 'on'})
    _add_payload({'name': full_name, 'age': str(age_value), 'allCheckboxes': 'on'})
    _add_payload({'name': full_name, 'birthday': birthdate, 'age': str(age_value), 'allCheckboxes': 'on'})

    def _about_you_data_urls(raw_url: str) -> list[str]:
        parsed = urlparse(raw_url)
        path = parsed.path or "/about-you"
        if not path.endswith(".data"):
            path = f"{path.rstrip('/')}.data"
        base_query = parse_qs(parsed.query, keep_blank_values=True)
        urls: list[str] = []
        for route_id in ("routes/about-you", "routes/_auth/about-you", "routes/_auth.about-you"):
            query = {key: values[:] for key, values in base_query.items()}
            query["_routes"] = [route_id]
            urls.append(urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, urlencode(query, doseq=True), parsed.fragment)))
        return urls

    candidate_actions = ['', action or '/about-you']
    candidate_urls = [target]
    if '/about-you' in target:
        candidate_urls.extend([
            _merge_url_query(target, _data='routes/about-you'),
            _merge_url_query(target, _data='routes/_auth/about-you'),
            *_about_you_data_urls(target),
        ])

    last_error = 'about_you_form_submit_failed'
    attempts: list[str] = []
    for candidate_url in dict.fromkeys(candidate_urls):
        for candidate_action in candidate_actions:
            for payload in candidate_payloads:
                try:
                    final_url, body = _post_form_and_follow(
                        registrar,
                        page_url=candidate_url,
                        action=candidate_action,
                        payload=payload,
                    )
                    attempts.append(f"{urlparse(candidate_url).path or '/'}:{'+'.join(key for key in payload.keys() if key != 'name') or 'name'}")
                    normalized_body = str(body or '').lower()
                    if final_url and '/about-you' not in final_url:
                        return final_url, body
                    if extract_oauth_callback_params_from_url(final_url):
                        return final_url, body
                    follow_probe = _load_continue_page(registrar, final_url or candidate_url)
                    follow_url = str(follow_probe.get('continue_url') or final_url or candidate_url).strip()
                    follow_callback = str(follow_probe.get('callback_url') or '').strip()
                    follow_page_type = str(follow_probe.get('page_type') or '').strip()
                    if follow_callback:
                        return follow_callback, str(follow_probe.get('text') or body or '')
                    if follow_url and '/about-you' not in follow_url:
                        return follow_url, str(follow_probe.get('text') or body or '')
                    if follow_page_type in ('add_email', 'consent', 'oauth_consent'):
                        return follow_url or final_url or candidate_url, str(follow_probe.get('text') or body or '')
                    last_error = f'about_you_still_on_page::{follow_url or final_url or candidate_url}'
                except Exception as exc:
                    last_error = str(exc or 'about_you_form_submit_failed')
                    continue
    if attempts:
        last_error = f"{last_error}; attempts={', '.join(attempts[-8:])}"
    raise RuntimeError(last_error or 'about_you_form_submit_failed')


def _post_form_and_follow(
    registrar: PlatformRegistrar,
    *,
    page_url: str,
    action: str,
    payload: dict[str, str],
) -> tuple[str, str]:
    raw_action = str(action or "").strip()
    if not raw_action:
        target = page_url
    elif raw_action.startswith("http://") or raw_action.startswith("https://"):
        target = raw_action
    elif raw_action.startswith("?"):
        parsed = urlparse(page_url)
        target = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, raw_action[1:], parsed.fragment))
    else:
        target = urljoin(page_url, raw_action)
    headers = get_navigate_headers()
    headers["content-type"] = "application/x-www-form-urlencoded"
    headers["origin"] = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"
    headers["referer"] = page_url
    if ".data" in target or "_data=" in target or "_routes=" in target:
        headers["accept"] = "*/*"
        headers["sec-fetch-dest"] = "empty"
        headers["sec-fetch-mode"] = "cors"
        headers["sec-fetch-site"] = "same-origin"
        headers["x-remix-request"] = "yes"
    response, error = request_with_local_retry(
        registrar.session,
        "post",
        target,
        data=payload,
        headers=headers,
        allow_redirects=True,
        verify=False,
    )
    if response is None:
        raise RuntimeError(error or "form_submit_failed")
    final_url = str(getattr(response, "url", "") or target)
    try:
        body = str(response.text or "")
    except Exception:
        body = ""
    return final_url, body


_PHONE_FLOW_SIGNUP_VERIFIED_STAGES = frozenset({
    "signup_sms_verified",
    "oauth_phone_verified",
    "awaiting_callback",
    "awaiting_cpa_callback",
    "callback_fetched",
    "cpa_callback_fetched",
    "callback_submitted",
})

_PHONE_FLOW_OAUTH_VERIFIED_STAGES = frozenset({
    "oauth_phone_verified",
    "awaiting_callback",
    "awaiting_cpa_callback",
    "callback_fetched",
    "cpa_callback_fetched",
    "callback_submitted",
})


def _classify_phone_flow_error(raw_error: str) -> PhoneFlowFailure:
    message = str(raw_error or "").strip()
    lowered = message.lower()
    if not message:
        return PhoneFlowFailure(code="unknown", message="", retryable=False, recovery_action="stop")
    if "whatsapp_channel_detected" in lowered:
        return PhoneFlowFailure(code="unexpected_delivery_channel", message=message, retryable=True, recovery_action="replace_phone")
    if "sms_code_timeout" in lowered or "hero_sms_code_timeout" in lowered or "phone_otp_timeout" in lowered:
        return PhoneFlowFailure(code="sms_timeout", message=message, retryable=True, recovery_action="resend_or_replace_phone")
    if lowered.startswith("validate_phone_signup_otp_") or "phone_otp_validate_failed" in lowered:
        return PhoneFlowFailure(code="sms_rejected", message=message, retryable=True, recovery_action="replace_phone")
    if "add_phone_send_failed" in lowered:
        return PhoneFlowFailure(code="phone_submission_failed", message=message, retryable=True, recovery_action="replace_phone")
    if "cpa_callback_submit_failed" in lowered:
        return PhoneFlowFailure(code="cpa_callback_submit_failed", message=message, retryable=True, recovery_action="retry_callback_submit")
    if "callback_submit_failed" in lowered:
        return PhoneFlowFailure(code="callback_submit_failed", message=message, retryable=True, recovery_action="retry_callback_submit")
    if "callback_not_reached" in lowered or "callback_not_ready" in lowered or "cpa_callback_not_reached" in lowered or "cpa_callback_not_ready" in lowered:
        return PhoneFlowFailure(code="callback_not_produced", message=message, retryable=True, recovery_action="retry_callback_fetch")
    if "bind_email" in lowered or "add_email" in lowered:
        retryable = "timeout" in lowered or "required" in lowered
        return PhoneFlowFailure(code="bind_email_failed", message=message, retryable=retryable, recovery_action="retry_bind_email" if retryable else "stop")
    if (
        "continue_url" in lowered
        or "create_account_" in lowered
        or "session_establishment_failed" in lowered
        or "page_shape" in lowered
        or "unexpected_page" in lowered
    ):
        return PhoneFlowFailure(code="page_shape_unexpected", message=message, retryable=False, recovery_action="stop")
    return PhoneFlowFailure(code="phone_signup_failed", message=message, retryable=False, recovery_action="stop")


def _build_phone_flow_runtime(
    *,
    phone_number: str = "",
    activation_id: str = "",
    provider: str = "",
    stage: str = "partial",
    purpose: str = "signup",
    status: str = "partial",
    bind_email: str = "",
    callback_url: str = "",
    callback_source: str = "",
    import_submit_ok: bool | None = None,
    import_submit_message: str = "",
    last_error: str = "",
    error_code: str = "",
    error_retryable: bool = False,
    recovery_action: str = "stop",
) -> dict[str, Any]:
    normalized_stage = str(stage or status or "partial").strip() or "partial"
    resolved_provider = str(provider or "").strip() or ("hero_sms" if phone_number or activation_id else "")
    return {
        "phone_number": str(phone_number or "").strip(),
        "activation_id": str(activation_id or "").strip(),
        "provider": resolved_provider,
        "stage": normalized_stage,
        "status": str(status or normalized_stage or "partial").strip() or "partial",
        "purpose": str(purpose or "signup").strip() or "signup",
        "bind_email": str(bind_email or "").strip(),
        "signup_verified": normalized_stage in _PHONE_FLOW_SIGNUP_VERIFIED_STAGES,
        "oauth_verified": normalized_stage in _PHONE_FLOW_OAUTH_VERIFIED_STAGES,
        "callback": {
            "url": str(callback_url or "").strip(),
            "source": str(callback_source or "").strip(),
        },
        "import_submit_ok": import_submit_ok,
        "import_submit_message": str(import_submit_message or "").strip(),
        "error": {
            "code": str(error_code or "").strip(),
            "message": str(last_error or "").strip(),
            "retryable": bool(error_retryable),
            "recovery_action": str(recovery_action or "stop").strip() or "stop",
        },
    }


def _set_phone_flow_stage(
    phone_flow: dict[str, Any],
    stage: str,
    *,
    status: str | None = None,
    bind_email: str | None = None,
    callback_url: str | None = None,
    callback_source: str | None = None,
    import_submit_ok: bool | None = None,
    import_submit_message: str | None = None,
    cpa_submit_ok: bool | None = None,
    cpa_submit_message: str | None = None,
    last_error: str | None = None,
    error_code: str | None = None,
    error_retryable: bool | None = None,
    recovery_action: str | None = None,
    purpose: str | None = None,
) -> dict[str, Any]:
    phone_flow["stage"] = str(stage or phone_flow.get("stage") or "partial").strip() or "partial"
    if status is not None:
        phone_flow["status"] = str(status or "").strip() or phone_flow["stage"]
    else:
        phone_flow["status"] = str(phone_flow.get("status") or phone_flow["stage"]).strip() or phone_flow["stage"]
    if bind_email is not None:
        phone_flow["bind_email"] = str(bind_email or "").strip()
    if purpose is not None:
        phone_flow["purpose"] = str(purpose or "signup").strip() or "signup"
    callback = dict(phone_flow.get("callback") or {})
    if callback_url is not None:
        callback["url"] = str(callback_url or "").strip()
    if callback_source is not None:
        callback["source"] = str(callback_source or "").strip()
    phone_flow["callback"] = callback
    legacy_import_ok = phone_flow.get("import_submit_ok") if "import_submit_ok" in phone_flow else phone_flow.get("cpa_submit_ok")
    legacy_import_message = phone_flow.get("import_submit_message") if "import_submit_message" in phone_flow else phone_flow.get("cpa_submit_message")
    resolved_import_submit_ok = import_submit_ok if import_submit_ok is not None else cpa_submit_ok
    resolved_import_submit_message = import_submit_message if import_submit_message is not None else cpa_submit_message
    if resolved_import_submit_ok is not None or "import_submit_ok" not in phone_flow:
        phone_flow["import_submit_ok"] = resolved_import_submit_ok if resolved_import_submit_ok is not None else legacy_import_ok
    if resolved_import_submit_message is not None:
        phone_flow["import_submit_message"] = str(resolved_import_submit_message or "").strip()
    elif "import_submit_message" not in phone_flow and legacy_import_message is not None:
        phone_flow["import_submit_message"] = str(legacy_import_message or "").strip()
    error = dict(phone_flow.get("error") or {})
    if last_error is not None:
        error["message"] = str(last_error or "").strip()
    if error_code is not None:
        error["code"] = str(error_code or "").strip()
    if error_retryable is not None:
        error["retryable"] = bool(error_retryable)
    if recovery_action is not None:
        error["recovery_action"] = str(recovery_action or "stop").strip() or "stop"
    if not error:
        error = {"code": "", "message": "", "retryable": False, "recovery_action": "stop"}
    phone_flow["error"] = error
    normalized_stage = str(phone_flow.get("stage") or "partial").strip() or "partial"
    phone_flow["signup_verified"] = normalized_stage in _PHONE_FLOW_SIGNUP_VERIFIED_STAGES
    phone_flow["oauth_verified"] = normalized_stage in _PHONE_FLOW_OAUTH_VERIFIED_STAGES
    return phone_flow


def _snapshot_phone_flow_attempt(phone_flow: dict[str, Any], *, note: str = "") -> dict[str, Any]:
    callback = dict(phone_flow.get("callback") or {})
    error = dict(phone_flow.get("error") or {})
    return {
        "stage": str(phone_flow.get("stage") or "").strip(),
        "status": str(phone_flow.get("status") or "").strip(),
        "purpose": str(phone_flow.get("purpose") or "").strip(),
        "phone_number": str(phone_flow.get("phone_number") or "").strip(),
        "activation_id": str(phone_flow.get("activation_id") or "").strip(),
        "provider": str(phone_flow.get("provider") or "").strip(),
        "bind_email": str(phone_flow.get("bind_email") or "").strip(),
        "callback_url": str(callback.get("url") or "").strip(),
        "callback_source": str(callback.get("source") or "").strip(),
        "import_submit_ok": phone_flow.get("import_submit_ok", phone_flow.get("cpa_submit_ok")),
        "import_submit_message": str(phone_flow.get("import_submit_message", phone_flow.get("cpa_submit_message") or "") or "").strip(),
        "error_code": str(error.get("code") or "").strip(),
        "last_error": str(error.get("message") or "").strip(),
        "recovery_action": str(error.get("recovery_action") or "").strip(),
        "note": str(note or "").strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def _save_partial_hero_phone_bind_result(
    *,
    phone_flow: dict[str, Any],
    password: str,
    note: str = "",
) -> str:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / PARTIAL_HERO_PHONE_BIND_RESULT_NAME
    previous_attempts: list[dict[str, Any]] = []
    if path.exists():
        try:
            previous_payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(previous_payload, dict) and isinstance(previous_payload.get("attempts"), list):
                previous_attempts = [item for item in previous_payload.get("attempts") or [] if isinstance(item, dict)]
        except Exception:
            previous_attempts = []
    normalized_flow = _build_phone_flow_runtime(
        phone_number=str(phone_flow.get("phone_number") or "").strip(),
        activation_id=str(phone_flow.get("activation_id") or "").strip(),
        provider=str(phone_flow.get("provider") or "").strip(),
        stage=str(phone_flow.get("stage") or "partial").strip() or "partial",
        purpose=str(phone_flow.get("purpose") or "signup").strip() or "signup",
        status=str(phone_flow.get("status") or phone_flow.get("stage") or "partial").strip() or "partial",
        bind_email=str(phone_flow.get("bind_email") or "").strip(),
        callback_url=str((phone_flow.get("callback") or {}).get("url") or "").strip(),
        callback_source=str((phone_flow.get("callback") or {}).get("source") or "").strip(),
        import_submit_ok=phone_flow.get("import_submit_ok", phone_flow.get("cpa_submit_ok")),
        import_submit_message=str(phone_flow.get("import_submit_message", phone_flow.get("cpa_submit_message") or "") or "").strip(),
        last_error=str((phone_flow.get("error") or {}).get("message") or "").strip(),
        error_code=str((phone_flow.get("error") or {}).get("code") or "").strip(),
        error_retryable=bool((phone_flow.get("error") or {}).get("retryable") or False),
        recovery_action=str((phone_flow.get("error") or {}).get("recovery_action") or "stop").strip() or "stop",
    )
    callback = dict(normalized_flow.get("callback") or {})
    error = dict(normalized_flow.get("error") or {})
    attempts = (previous_attempts + [_snapshot_phone_flow_attempt(normalized_flow, note=note)])[-50:]
    payload = {
        "ok": bool(callback.get("url")),
        "status": normalized_flow.get("status"),
        "stage": normalized_flow.get("stage"),
        "provider": normalized_flow.get("provider"),
        "verification_purpose": normalized_flow.get("purpose"),
        "phone_number": normalized_flow.get("phone_number"),
        "password": str(password or "").strip(),
        "activation_id": normalized_flow.get("activation_id"),
        "email": normalized_flow.get("bind_email"),
        "callback_url": callback.get("url") or "",
        "callback_source": callback.get("source") or "",
        "import_submit_ok": normalized_flow.get("import_submit_ok"),
        "import_submit_message": normalized_flow.get("import_submit_message") or "",
        "last_error": error.get("message") or "",
        "error_code": error.get("code") or "",
        "error_retryable": bool(error.get("retryable") or False),
        "recovery_action": error.get("recovery_action") or "stop",
        "phone_flow": normalized_flow,
        "attempts": attempts,
        "attempt_count": len(attempts),
        "note": str(note or "").strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return str(path)


def submit_callback_to_cpa_management(
    cpa_url: str,
    cpa_management_key: str,
    callback_or_code: str,
    expected_state: str = "",
) -> dict[str, Any]:
    from .reauthorize import _submit_callback_to_cpa

    return _submit_callback_to_cpa(
        callback_or_code,
        cpa_url=cpa_url,
        cpa_management_key=cpa_management_key,
        expected_state=expected_state,
    )


def _submit_callback_to_cpa_with_retry(
    cpa_url: str,
    cpa_management_key: str,
    callback_or_code: str,
    *,
    expected_state: str = "",
    max_attempts: int = 3,
    retry_delay: float = 2.0,
) -> dict[str, Any]:
    attempts = max(1, int(max_attempts or 1))
    last_error = ""
    for attempt in range(1, attempts + 1):
        try:
            result = submit_callback_to_cpa_management(cpa_url, cpa_management_key, callback_or_code, expected_state)
            if isinstance(result, dict):
                result["submit_attempts"] = attempt
                return result
            return {"ok": True, "message": str(result or ""), "raw": result, "submit_attempts": attempt}
        except Exception as exc:
            last_error = str(exc)
            if attempt >= attempts:
                break
            time.sleep(max(0.0, float(retry_delay or 0.0)))
    raise RuntimeError(f"cpa_callback_submit_failed: {last_error or 'unknown'}")


def _prepare_bind_mailbox(mail_config: dict[str, Any] | None, explicit_email: str) -> tuple[str, dict[str, Any] | None]:
    bind_email = str(explicit_email or "").strip()
    if bind_email:
        cfg = mail_config if isinstance(mail_config, dict) else {}
        providers = cfg.get("providers") if isinstance(cfg, dict) else []
        provider = providers[0] if isinstance(providers, list) and providers and isinstance(providers[0], dict) else {}
        provider_type = str(provider.get("type") or "").strip()
        if not provider_type:
            return bind_email, None
        mailbox = {"provider": provider_type, "email": bind_email, "bind_email": bind_email}
        for key in (
            "base_url",
            "api_key",
            "domain",
            "admin_auth",
            "custom_auth",
            "imap_user",
            "imap_password",
            "cookies_json",
            "cookies_path",
            "host",
            "hme_label",
        ):
            value = provider.get(key)
            if value not in (None, ""):
                mailbox[key] = value
        return bind_email, mailbox
    cfg = mail_config if isinstance(mail_config, dict) else {}
    if not cfg:
        raise RuntimeError("bind_email_required")
    mailbox = mail_provider.create_mailbox(cfg, None)
    email = str(mailbox.get("email") or "").strip()
    if not email:
        raise RuntimeError("bind_email_create_failed")
    return email, mailbox


def _add_email_headers(
    registrar: PlatformRegistrar,
    referer: str,
    *,
    content_type: str = "application/json",
    include_sentinel: bool = True,
) -> dict[str, str]:
    headers = get_common_headers()
    headers["accept"] = "application/json, text/plain, */*"
    headers["accept-language"] = "zh-CN,zh;q=0.9"
    headers["referer"] = str(referer or f"{auth_base}/add-email")
    headers["oai-device-id"] = registrar.device_id
    headers.update(_make_trace_headers())
    if include_sentinel:
        try:
            headers["openai-sentinel-token"] = build_sentinel_token(registrar.session, registrar.device_id, "authorize_continue")
        except Exception:
            pass
    if content_type:
        headers["content-type"] = content_type
    else:
        headers.pop("content-type", None)
    return headers


def _submit_add_email_api(registrar: PlatformRegistrar, email_address: str, referer: str) -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    for path, payload, include_sentinel in (
        ("/api/accounts/add-email/send", {"origin_page_type": "add_email", "data": {"email": email_address}}, False),
        ("/api/accounts/add-email/send", {"origin_page_type": "add_email", "data": {"email": email_address}}, True),
        ("/api/accounts/add-email/send", {"origin_page_type": "add_email", "email": email_address}, False),
        ("/api/accounts/add-email/send", {"origin_page_type": "add_email", "email": email_address}, True),
        ("/api/accounts/add-email/send", {"email": email_address}, False),
        ("/api/accounts/add-email/send", {"email": email_address}, True),
        ("/api/accounts/add-email", {"email": email_address}, False),
        ("/api/accounts/email-otp/send", {"email": email_address}, False),
        ("/api/accounts/email-otp/send", {}, False),
    ):
        url = f"{auth_base}{path}"
        headers = _add_email_headers(registrar, referer, include_sentinel=include_sentinel)
        try:
            response, error = request_with_local_retry(
                registrar.session,
                "post",
                url,
                json=payload,
                headers=headers,
                allow_redirects=False,
                verify=False,
            )
            status = int(getattr(response, "status_code", 0) or 0) if response is not None else 0
            body = _response_json(response) if response is not None else {}
            info = {
                "ok": response is not None and 200 <= status < 300,
                "status": status,
                "json": body,
                "text": str(getattr(response, "text", "") or "")[:1000] if response is not None else "",
                "location": str(getattr(response, "headers", {}).get("Location") or "") if response is not None else "",
                "final_url": str(getattr(response, "url", url) or url) if response is not None else url,
                "attempt": path,
                "payload_keys": sorted(payload.keys()),
                "sentinel": include_sentinel,
                "error": error or "",
            }
        except Exception as exc:
            info = {
                "ok": False,
                "status": 0,
                "json": {},
                "text": "",
                "location": "",
                "final_url": url,
                "attempt": path,
                "payload_keys": sorted(payload.keys()),
                "sentinel": include_sentinel,
                "error": str(exc),
            }
        attempts.append(info)
        if info.get("ok") or extract_oauth_callback_params_from_url(str(info.get("location") or info.get("final_url") or "")):
            return {**info, "attempts": attempts}
    return {**attempts[-1], "attempts": attempts} if attempts else {"ok": False, "status": 0, "attempts": []}


def _add_email_send_attempt_summary(item: dict[str, Any]) -> str:
    attempt = str((item or {}).get("attempt") or "-")
    status = str((item or {}).get("status") or 0)
    body = (item or {}).get("json") if isinstance((item or {}).get("json"), dict) else {}
    error = body.get("error") if isinstance(body.get("error"), dict) else {}
    code = str(error.get("code") or body.get("code") or body.get("error_code") or "").strip()
    message = str(error.get("message") or body.get("message") or (item or {}).get("error") or "").strip()
    detail = code or message
    suffix = f"/{detail[:80]}" if detail else ""
    sentinel = "sentinel" if (item or {}).get("sentinel") else "browser"
    return f"{attempt}:{status}:{sentinel}{suffix}"


def _validate_add_email_code_api(registrar: PlatformRegistrar, code: str, referer: str, email_address: str = "") -> dict[str, Any]:
    attempts: list[dict[str, Any]] = []
    clean_code = str(code or "").strip()
    clean_email = str(email_address or "").strip()
    state = str((getattr(registrar, "last_authorize", {}) or {}).get("state") or "").strip()
    payloads = [
        {"code": clean_code},
        {"origin_page_type": "add_email", "code": clean_code},
        {"origin_page_type": "add_email", "data": {"code": clean_code}},
        {"origin_page_type": "email_otp_verification", "code": clean_code},
        {"origin_page_type": "email_otp_verification", "data": {"code": clean_code}},
    ]
    if clean_email:
        payloads.extend([
            {"email": clean_email, "code": clean_code},
            {"origin_page_type": "add_email", "email": clean_email, "code": clean_code},
            {"origin_page_type": "add_email", "data": {"email": clean_email, "code": clean_code}},
            {"origin_page_type": "email_otp_verification", "email": clean_email, "code": clean_code},
            {"origin_page_type": "email_otp_verification", "data": {"email": clean_email, "code": clean_code}},
        ])
    if state:
        payloads.extend([
            {"code": clean_code, "state": state},
            {"origin_page_type": "add_email", "code": clean_code, "state": state},
            {"origin_page_type": "add_email", "data": {"code": clean_code, "state": state}},
            {"origin_page_type": "email_otp_verification", "code": clean_code, "state": state},
            {"origin_page_type": "email_otp_verification", "data": {"code": clean_code, "state": state}},
        ])
        if clean_email:
            payloads.extend([
                {"email": clean_email, "code": clean_code, "state": state},
                {"origin_page_type": "add_email", "email": clean_email, "code": clean_code, "state": state},
                {"origin_page_type": "add_email", "data": {"email": clean_email, "code": clean_code, "state": state}},
                {"origin_page_type": "email_otp_verification", "email": clean_email, "code": clean_code, "state": state},
                {"origin_page_type": "email_otp_verification", "data": {"email": clean_email, "code": clean_code, "state": state}},
            ])
    seen_payloads: set[str] = set()
    unique_payloads: list[dict[str, Any]] = []
    for payload in payloads:
        key = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        if key in seen_payloads:
            continue
        seen_payloads.add(key)
        unique_payloads.append(payload)
    for path in ("/api/accounts/add-email/validate", "/api/accounts/add-email/verify", "/api/accounts/email-otp/validate"):
        for payload in unique_payloads:
            if path.startswith("/api/accounts/add-email") and clean_email and "email" not in payload and "data" not in payload:
                continue
            url = f"{auth_base}{path}"
            headers = _add_email_headers(registrar, referer)
            try:
                response, error = request_with_local_retry(
                    registrar.session,
                    "post",
                    url,
                    json=payload,
                    headers=headers,
                    allow_redirects=False,
                    verify=False,
                )
                status = int(getattr(response, "status_code", 0) or 0) if response is not None else 0
                body = _response_json(response) if response is not None else {}
                location = str(getattr(response, "headers", {}).get("Location") or "") if response is not None else ""
                final_url = str(getattr(response, "url", url) or url) if response is not None else url
                info = {
                    "ok": response is not None and (200 <= status < 300 or bool(extract_oauth_callback_params_from_url(location or final_url))),
                    "status": status,
                    "json": body,
                    "text": str(getattr(response, "text", "") or "")[:1000] if response is not None else "",
                    "location": location,
                    "final_url": final_url,
                    "error": error or "",
                    "attempt": path,
                    "payload_keys": sorted(payload.keys()),
                }
            except Exception as exc:
                info = {
                    "ok": False,
                    "status": 0,
                    "json": {},
                    "text": "",
                    "location": "",
                    "final_url": url,
                    "error": str(exc),
                    "attempt": path,
                    "payload_keys": sorted(payload.keys()),
                }
            attempts.append(info)
            if info.get("ok") and _add_email_url_indicates_completion(_continue_url_from_step(info, str(info.get("final_url") or ""))):
                return {**info, "attempts": attempts}
    return {**attempts[-1], "attempts": attempts} if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "location": "", "final_url": f"{auth_base}/api/accounts/email-otp/validate", "error": ""}


def _refresh_add_email_code_page(registrar: PlatformRegistrar, current_url: str) -> tuple[str, str]:
    state = str((getattr(registrar, "last_authorize", {}) or {}).get("state") or "").strip()
    candidates = [
        str(current_url or "").strip() or f"{auth_base}/add-email",
        f"{auth_base}/add-email?state={quote(state, safe='')}" if state else "",
        f"{auth_base}/add-email",
    ]
    seen: set[str] = set()
    for target in candidates:
        if not target or target in seen:
            continue
        seen.add(target)
        headers = get_navigate_headers()
        headers["accept"] = "application/json, text/html, */*"
        headers["referer"] = target
        headers["oai-device-id"] = registrar.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = build_sentinel_token(registrar.session, registrar.device_id, "authorize_continue")
        except Exception:
            pass
        response, _ = request_with_local_retry(
            registrar.session,
            "get",
            target,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            continue
        final_url = str(getattr(response, "url", target) or target)
        try:
            html = str(response.text or "")
        except Exception:
            html = ""
        if extract_oauth_callback_params_from_url(final_url) or _has_add_email_code_form(html):
            return final_url, html
    return "", ""


def _submit_add_email_code_form(
    registrar: PlatformRegistrar,
    *,
    page_url: str,
    page_html: str,
    fallback_action: str,
    code: str,
) -> tuple[str, str]:
    verify_action, verify_hidden, _, verify_code_name = _extract_add_email_code_form_inputs(page_html)
    if not verify_action:
        verify_action = fallback_action
    if not verify_code_name:
        verify_code_name = "code"
    verify_payload = dict(verify_hidden)
    verify_payload[verify_code_name] = code
    final_url, body = _post_form_and_follow(
        registrar,
        page_url=page_url,
        action=verify_action,
        payload=verify_payload,
    )
    resolved_url = _add_email_result_url(final_url, body)
    return resolved_url or final_url, body


def _continue_url_from_step(info: dict[str, Any], fallback: str = "") -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    for value in (
        body.get("continue_url"),
        body.get("redirect_url"),
        body.get("url"),
        page.get("continue_url"),
        page.get("redirect_url"),
        page.get("url"),
        info.get("location"),
        info.get("final_url"),
        fallback,
    ):
        raw = str(value or "").strip()
        if not raw:
            continue
        if raw.startswith("/"):
            return f"{auth_base}{raw}"
        return raw
    return ""


def _add_email_result_url(final_url: str, body_text: str = "") -> str:
    candidates = _iter_flow_url_candidates([body_text, final_url])
    for candidate in sorted(candidates, key=_flow_url_priority):
        if extract_oauth_callback_params_from_url(candidate):
            return candidate
    non_callback_candidates = [candidate for candidate in candidates if not extract_oauth_callback_params_from_url(candidate)]
    return _choose_preferred_flow_url(non_callback_candidates, fallback=final_url)


def _is_add_email_page_url(url: str) -> bool:
    try:
        path = urlparse(str(url or "")).path.rstrip("/").lower()
    except Exception:
        path = ""
    return path.endswith("/add-email")


def _add_email_url_indicates_completion(url: str) -> bool:
    raw = str(url or "").strip()
    if not raw:
        return False
    if extract_oauth_callback_params_from_url(raw):
        return True
    lowered = raw.lower()
    pending_markers = (
        "/add-email",
        "/email-verification",
        "/email-otp",
        "/api/accounts/add-email",
        "/api/accounts/email-otp",
    )
    return not any(marker in lowered for marker in pending_markers)


def _has_add_email_code_form(html_text: str) -> bool:
    text = str(html_text or "")
    if not text:
        return False
    _action, fields, _email_name, code_name = _extract_add_email_code_form_inputs(text)
    if code_name:
        return True
    return any("code" in str(key).lower() or "otp" in str(key).lower() for key in fields)


def _continue_with_optional_add_email(
    registrar: PlatformRegistrar,
    *,
    continue_url: str,
    bind_email: str = "",
    bind_email_code: str = "",
    bind_mail_config: dict[str, Any] | None = None,
) -> tuple[str, str]:
    resolved_bind_email = ""
    page_type = ""
    if continue_url:
        try:
            response, _ = request_with_local_retry(
                registrar.session,
                "get",
                continue_url,
                headers=get_navigate_headers(),
                allow_redirects=True,
                verify=False,
            )
            body = _response_json(response) if response is not None else {}
            page_type = str((body.get("page") or {}).get("type") or "").strip()
            if response is not None:
                continue_url = str(getattr(response, "url", "") or continue_url)
        except Exception:
            page_type = ""
    if page_type != "add_email" and not _is_add_email_page_url(continue_url):
        return continue_url, resolved_bind_email

    print("阶段：当前授权要求绑定邮箱")
    resolved_bind_email, mailbox = _prepare_bind_mailbox(bind_mail_config, bind_email)
    print(f"阶段：绑定邮箱地址：{resolved_bind_email}")
    add_email_page_response, add_email_page_error = request_with_local_retry(
        registrar.session,
        "get",
        continue_url,
        headers=get_navigate_headers(),
        allow_redirects=True,
        verify=False,
    )
    if add_email_page_response is None:
        raise RuntimeError(add_email_page_error or "open_add_email_page_failed")
    add_email_page_url = str(getattr(add_email_page_response, "url", "") or continue_url)
    add_email_page_html = str(getattr(add_email_page_response, "text", "") or "")
    if extract_oauth_callback_params_from_url(add_email_page_url):
        return add_email_page_url, resolved_bind_email

    action, hidden, email_name, _ = _extract_form_inputs(add_email_page_html)
    if not action:
        action = "/add-email"
    if not email_name:
        email_name = "email"
    email_form_payload = dict(hidden)
    email_form_payload[email_name] = resolved_bind_email
    if mailbox is not None:
        mailbox["_code_after_ts"] = int(time.time() * 1000)
    print(f"阶段：提交绑定邮箱表单：提交地址={action or '-'}，字段={email_name}")
    next_url, next_html = _post_form_and_follow(
        registrar,
        page_url=add_email_page_url,
        action=action,
        payload=email_form_payload,
    )
    print(f"阶段：绑定邮箱表单提交结果：地址={next_url[:160] or '-'}")
    if extract_oauth_callback_params_from_url(next_url):
        return next_url, resolved_bind_email
    api_info = _submit_add_email_api(registrar, resolved_bind_email, next_url or add_email_page_url)
    print(f"阶段：绑定邮箱验证码发送结果：状态码={api_info.get('status') or '-'}，成功={'是' if api_info.get('ok') else '否'}，方式={api_info.get('attempt') or '-'}")
    if not api_info.get("ok"):
        attempts = api_info.get("attempts") if isinstance(api_info.get("attempts"), list) else [api_info]
        summary = ",".join(
            _add_email_send_attempt_summary(item or {})
            for item in attempts
            if isinstance(item, dict)
        )
        raise RuntimeError(f"bind_email_send_failed_{api_info.get('status') or 0}:{summary}")
    api_next_url = _continue_url_from_step(api_info, "")
    if extract_oauth_callback_params_from_url(api_next_url):
        return api_next_url, resolved_bind_email
    try:
        api_next_path = urlparse(api_next_url).path.lower()
    except Exception:
        api_next_path = ""
    if api_next_url and "/api/accounts/" not in api_next_path and api_next_url != next_url:
        next_url = api_next_url
    refreshed_url, refreshed_html = _refresh_add_email_code_page(registrar, next_url or add_email_page_url)
    if refreshed_url:
        next_url = refreshed_url
        next_html = refreshed_html
        print(f"阶段：绑定邮箱验证码页面已刷新：地址={next_url[:160] or '-'}")

    code = str(bind_email_code or "").strip()
    if not code:
        if mailbox is None:
            raise RuntimeError("bind_email_code_required")
        print("阶段：等待绑定邮箱验证码")
        code = str(mail_provider.wait_for_code(bind_mail_config or {}, mailbox) or "").strip()
    if not code:
        raise RuntimeError("bind_email_code_timeout")
    print(f"阶段：已收到绑定邮箱验证码：{code}")
    if _has_add_email_code_form(next_html):
        try:
            verified_url, verified_html = _submit_add_email_code_form(
                registrar,
                page_url=next_url or add_email_page_url,
                page_html=next_html,
                fallback_action=action,
                code=code,
            )
            if _add_email_url_indicates_completion(verified_url):
                print("阶段：绑定邮箱验证码已通过")
                return verified_url, resolved_bind_email
            next_url = verified_url or next_url
            next_html = verified_html or next_html
            print(f"阶段：绑定邮箱验证码表单已提交，但当前仍未离开绑定/验证码页：地址={str(next_url or '-')[:160]}")
        except Exception as exc:
            print(f"阶段：绑定邮箱表单验证码兜底校验失败：{str(exc)[:160]}")
    validate_info = _validate_add_email_code_api(registrar, code, next_url or add_email_page_url, resolved_bind_email)
    print(
        "阶段：绑定邮箱验证码 API 校验结果："
        f"状态码={validate_info.get('status') or '-'}，成功={'是' if validate_info.get('ok') else '否'}，方式={validate_info.get('attempt') or '-'}"
    )
    if validate_info.get("ok"):
        verified_url = _continue_url_from_step(validate_info, str(validate_info.get("final_url") or next_url))
        if _add_email_url_indicates_completion(verified_url):
            print("阶段：绑定邮箱验证码已通过")
            return verified_url, resolved_bind_email
        if verified_url:
            print(f"阶段：绑定邮箱验证码 API 已接受，但当前仍未离开绑定/验证码页：地址={verified_url[:160]}")
            return verified_url, ""
    if not _has_add_email_code_form(next_html):
        attempts = validate_info.get("attempts") if isinstance(validate_info.get("attempts"), list) else [validate_info]
        summary = ",".join(
            f"{str((item or {}).get('attempt') or '-')}:{str((item or {}).get('status') or 0)}"
            for item in attempts
            if isinstance(item, dict)
        )
        print(f"阶段：绑定邮箱验证码校验失败：尝试摘要={summary or '-'}")
        raise RuntimeError(f"bind_email_validate_failed_{validate_info.get('status') or 0}:{summary}")
    verified_url, _ = _submit_add_email_code_form(
        registrar,
        page_url=next_url,
        page_html=next_html,
        fallback_action=action,
        code=code,
    )
    if _add_email_url_indicates_completion(verified_url):
        print("阶段：绑定邮箱验证码已通过")
        return verified_url, resolved_bind_email
    print(f"阶段：绑定邮箱验证码表单最终提交后仍未离开绑定/验证码页：地址={str(verified_url or '-')[:160]}")
    return verified_url, ""


def legacy_phone_login_bind_email_and_submit(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise RuntimeError("legacy_flow_removed_use_sub2api_only")


def legacy_login_and_submit(*args: Any, **kwargs: Any) -> dict[str, Any]:
    raise RuntimeError("legacy_flow_removed_use_sub2api_only")


def run_oauth_token_flow(
    config: Sub2APIOAuthFlowConfig,
    *,
    callback_or_code: str,
    phone_number: str = "",
    hero_sms_order_id: str = "",
    hero_sms_price: float | None = None,
    email_password: str = "",
    mail_provider_name: str = "",
) -> Sub2APIOAuthFlowResult:
    prepared = build_openai_oauth_authorize_url(config)
    callback_url, code = normalize_callback_url(callback_or_code, prepared.redirect_uri, prepared.state)
    result = exchange_callback_code(config, prepared, callback_or_code)
    if not result.ok:
        return Sub2APIOAuthFlowResult(
            ok=False,
            authorize_url=prepared.authorize_url,
            callback_url=callback_url,
            code=code,
            error=result.error,
            tokens=result,
        )
    payload = build_sub2api_import_payload(
        result,
        concurrency=config.concurrency,
        priority=config.priority,
        rate_multiplier=config.rate_multiplier,
        auto_pause_on_expired=config.auto_pause_on_expired,
        organization_id=config.organization_id,
        plan_type=config.plan_type,
        privacy_mode=config.privacy_mode,
        account_name=config.account_name,
    )
    archive = build_account_archive(
        prepared,
        result,
        callback_url=callback_url,
        phone_number=phone_number,
        phone_country=(config.hero_sms.country if config.hero_sms else "CO"),
        hero_sms_order_id=hero_sms_order_id,
        hero_sms_price=hero_sms_price,
        email_password=email_password,
        mail_provider_name=mail_provider_name,
        organization_id=config.organization_id,
        plan_type=config.plan_type,
    )
    export_path = save_sub2api_export(payload, config.export_name)
    archive_path = save_account_archive(archive, config.archive_name)
    saved_result = save_result(result)
    return Sub2APIOAuthFlowResult(
        ok=True,
        authorize_url=prepared.authorize_url,
        callback_url=callback_url,
        code=code,
        export_path=str(export_path),
        archive_path=str(archive_path),
        saved_result=str(saved_result),
        email=result.email,
        payload=payload,
        archive=archive,
        tokens=result,
    )


def generate_authorize_bundle(config: Sub2APIOAuthFlowConfig) -> dict[str, Any]:
    """Return a JSON-serializable authorize bundle for manual/browser-assisted OAuth."""
    prepared = build_openai_oauth_authorize_url(config)
    return asdict(prepared)
