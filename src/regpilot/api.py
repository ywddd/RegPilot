from __future__ import annotations

import json
import argparse
import math
import re
import requests
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .accounts_store import count_accounts, delete_account, delete_accounts, get_account, init_db, list_accounts, upsert_account
from .config import DATA_DIR, LOG_DIR
from . import microsoft_mail_pool
from .register_core import _decode_jwt_payload, auth_base, platform_oauth_client_id
from .reauthorize import auto_reauthorize_account_with_email_otp, finish_account_reauthorize, start_account_reauthorize
from .sms_provider_config import sms_api_key_from_values, sms_provider_from_values
from .api_tasks import (
    JOBS,
    _hero_country_lookup,
    _hero_phone_bind,
    _hero_price_lookup,
    _load_webui_config as _load_webui_config_with_defaults,
    _phone_direct,
    _run_job,
    _run_register,
    _save_webui_config as _save_webui_config_with_defaults,
)
from .webui_html import FASTAPI_INDEX_HTML


_PHONE_REUSE_POOL_CACHE: dict[str, Any] = {"mtime": None, "data": {}}


def _load_phone_reuse_pool_cached() -> dict[str, Any]:
    pool_path = DATA_DIR / "phone_reuse_pool.json"
    try:
        mtime = pool_path.stat().st_mtime if pool_path.exists() else None
        if _PHONE_REUSE_POOL_CACHE.get("mtime") == mtime:
            return _PHONE_REUSE_POOL_CACHE.get("data") if isinstance(_PHONE_REUSE_POOL_CACHE.get("data"), dict) else {}
        data = json.loads(pool_path.read_text(encoding="utf-8")) if pool_path.exists() else {}
        if not isinstance(data, dict):
            data = {}
        _PHONE_REUSE_POOL_CACHE.update({"mtime": mtime, "data": data})
        return data
    except Exception:
        return {}


class ConfigSaveRequest(BaseModel):
    section: str = "register"
    values: dict[str, Any] = Field(default_factory=dict)


class TaskRunRequest(BaseModel):
    section: str = "register"
    values: dict[str, Any] = Field(default_factory=dict)


class AccountUpsertRequest(BaseModel):
    id: str = ""
    email: str
    password: str = ""
    status: str = "active"
    source: str = "manual"
    callback_url: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    mailbox: dict[str, Any] = Field(default_factory=dict)
    notes: str = ""
    tags: list[str] = Field(default_factory=list)
    usable_for_reauth: bool = True


class AccountDeleteRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


class MicrosoftMailAccountRequest(BaseModel):
    id: str = ""
    email: str
    password: str = ""
    client_id: str = ""
    refresh_token: str = ""
    status: str = "authorized"
    used: bool = False
    alias_index: int = 0
    alias_max: int = 5
    notes: str = ""


class MicrosoftMailImportRequest(BaseModel):
    text: str = ""


class ReauthorizeRequest(BaseModel):
    account_id: str
    proxy: str = ""


class ReauthorizeFinishRequest(BaseModel):
    account_id: str
    callback_or_code: str
    code_verifier: str
    state: str = ""
    redirect_uri: str = "http://localhost:1455/auth/callback"
    client_id: str = ""
    codex2api_url: str = ""
    codex2api_admin_key: str = ""
    codex2api_proxy_url: str = ""
    proxy: str = ""


class ReauthorizeAutoRequest(BaseModel):
    account_id: str
    codex2api_url: str = ""
    codex2api_admin_key: str = ""
    codex2api_proxy_url: str = ""
    proxy: str = ""
    wait_timeout: int = 60
    wait_interval: int = 2
    request_timeout: int = 30
    sms_provider: str = ""
    sms_api_key: str = ""
    hero_sms_api_key: str = ""
    smsbower_api_key: str = ""
    fivesim_api_key: str = ""
    hero_sms_base_url: str = ""
    smsbower_base_url: str = ""
    hero_sms_country: str = ""
    hero_sms_service: str = ""
    hero_sms_min_price: float | str = 0.0
    hero_sms_max_price: float | str = 0.0
    sms_wait_timeout: int | None = None
    sms_wait_interval: int | None = None
    sms_resend_after_seconds: int | None = None
    sms_timeout_after_resend_seconds: int | None = None
    sms_release_after_seconds: int | None = None
    sms_auto_retry: bool | None = None
    sms_retry_count: int | None = None
    hero_sms_wait_timeout: int | None = None
    hero_sms_wait_interval: int | None = None
    hero_sms_resend_after_seconds: int | None = None
    hero_sms_timeout_after_resend_seconds: int | None = None
    hero_sms_release_after_seconds: int | None = None
    hero_sms_auto_retry: bool | None = None
    hero_sms_retry_count: int | None = None
    allow_phone_verification: bool = False


app = FastAPI(title="RegPilot API", version="0.1.0")


def main() -> None:
    parser = argparse.ArgumentParser(prog="regpilot-api", description="Run the RegPilot FastAPI server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    import uvicorn

    uvicorn.run("regpilot.api:app", host=args.host, port=args.port)


def _load_webui_default_proxy() -> str:
    data = _load_webui_config()
    for section in ("register", "phone_direct", "hero_phone_bind"):
        value = str(((data.get(section) or {}).get("proxy") or "")).strip()
        if value:
            return value
    return ""


def _prefer_proxy(explicit_proxy: str) -> str:
    value = str(explicit_proxy or "").strip()
    return value or _load_webui_default_proxy()


def _jwt_exp_value(payload: dict[str, Any]) -> int:
    try:
        return int((payload or {}).get("exp") or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _account_token_status(item: dict[str, Any]) -> dict[str, Any]:
    access_token = str(item.get("access_token") or "").strip()
    refresh_token = str(item.get("refresh_token") or "").strip()
    if not access_token or not refresh_token:
        mailbox = item.get("mailbox") if isinstance(item.get("mailbox"), dict) else {}
        if mailbox.get("_cpa_submit_ok") and str(item.get("callback_url") or mailbox.get("_callback_url") or "").strip():
            return {"token_status": "cpa_only", "token_status_label": "仅CPA", "token_refreshable": False}
        return {"token_status": "missing", "token_status_label": "无", "token_refreshable": False}
    access_payload = _decode_jwt_payload(access_token) or {}
    exp = _jwt_exp_value(access_payload)
    if str(item.get("last_error") or "").startswith("refresh_token_failed:"):
        return {"token_status": "reauth_required", "token_status_label": "需重新授权", "token_refreshable": False, "token_expires_at": exp}
    if exp and exp <= int(time.time()):
        return {"token_status": "access_expired", "token_status_label": "需刷新", "token_refreshable": True, "token_expires_at": exp}
    return {"token_status": "refreshable", "token_status_label": "可刷新", "token_refreshable": True, "token_expires_at": exp}


def _account_phone_status(item: dict[str, Any]) -> dict[str, Any]:
    access_payload = _decode_jwt_payload(str(item.get("access_token") or "")) or {}
    id_payload = _decode_jwt_payload(str(item.get("id_token") or "")) or {}
    profile = access_payload.get("https://api.openai.com/profile") if isinstance(access_payload.get("https://api.openai.com/profile"), dict) else {}
    phone_number = str(profile.get("phone_number") or "").strip()
    verified = bool(profile.get("phone_number_verified"))
    if phone_number and verified:
        return {"phone_status": "verified", "phone_status_label": "已绑定", "phone_number": phone_number}
    mailbox = item.get("mailbox") if isinstance(item.get("mailbox"), dict) else {}
    if str(mailbox.get("phone_number") or "").strip():
        return {"phone_status": "bound_recorded", "phone_status_label": "已绑定", "phone_number": str(mailbox.get("phone_number") or "").strip()}
    try:
        pool = _load_phone_reuse_pool_cached()
        account_id = str(item.get("id") or "").strip()
        email = str(item.get("email") or "").strip()
        for row in pool.get("items") or []:
            if not isinstance(row, dict):
                continue
            for account in row.get("accounts") or []:
                if not isinstance(account, dict):
                    continue
                if (account_id and str(account.get("account_id") or "") == account_id) or (email and str(account.get("email") or "") == email):
                    phone = str(row.get("phone_number") or "").strip()
                    if phone:
                        return {"phone_status": "bound_recorded", "phone_status_label": "已绑定", "phone_number": phone}
    except Exception:
        pass
    if str(item.get("status") or "") == "authorized" and (str(item.get("callback_url") or "").strip() or item.get("access_token") or item.get("id_token")):
        return {"phone_status": "authorized_assumed", "phone_status_label": "已绑定（授权通过）", "phone_number": ""}
    if item.get("access_token") or item.get("id_token"):
        return {"phone_status": "missing", "phone_status_label": "未绑定", "phone_number": ""}
    return {"phone_status": "unknown", "phone_status_label": "未知", "phone_number": ""}


def _configured_cloudflare_domains() -> set[str]:
    domains: set[str] = set()
    try:
        data = _load_webui_config()
    except Exception:
        data = {}
    for section_name in ("register", "phone_direct", "hero_phone_bind"):
        section = data.get(section_name) if isinstance(data, dict) else {}
        if not isinstance(section, dict):
            continue
        domain = str(section.get("cf_temp_domain") or "").strip().lower().lstrip("@")
        if domain:
            domains.add(domain)
    return domains


def _account_mail_provider_status(item: dict[str, Any]) -> dict[str, Any]:
    mailbox = item.get("mailbox") if isinstance(item.get("mailbox"), dict) else {}
    provider = str(mailbox.get("provider") or "").strip().lower().replace("_", "-")
    if provider in {"icloud-hme", "icloud"}:
        provider = "icloud"
    if provider in {"outlook-api", "microsoft-mail"}:
        provider = "hotmail-api"
    if not provider:
        mailbox_domain = str(mailbox.get("domain") or "").strip().lower().lstrip("@")
        email = str(item.get("email") or mailbox.get("email") or mailbox.get("bind_email") or "").strip().lower()
        email_domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        cloudflare_domains = _configured_cloudflare_domains()
        if mailbox_domain in cloudflare_domains or email_domain in cloudflare_domains:
            provider = "cloudflare-temp-email"
    labels = {
        "cloudflare-temp-email": "Cloudflare",
        "icloud": "iCloud",
        "hotmail-api": "Outlook/Hotmail",
    }
    return {
        "mail_provider": provider,
        "mail_provider_label": labels.get(provider, provider or "-"),
    }


def _account_with_token_status(item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    out.update(_account_token_status(item))
    out.update(_account_phone_status(item))
    out.update(_account_mail_provider_status(item))
    return out


def _safe_account_with_status(item: dict[str, Any]) -> dict[str, Any]:
    return _redact_sensitive(_account_with_token_status(item))


def _load_webui_config() -> dict[str, Any]:
    return _load_webui_config_with_defaults()


def _save_webui_config(data: dict[str, Any]) -> dict[str, Any]:
    return _save_webui_config_with_defaults(data)


def _merge_task_values(section: str, values: dict[str, Any]) -> dict[str, Any]:
    storage_section = "hero_phone_bind" if section == "phone_direct" else section
    data = _load_webui_config()
    register_cfg = data.get("register") if isinstance(data.get("register"), dict) else {}
    section_cfg = data.get(storage_section) if isinstance(data.get(storage_section), dict) else {}
    explicit = dict(values or {})
    merged: dict[str, Any] = {**register_cfg, **section_cfg}
    for key, value in explicit.items():
        if value is not None:
            merged[str(key)] = value
    if storage_section == "hero_phone_bind":
        if "sms_auto_retry" not in explicit and "hero_sms_auto_retry" not in explicit:
            merged["sms_auto_retry"] = _bool_for_values(merged, "sms_auto_retry", legacy_key="hero_sms_auto_retry")
        merged.setdefault("sms_retry_count", 3)
        merged.setdefault("sms_wait_timeout", 60)
        merged.setdefault("sms_wait_interval", 5)
        merged.setdefault("sms_resend_after_seconds", 30)
        merged.setdefault("sms_timeout_after_resend_seconds", 60)
        merged.setdefault("sms_release_after_seconds", 120)
    return merged


def _config_value(*keys: str) -> str:
    data = _load_webui_config()
    for section in ("register", "phone_direct", "hero_phone_bind"):
        values = data.get(section) if isinstance(data.get(section), dict) else {}
        for key in keys:
            value = str(values.get(key) or "").strip()
            if value:
                return value
    return ""


def _prefer_codex2api_url(explicit: str) -> str:
    return str(explicit or "").strip() or _config_value("codex2api_url")


def _prefer_codex2api_admin_key(explicit: str) -> str:
    return str(explicit or "").strip() or _config_value("codex2api_admin_key")


def _prefer_codex2api_proxy_url(explicit: str) -> str:
    return str(explicit or "").strip() or _config_value("codex2api_proxy_url")


def _prefer_reauthorize_sms_values(payload: ReauthorizeAutoRequest) -> dict[str, Any]:
    data = _load_webui_config()
    register_cfg = data.get("register") if isinstance(data.get("register"), dict) else {}
    phone_cfg = data.get("phone_direct") if isinstance(data.get("phone_direct"), dict) else {}
    if not phone_cfg:
        phone_cfg = data.get("hero_phone_bind") if isinstance(data.get("hero_phone_bind"), dict) else {}
    merged: dict[str, Any] = {**register_cfg, **phone_cfg}

    def explicit_value(key: str) -> Any:
        explicit = getattr(payload, key, None)
        if explicit not in (None, ""):
            return explicit
        return None

    def config_value(key: str) -> Any:
        value = merged.get(key)
        if value not in (None, ""):
            return value
        return None

    def pick(key: str, default: Any = "") -> Any:
        explicit = explicit_value(key)
        if explicit is not None:
            return explicit
        value = config_value(key)
        if value is not None:
            return value
        return default

    def pick_renamed(new_key: str, old_key: str, default: Any) -> Any:
        for key in (new_key, old_key):
            explicit = explicit_value(key)
            if explicit is not None:
                return explicit
        for key in (new_key, old_key):
            value = config_value(key)
            if value is not None:
                return value
        return default

    provider = _sms_provider_for_values({"sms_provider": pick("sms_provider", "hero_sms")})
    hero_key = str(pick("hero_sms_api_key", "") or "").strip()
    bower_key = str(pick("smsbower_api_key", "") or "").strip()
    fivesim_key = str(pick("fivesim_api_key", "") or "").strip()
    api_key = sms_api_key_from_values(
        {
            "sms_provider": provider,
            "sms_api_key": pick("sms_api_key", ""),
            "hero_sms_api_key": hero_key,
            "smsbower_api_key": bower_key,
            "fivesim_api_key": fivesim_key,
        },
        provider,
    )
    bounds = {
        "sms_wait_timeout": pick_renamed("sms_wait_timeout", "hero_sms_wait_timeout", 60),
        "sms_wait_interval": pick_renamed("sms_wait_interval", "hero_sms_wait_interval", 5),
        "sms_resend_after_seconds": pick_renamed("sms_resend_after_seconds", "hero_sms_resend_after_seconds", 30),
        "sms_timeout_after_resend_seconds": pick_renamed("sms_timeout_after_resend_seconds", "hero_sms_timeout_after_resend_seconds", 60),
        "sms_release_after_seconds": pick_renamed("sms_release_after_seconds", "hero_sms_release_after_seconds", 120),
        "sms_retry_count": pick_renamed("sms_retry_count", "hero_sms_retry_count", 3),
        "hero_sms_min_price": pick("hero_sms_min_price", 0.0),
        "hero_sms_max_price": pick("hero_sms_max_price", 0.0),
    }
    wait_timeout = _positive_int_for_values(bounds, "sms_wait_timeout")
    wait_interval = _positive_int_for_values(bounds, "sms_wait_interval")
    resend_after = _positive_int_for_values(bounds, "sms_resend_after_seconds")
    timeout_after_resend = _positive_int_for_values(bounds, "sms_timeout_after_resend_seconds")
    release_after = _positive_int_for_values(bounds, "sms_release_after_seconds")
    retry_count = _positive_int_for_values(bounds, "sms_retry_count")
    min_price = _optional_float_for_values(bounds, "hero_sms_min_price")
    max_price = _optional_float_for_values(bounds, "hero_sms_max_price")
    if max_price > 0 and min_price > max_price:
        raise HTTPException(status_code=400, detail="invalid_sms_price_range")
    return {
        "sms_provider": provider,
        "sms_api_key": api_key,
        "hero_sms_api_key": hero_key,
        "smsbower_api_key": bower_key,
        "fivesim_api_key": fivesim_key,
        "hero_sms_base_url": str(pick("hero_sms_base_url", "") or "").strip(),
        "smsbower_base_url": str(pick("smsbower_base_url", "") or "").strip(),
        "hero_sms_country": (
            "england"
            if provider == "5sim" and (not str(pick("hero_sms_country", "") or "").strip() or str(pick("hero_sms_country", "") or "").strip().isdigit())
            else str(pick("hero_sms_country", "16") or "16").strip()
        ),
        "hero_sms_service": (
            "openai"
            if provider == "5sim" and str(pick("hero_sms_service", "dr") or "dr").strip() in {"", "dr"}
            else str(pick("hero_sms_service", "dr") or "dr").strip()
        ),
        "hero_sms_min_price": min_price,
        "hero_sms_max_price": max_price,
        "sms_wait_timeout": wait_timeout,
        "sms_wait_interval": wait_interval,
        "sms_resend_after_seconds": resend_after,
        "sms_timeout_after_resend_seconds": timeout_after_resend,
        "sms_release_after_seconds": release_after,
        "sms_auto_retry": _bool_for_values(
            {"sms_auto_retry": pick_renamed("sms_auto_retry", "hero_sms_auto_retry", False)},
            "sms_auto_retry",
        ),
        "sms_retry_count": retry_count,
    }


def _has_any_target_import(values: dict[str, Any]) -> bool:
    has_codex2api = bool(
        _bool_for_values(values, "codex2api_auto_import")
        and str(values.get("codex2api_url") or "").strip()
        and str(values.get("codex2api_admin_key") or "").strip()
    )
    return has_codex2api


def _sms_api_key_for_values(values: dict[str, Any]) -> str:
    provider = _sms_provider_for_values(values)
    return sms_api_key_from_values(values, provider)


def _sms_provider_for_values(values: dict[str, Any]) -> str:
    try:
        return sms_provider_from_values(values)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _positive_int_for_values(values: dict[str, Any], key: str, *, legacy_key: str = "") -> int:
    raw = values.get(key)
    if raw in (None, "") and legacy_key:
        raw = values.get(legacy_key)
    if raw in (None, ""):
        return 1
    if isinstance(raw, bool):
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    if isinstance(raw, float) and not raw.is_integer():
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    if isinstance(raw, str):
        text = raw.strip()
        if not re.fullmatch(r"\d+", text):
            raise HTTPException(status_code=400, detail=f"invalid_{key}")
        raw = text
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    if value < 1:
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    return value


def _optional_float_for_values(values: dict[str, Any], key: str, *, legacy_key: str = "") -> float:
    raw = values.get(key)
    if raw in (None, ""):
        if legacy_key:
            raw = values.get(legacy_key)
            if raw in (None, ""):
                return 0.0
        else:
            return 0.0
    try:
        value = float(raw)
    except (TypeError, ValueError, OverflowError):
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    if not math.isfinite(value):
        raise HTTPException(status_code=400, detail=f"invalid_{key}")
    return value


def _bool_for_values(values: dict[str, Any], key: str, *, legacy_key: str = "") -> bool:
    raw = values.get(key)
    if raw in (None, "") and legacy_key:
        raw = values.get(legacy_key)
    if raw in (None, ""):
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    if isinstance(raw, int) and raw in (0, 1):
        return bool(raw)
    raise HTTPException(status_code=400, detail=f"invalid_{key}")


def _preflight_common_task_bounds(values: dict[str, Any]) -> None:
    _positive_int_for_values(values, "total")
    _positive_int_for_values(values, "threads")
    _positive_int_for_values(values, "request_timeout")
    _positive_int_for_values(values, "wait_timeout")
    _positive_int_for_values(values, "wait_interval")
    _bool_for_values(values, "env_random_enabled")
    _bool_for_values(values, "codex2api_auto_import")
    _bool_for_values(values, "cf_temp_use_random_subdomain")


def _preflight_phone_direct(values: dict[str, Any]) -> None:
    _preflight_common_task_bounds(values)
    _positive_int_for_values(values, "sms_wait_timeout", legacy_key="hero_sms_wait_timeout")
    _positive_int_for_values(values, "sms_wait_interval", legacy_key="hero_sms_wait_interval")
    _positive_int_for_values(values, "sms_retry_count", legacy_key="hero_sms_retry_count")
    _bool_for_values(values, "sms_auto_retry", legacy_key="hero_sms_auto_retry")
    min_price = _optional_float_for_values(values, "sms_min_price", legacy_key="hero_sms_min_price")
    max_price = _optional_float_for_values(values, "sms_max_price", legacy_key="hero_sms_max_price")
    if max_price > 0 and min_price > max_price:
        raise HTTPException(status_code=400, detail="invalid_sms_price_range")
    if not _sms_api_key_for_values(values):
        raise HTTPException(status_code=400, detail="sms_api_key_required")
    if not _has_any_target_import(values):
        raise HTTPException(status_code=400, detail="codex2api_required")


def _preflight_hero_phone_bind(values: dict[str, Any]) -> None:
    _preflight_phone_direct(values)


def _preflight_sms_lookup(values: dict[str, Any]) -> None:
    _sms_provider_for_values(values)
    _positive_int_for_values(values, "sms_wait_timeout", legacy_key="hero_sms_wait_timeout")
    _positive_int_for_values(values, "sms_wait_interval", legacy_key="hero_sms_wait_interval")
    _bool_for_values(values, "sms_auto_retry", legacy_key="hero_sms_auto_retry")
    min_price = _optional_float_for_values(values, "sms_min_price", legacy_key="hero_sms_min_price")
    max_price = _optional_float_for_values(values, "sms_max_price", legacy_key="hero_sms_max_price")
    if max_price > 0 and min_price > max_price:
        raise HTTPException(status_code=400, detail="invalid_sms_price_range")
    if not _sms_api_key_for_values(values):
        raise HTTPException(status_code=400, detail="sms_api_key_required")


def _preflight_register(values: dict[str, Any]) -> None:
    _preflight_common_task_bounds(values)
    mail_type = str(values.get("mail_type") or "cloudflare-temp-email").strip().lower()
    if mail_type not in {"cloudflare-temp-email", "icloud", "icloud-hme", "icloud_hme", "hotmail-api", "outlook-api", "microsoft-mail"}:
        raise HTTPException(status_code=400, detail="invalid_mail_type")
    if mail_type == "cloudflare-temp-email":
        if not str(values.get("cf_temp_base_url") or "").strip():
            raise HTTPException(status_code=400, detail="cf_temp_base_url_required")
        if not str(values.get("cf_temp_admin_auth") or "").strip():
            raise HTTPException(status_code=400, detail="cf_temp_admin_auth_required")
        if not str(values.get("cf_temp_domain") or "").strip():
            raise HTTPException(status_code=400, detail="cf_temp_domain_required")
        return
    if mail_type in {"icloud", "icloud-hme", "icloud_hme"}:
        has_email = bool(str(values.get("icloud_email") or "").strip())
        has_cookies = bool(str(values.get("icloud_cookies_json") or "").strip() or str(values.get("icloud_cookies_path") or "").strip())
        has_imap = bool(str(values.get("icloud_imap_user") or "").strip() and str(values.get("icloud_imap_password") or "").strip())
        if not has_email and not has_cookies:
            raise HTTPException(status_code=400, detail="icloud_email_or_cookies_required")
        if has_email and not has_imap and not has_cookies:
            raise HTTPException(status_code=400, detail="icloud_imap_or_cookies_required")
    if mail_type in {"hotmail-api", "outlook-api", "microsoft-mail"}:
        if not str(values.get("hotmail_api_base_url") or "").strip():
            raise HTTPException(status_code=400, detail="hotmail_api_base_url_required")
        if microsoft_mail_pool.count_available(alias_enabled=_bool_for_values(values, "hotmail_alias_enabled")) < 1:
            raise HTTPException(status_code=400, detail="microsoft_mail_pool_empty")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return FASTAPI_INDEX_HTML


@app.get("/api/config")
def api_config() -> dict[str, Any]:
    return {"ok": True, "path": str(DATA_DIR / "webui_config.json"), "config": _load_webui_config()}


@app.post("/api/config")
def api_save_config(payload: ConfigSaveRequest) -> dict[str, Any]:
    requested_section = str(payload.section or "register").strip() or "register"
    if requested_section not in {"register", "phone_direct", "hero_phone_bind", "logs"}:
        raise HTTPException(status_code=400, detail="invalid_config_section")
    section = "hero_phone_bind" if requested_section == "phone_direct" else requested_section
    data = _load_webui_config()
    current = data.get(section) if isinstance(data.get(section), dict) else {}
    merged = dict(current)
    for key, value in (payload.values or {}).items():
        merged[str(key)] = value
    data[section] = merged
    try:
        saved = _save_webui_config(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "path": str(DATA_DIR / "webui_config.json"), "section": requested_section, "storage_section": section, "config": saved}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "RegPilot API"}


def _safe_microsoft_mail_account(item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    if out.get("password"):
        out["password"] = "***"
    if out.get("refresh_token"):
        out["refresh_token"] = "***"
    return out


@app.get("/api/microsoft-mail/accounts")
def api_list_microsoft_mail_accounts() -> dict[str, Any]:
    items = microsoft_mail_pool.list_accounts()
    return {"ok": True, "items": [_safe_microsoft_mail_account(item) for item in items], "total": len(items)}


@app.post("/api/microsoft-mail/accounts")
def api_upsert_microsoft_mail_account(payload: MicrosoftMailAccountRequest) -> dict[str, Any]:
    item = microsoft_mail_pool.upsert_account(payload.model_dump())
    return {"ok": True, "item": _safe_microsoft_mail_account(item)}


@app.post("/api/microsoft-mail/import")
def api_import_microsoft_mail_accounts(payload: MicrosoftMailImportRequest) -> dict[str, Any]:
    return {"ok": True, **microsoft_mail_pool.import_accounts(payload.text)}


@app.post("/api/microsoft-mail/clear-used")
def api_clear_used_microsoft_mail_accounts() -> dict[str, Any]:
    return {"ok": True, "count": microsoft_mail_pool.clear_used()}


@app.delete("/api/microsoft-mail/accounts/{account_id}")
def api_delete_microsoft_mail_account(account_id: str) -> dict[str, Any]:
    ok = microsoft_mail_pool.delete_account(account_id)
    if not ok:
        raise HTTPException(status_code=404, detail="microsoft_mail_account_not_found")
    return {"ok": True, "id": account_id}


@app.get("/api/accounts")
def api_list_accounts(limit: int = 200, offset: int = 0, q: str = "") -> dict[str, Any]:
    limit = min(500, max(1, int(limit)))
    offset = max(0, int(offset))
    search = str(q or "").strip()
    return {
        "ok": True,
        "items": [_safe_account_with_status(item) for item in list_accounts(limit=limit, offset=offset, search=search)],
        "limit": limit,
        "offset": offset,
        "total": count_accounts(search=search),
        "q": search,
    }


@app.get("/api/accounts/{account_id}")
def api_get_account(account_id: str) -> dict[str, Any]:
    item = get_account(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="account_not_found")
    return {"ok": True, "item": _safe_account_with_status(item)}


def _iso_from_jwt_exp(value: Any) -> str:
    try:
        import datetime as _dt

        exp = int(value or 0)
        if exp <= 0:
            return ""
        return _dt.datetime.fromtimestamp(exp, _dt.timezone(_dt.timedelta(hours=8))).replace(microsecond=0).isoformat()
    except Exception:
        return ""


def _refresh_account_tokens(item: dict[str, Any]) -> dict[str, Any]:
    refresh_token = str(item.get("refresh_token") or "").strip()
    if not refresh_token:
        raise HTTPException(status_code=400, detail="account_has_no_refresh_token")
    proxy = _prefer_proxy("")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        response = requests.post(
            f"{auth_base}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": platform_oauth_client_id,
            },
            timeout=60,
            verify=False,
            proxies=proxies,
        )
    except requests.RequestException as exc:
        failed = dict(item)
        failed["status"] = "auth_failed"
        failed["last_error"] = "refresh_token_failed:request_failed"
        try:
            upsert_account(failed)
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=failed["last_error"]) from exc
    try:
        data = response.json()
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    if response.status_code != 200:
        message = ""
        error = data.get("error") if isinstance(data.get("error"), dict) else {}
        if isinstance(error, dict):
            message = str(error.get("code") or error.get("message") or "").strip()
        failed = dict(item)
        failed["status"] = "auth_failed"
        failed["last_error"] = f"refresh_token_failed:{message or response.status_code}"
        try:
            upsert_account(failed)
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=failed["last_error"])
    access_token = str(data.get("access_token") or "").strip()
    new_refresh_token = str(data.get("refresh_token") or refresh_token).strip()
    id_token = str(data.get("id_token") or item.get("id_token") or "").strip()
    if not access_token or not new_refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token_missing_tokens")
    updated = dict(item)
    updated["access_token"] = access_token
    updated["refresh_token"] = new_refresh_token
    updated["id_token"] = id_token
    updated["status"] = "authorized"
    updated["last_error"] = ""
    saved = upsert_account(updated)
    return saved or updated


@app.get("/api/accounts/{account_id}/export-json")
def api_export_account_json(account_id: str) -> dict[str, Any]:
    item = get_account(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="account_not_found")
    if not str(item.get("access_token") or "").strip() or not str(item.get("refresh_token") or "").strip():
        raise HTTPException(status_code=400, detail="account_has_no_local_token")
    item = _refresh_account_tokens(item)
    phone_status = _account_phone_status(item)
    if phone_status.get("phone_status") not in {"verified", "bound_recorded", "authorized_assumed"}:
        raise HTTPException(status_code=400, detail="phone_not_verified_reauthorize_after_binding_required")
    access_token = str(item.get("access_token") or "")
    id_token = str(item.get("id_token") or "")
    access_payload = _decode_jwt_payload(access_token) or {}
    id_payload = _decode_jwt_payload(id_token) or {}
    profile = access_payload.get("https://api.openai.com/profile") if isinstance(access_payload.get("https://api.openai.com/profile"), dict) else {}
    auth_claim = id_payload.get("https://api.openai.com/auth") if isinstance(id_payload.get("https://api.openai.com/auth"), dict) else {}
    orgs = auth_claim.get("organizations") if isinstance(auth_claim.get("organizations"), list) else []
    default_org = next((org for org in orgs if isinstance(org, dict) and org.get("is_default")), orgs[0] if orgs else {})
    email = str(item.get("email") or profile.get("email") or id_payload.get("email") or "")
    expired = _iso_from_jwt_exp(access_payload.get("exp"))
    payload = {
        "access_token": access_token,
        "account_id": str((item.get("mailbox") or {}).get("account_id") or default_org.get("id") or "") if isinstance(item.get("mailbox"), dict) or isinstance(default_org, dict) else "",
        "disabled": False,
        "email": email,
        "expired": expired,
        "id_token": id_token,
        "last_refresh": str(item.get("last_auth_at") or item.get("updated_at") or ""),
        "plan_type": "free",
        "refresh_token": str(item.get("refresh_token") or ""),
        "type": "codex",
    }
    safe_email = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(item.get("email") or account_id)).strip("_") or account_id
    return {"ok": True, "filename": f"cpa-{safe_email}.json", "payload": payload}


@app.post("/api/accounts")
def api_upsert_account(payload: AccountUpsertRequest) -> dict[str, Any]:
    item = upsert_account(payload.model_dump())
    return {"ok": True, "item": _safe_account_with_status(item)}


@app.post("/api/accounts/delete")
def api_delete_accounts(payload: AccountDeleteRequest) -> dict[str, Any]:
    result = delete_accounts(payload.ids)
    return {"ok": True, **result}


@app.delete("/api/accounts/{account_id}")
def api_delete_account(account_id: str) -> dict[str, Any]:
    ok = delete_account(account_id)
    if not ok:
        raise HTTPException(status_code=404, detail="account_not_found")
    return {"ok": True, "id": account_id}


@app.post("/api/tasks/register")
def api_task_register(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("register", payload.values or {})
    _preflight_register(merged)
    return _run_job("register", _run_register, merged)


@app.post("/api/tasks/hero/phone-bind")
def api_task_hero_phone_bind(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_hero_phone_bind(merged)
    return _run_job("phone_direct", _phone_direct, merged)


@app.post("/api/tasks/phone-direct")
def api_task_phone_direct(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("phone_direct", payload.values or {})
    _preflight_phone_direct(merged)
    return _run_job("phone_direct", _phone_direct, merged)


@app.post("/api/hero/countries")
def api_hero_countries(payload: TaskRunRequest) -> dict[str, Any]:
    return api_sms_countries(payload)


@app.post("/api/sms/countries")
def api_sms_countries(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_sms_lookup(merged)
    try:
        return _hero_country_lookup(merged)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/sms/price")
def api_sms_price(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_sms_lookup(merged)
    try:
        return _hero_price_lookup(merged)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            lk = str(key).lower()
            if (
                lk in {"token", "access_token", "refresh_token", "id_token"}
                or (lk.endswith("_token") and not lk.startswith("has_"))
                or "password" in lk
                or "cookie" in lk
                or "secret" in lk
                or "api_key" in lk
                or lk.endswith("_auth")
                or lk.endswith("_key")
                or lk in {"key", "admin_auth", "custom_auth", "access_token", "refresh_token", "id_token"}
            ):
                out[key] = "***" if item else ""
            else:
                out[key] = _redact_sensitive(item)
        return out
    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]
    if isinstance(value, str):
        return _redact_sensitive_text(value)
    return value


def _redact_sensitive_text(value: str) -> str:
    text = str(value or "")
    patterns = [
        (r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;&)}]+", r"\1[hidden]"),
        (r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{12,}", "Bearer [hidden]"),
        (r"(?i)(api[_-]?key|sms[_-]?api[_-]?key|hero[_-]?sms[_-]?api[_-]?key|smsbower[_-]?api[_-]?key|mail[_-]?api[_-]?key)(\s*[=:]\s*)[^\s,;&)}]+", r"\1\2[hidden]"),
        (r"(?i)(password|cookie|cookies|admin[_-]?auth|custom[_-]?auth|admin[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)(\s*[=:]\s*)[^\s,;&)}]+", r"\1\2[hidden]"),
        (r'(?i)("(?:api[_-]?key|sms[_-]?api[_-]?key|hero[_-]?sms[_-]?api[_-]?key|smsbower[_-]?api[_-]?key|mail[_-]?api[_-]?key|password|cookie|cookies|admin[_-]?auth|custom[_-]?auth|admin[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token)"\s*:\s*")[^"]*(")', r"\1[hidden]\2"),
    ]
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text


def _strip_visible_debug_output(output: str) -> str:
    lines: list[str] = []
    for line in str(output or "").splitlines():
        if line.startswith("Flow debug summary:") or line.startswith("Flow debug encode failed:"):
            continue
        lines.append(_redact_sensitive_text(line))
    return "\n".join(lines)


def _zh_job_message(message: Any) -> str:
    text = str(message or "").strip()
    exact = {
        "CPA callback submitted": "CPA 回调已提交",
        "missing_callback_after_auth": "授权完成后未拿到 OAuth 回调",
        "missing_callback_after_phone_verification": "手机二次验证后未拿到 OAuth 回调",
        "phone_verification_required_sms_key_missing": "需要手机二次验证，但未配置接码服务",
        "manual_phone_verification_required": "无法自动授权：需要人工完成手机二次验证",
        "wait_for_code_timeout": "等待邮箱验证码超时",
        "job_stopped_by_user": "任务已被手动停止",
        "session_establishment_failed": "登录会话建立失败",
    }
    if text in exact:
        return exact[text]
    text = re.sub(r"login_password_(\d+)", r"密码登录失败（状态码=\1）", text)
    text = text.replace("account_not_created_registration_disallowed", "账号未创建：about-you 被上游拒绝")
    text = re.sub(r"send_otp_(\d+)", r"发送邮箱验证码失败（状态码=\1）", text)
    text = re.sub(r"validate_otp_(\d+)", r"邮箱验证码校验失败（状态码=\1）", text)
    text = text.replace("phone_verification_after_email_otp_failed", "邮箱验证码后手机二次验证失败")
    text = text.replace("phone_verification_after_password_failed", "密码登录后手机二次验证失败")
    text = text.replace("phone_verification_after_bind_email_failed", "绑定邮箱后手机二次验证失败")
    text = text.replace("email_otp_fallback_failed", "邮箱验证码兜底登录失败")
    return text or "-"


def _safe_job(job: dict[str, Any]) -> dict[str, Any]:
    safe = _redact_sensitive(job)
    if isinstance(safe, dict) and "output" in safe:
        safe["output"] = _strip_visible_debug_output(str(safe.get("output") or ""))
    error = safe.get("error") if isinstance(safe, dict) else None
    if isinstance(error, dict) and "traceback" in error:
        error["traceback"] = "[hidden; see server logs]"
    return safe


@app.get("/api/jobs")
def api_jobs() -> dict[str, Any]:
    return {"ok": True, "items": [_safe_job(job) for job in JOBS.list()]}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str) -> dict[str, Any]:
    for job in JOBS.list():
        if job.get("id") == job_id:
            return {"ok": True, "item": _safe_job(job)}
    raise HTTPException(status_code=404, detail="job_not_found")


@app.post("/api/jobs/{job_id}/stop")
def api_job_stop(job_id: str) -> dict[str, Any]:
    try:
        result = JOBS.request_stop(job_id)
    except ValueError as exc:
        if str(exc) == "job_not_found":
            raise HTTPException(status_code=404, detail="job_not_found")
        raise
    return {"ok": True, **result}


@app.post("/api/accounts/reauthorize")
def api_reauthorize(payload: ReauthorizeRequest) -> dict[str, Any]:
    outcome = start_account_reauthorize(payload.account_id, proxy=_prefer_proxy(payload.proxy))
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "authorize_url": outcome.authorize_url,
        "state": outcome.state,
        "nonce": outcome.nonce,
        "redirect_uri": outcome.redirect_uri,
        "client_id": outcome.client_id,
        "code_verifier": outcome.code_verifier,
        "bind_email": outcome.bind_email,
    }


@app.post("/api/accounts/reauthorize/finish")
def api_reauthorize_finish(payload: ReauthorizeFinishRequest) -> dict[str, Any]:
    outcome = finish_account_reauthorize(
        payload.account_id,
        callback_or_code=payload.callback_or_code,
        code_verifier=payload.code_verifier,
        state=payload.state,
        redirect_uri=payload.redirect_uri,
        client_id=payload.client_id,
        codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
        codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
        codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
        proxy=_prefer_proxy(payload.proxy),
    )
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "callback_url": outcome.callback_url,
        "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
        "cpa_import_submit_message": outcome.codex2api_import_submit_message,
        "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
        "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
    }


def _reauthorize_account_log_line(account_id: str) -> str:
    account = get_account(account_id) or {}
    account_email = str(account.get("email") or "").strip()
    if account_email:
        return f"阶段：账号：{account_email}（ID：{account_id}）"
    return f"阶段：账号ID：{account_id}"


@app.post("/api/accounts/reauthorize/auto/job")
def api_reauthorize_auto_job(payload: ReauthorizeAutoRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)

    def run() -> dict[str, Any]:
        print("阶段：开始重新授权")
        print(_reauthorize_account_log_line(payload.account_id))
        print(f"阶段：CPA 地址：{_prefer_codex2api_url(payload.codex2api_url)}")
        outcome = auto_reauthorize_account_with_email_otp(
            payload.account_id,
            codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
            codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
            codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
            proxy=_prefer_proxy(payload.proxy),
            wait_timeout=payload.wait_timeout,
            wait_interval=payload.wait_interval,
            request_timeout=payload.request_timeout,
            allow_phone_verification=bool(payload.allow_phone_verification),
            **sms_values,
        )
        print(f"阶段：重新授权任务结束：{_zh_job_message(outcome.message)}")
        if outcome.debug:
            try:
                slim = {k: v for k, v in outcome.debug.items() if k in {"validate_otp_summary", "resume_probe", "callback_summary", "codex2api_oauth", "cpa_oauth", "consent_direct_summary", "phone_verification_after_password_summary", "phone_verification_after_email_otp_summary", "phone_verification_after_pre_password_email_otp_summary"}}
                if slim:
                    print("阶段：调试摘要已生成，敏感字段已隐藏")
            except Exception as exc:
                print(f"阶段：调试摘要生成失败：{exc}")
        return {
            "ok": outcome.ok,
            "message": outcome.message,
            "item": outcome.account,
            "callback_url": outcome.callback_url,
            "code": outcome.code,
            "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
            "cpa_import_submit_message": outcome.codex2api_import_submit_message,
            "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
            "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
        }
    return _run_job("reauthorize", run)


@app.post("/api/accounts/reauthorize/auto")
def api_reauthorize_auto(payload: ReauthorizeAutoRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)
    outcome = auto_reauthorize_account_with_email_otp(
        payload.account_id,
        codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
        codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
        codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
        proxy=_prefer_proxy(payload.proxy),
        wait_timeout=payload.wait_timeout,
        wait_interval=payload.wait_interval,
        request_timeout=payload.request_timeout,
        allow_phone_verification=bool(payload.allow_phone_verification),
        **sms_values,
    )
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "callback_url": outcome.callback_url,
        "code": outcome.code,
        "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
        "cpa_import_submit_message": outcome.codex2api_import_submit_message,
        "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
        "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
        "debug": outcome.debug,
    }


if __name__ == "__main__":
    main()
