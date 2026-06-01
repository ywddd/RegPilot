from __future__ import annotations

import time
import re
import json
import requests
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .accounts_store import get_account, save_registration_result_to_account, upsert_account
from .config import DATA_DIR, MailConfig, RegisterConfig
from .register_core import PlatformRegistrar, RegistrationResult, auth_base, wait_for_code, _response_json, extract_oauth_callback_params_from_consent_session, get_common_headers, _make_trace_headers, _registration_state_from_info, _decode_jwt_payload, build_sentinel_token, _random_name, _random_birthdate, _about_you_shape_log_summary, _accounts_error_code
from .oauth_token_flow import (
    HeroSMSConfig,
    SMSBOWER_BASE_URL,
    FIVESIM_BASE_URL,
    Sub2APIOAuthFlowConfig,
    acquire_hero_sms_phone,
    build_openai_oauth_authorize_url,
    exchange_callback_code,
    poll_hero_sms_code,
    set_hero_sms_status,
    _request_codex2api_json,
    _normalize_sub2api_origin,
    _normalize_sms_provider,
    extract_oauth_callback_params_from_url,
    _resolve_oauth_callback,
    _continue_with_optional_add_email,
    _load_continue_page,
    _prepare_bind_mailbox,
    _submit_about_you_form,
    _extract_form_inputs,
    _post_form_and_follow,
)


PHONE_REUSE_LIMIT = 3
PHONE_REUSE_POOL_NAME = "phone_reuse_pool.json"


@dataclass
class ReauthorizeStartOutcome:
    ok: bool
    message: str = ""
    account: dict[str, Any] | None = None
    authorize_url: str = ""
    state: str = ""
    nonce: str = ""
    redirect_uri: str = ""
    client_id: str = ""
    code_verifier: str = ""
    bind_email: str = ""


@dataclass
class ReauthorizeFinishOutcome:
    ok: bool
    message: str = ""
    account: dict[str, Any] | None = None
    callback_url: str = ""
    codex2api_import_submit_ok: bool = False
    codex2api_import_submit_message: str = ""


def _har_browser_fetch_headers(referer_path: str, *, accept: str = "application/json", content_type: str = "application/json") -> dict[str, str]:
    referer = referer_path if referer_path.startswith("http") else f"{auth_base}{referer_path}"
    headers = get_common_headers()
    headers["accept"] = accept
    headers["accept-language"] = "zh-CN,zh;q=0.9"
    headers["referer"] = referer
    headers["sec-ch-ua"] = '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"'
    headers.update(_make_trace_headers())
    if content_type:
        headers["content-type"] = content_type
    else:
        headers.pop("content-type", None)
    return headers


@dataclass
class ReauthorizeAutoOutcome:
    ok: bool
    message: str = ""
    account: dict[str, Any] | None = None
    callback_url: str = ""
    code: str = ""
    codex2api_import_submit_ok: bool = False
    codex2api_import_submit_message: str = ""
    debug: dict[str, Any] | None = None


def _zh_bool(value: Any) -> str:
    return "是" if bool(value) else "否"


def _ready_text(value: Any) -> str:
    return "已拿到" if bool(value) else "未拿到"


def _proxy_text(value: Any) -> str:
    text = str(value or "").strip()
    return text or "直连"


def _log_stage(message: str) -> None:
    print(f"阶段：{message}")


def _short_url(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit] or "-"


def _response_brief(info: dict[str, Any], *, include_final: bool = True) -> str:
    parts = [
        f"状态码={info.get('status') if info.get('status') not in (None, '') else '-'}",
        f"成功={_zh_bool(info.get('ok'))}",
    ]
    page = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = page.get("page") if isinstance(page.get("page"), dict) else {}
    page_type = str(page.get("type") or info.get("page_type") or "").strip()
    if page_type:
        parts.append(f"页面类型={page_type}")
    if include_final:
        parts.append(f"最终地址={_short_url(info.get('final_url'))}")
    return "，".join(parts)


def _phone_verification_page_brief(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    page_type = str(page.get("type") or body.get("page_type") or info.get("page_type") or "").strip() or "-"
    continue_url = _first_step_continue_url(info) or "-"
    final_url = str(info.get("final_url") or "").strip() or "-"
    return f"页面类型={page_type}，继续地址={_short_url(continue_url)}，最终地址={_short_url(final_url)}"


def _log_phone_required_after_email_otp(info: dict[str, Any], source: str) -> None:
    _log_stage(f"{source}：邮箱验证码已通过，OpenAI 要求继续手机二次验证")
    _log_stage(f"手机二次验证页面：{_phone_verification_page_brief(info)}")


def _log_phone_verification_not_configured(info: dict[str, Any]) -> None:
    _log_stage(f"需要手机二次验证，但未配置接码服务或未允许手机验证：{_phone_verification_page_brief(info)}")


def _fail_manual_phone_verification_required(
    account: dict[str, Any],
    mailbox: dict[str, Any],
    debug: dict[str, Any],
    info: dict[str, Any],
    *,
    code: str = "",
) -> ReauthorizeAutoOutcome:
    message = "manual_phone_verification_required"
    debug["manual_phone_verification_required"] = {
        "page": _phone_verification_page_brief(info),
        "reason": "OpenAI 要求账号原手机号二次验证，重新授权不再使用接码服务自动处理",
    }
    _log_stage("无法继续自动授权：OpenAI 要求手机二次验证，需要人工使用账号原手机号完成验证")
    _log_stage(f"手机二次验证页面：{_phone_verification_page_brief(info)}")
    updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
    return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, code=code, debug=debug)


def _submit_callback_to_cpa(
    callback_or_code: str,
    *,
    cpa_url: str,
    cpa_management_key: str,
    expected_state: str = "",
) -> dict[str, Any]:
    params = extract_oauth_callback_params_from_url(callback_or_code) or {}
    code = str(params.get("code") or "").strip()
    state = str(params.get("state") or expected_state or "").strip()
    if not code:
        raise RuntimeError("cpa_callback_code_missing")
    if expected_state and state and state != expected_state:
        raise RuntimeError("cpa_callback_state_mismatch")
    origin = _normalize_sub2api_origin(cpa_url)
    if not origin:
        raise ValueError("invalid_cpa_url")
    management_key = str(cpa_management_key or "").strip()
    if not management_key:
        raise RuntimeError("cpa_management_key_missing")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {management_key}",
        "X-Management-Key": management_key,
    }
    response = requests.post(
        f"{origin}/v0/management/oauth-callback",
        headers=headers,
        json={"provider": "codex", "redirect_url": str(callback_or_code or "").strip()},
        timeout=60,
        verify=False,
    )
    try:
        data = response.json()
    except Exception:
        data = {}
    if response.status_code >= 400:
        detail = ""
        if isinstance(data, dict):
            detail = str(data.get("message") or data.get("detail") or data.get("error") or data.get("reason") or "").strip()
        raise RuntimeError(detail or f"cpa_oauth_callback_http_{response.status_code}")
    message = ""
    if isinstance(data, dict):
        message = str(data.get("message") or data.get("status_message") or data.get("detail") or "").strip()
    return {"ok": True, "message": message or "CPA callback submitted", "raw": data}


def _exchange_callback_with_codex2api(
    callback_or_code: str,
    *,
    codex2api_url: str,
    codex2api_admin_key: str,
    session_id: str,
    expected_state: str = "",
) -> dict[str, Any]:
    params = extract_oauth_callback_params_from_url(callback_or_code) or {}
    code = str(params.get("code") or "").strip()
    state = str(params.get("state") or expected_state or "").strip()
    if not code:
        raise RuntimeError("codex2api_callback_code_missing")
    data = _request_codex2api_json(
        codex2api_url,
        path="/api/admin/oauth/exchange-code",
        admin_key=codex2api_admin_key,
        method="POST",
        body={"session_id": session_id, "code": code, "state": state},
        timeout=60,
    )
    return {"ok": True, "message": str((data or {}).get("message") or "Codex2API OAuth 账号添加成功"), "raw": data}


def _start_cpa_oauth(
    *,
    cpa_url: str,
    cpa_management_key: str,
    email: str = "",
    proxy_url: str = "",
) -> dict[str, str]:
    origin = _normalize_sub2api_origin(cpa_url)
    if not origin:
        raise ValueError("invalid_cpa_url")
    management_key = str(cpa_management_key or "").strip()
    if not management_key:
        raise RuntimeError("cpa_management_key_missing")
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {management_key}",
        "X-Management-Key": management_key,
    }
    proxies = {"http": proxy_url, "https": proxy_url} if str(proxy_url or "").strip() else None
    response = requests.get(
        f"{origin}/v0/management/codex-auth-url",
        headers=headers,
        timeout=60,
        verify=False,
        proxies=proxies,
    )
    try:
        data = response.json()
    except Exception:
        data = {}
    if response.status_code >= 400:
        detail = ""
        if isinstance(data, dict):
            detail = str(data.get("message") or data.get("detail") or data.get("error") or data.get("reason") or "").strip()
        raise RuntimeError(detail or f"cpa_codex_auth_url_http_{response.status_code}")
    if not isinstance(data, dict):
        data = {}
    auth_url = str(
        data.get("url")
        or data.get("auth_url")
        or data.get("authUrl")
        or ((data.get("data") or {}).get("url") if isinstance(data.get("data"), dict) else "")
        or ((data.get("data") or {}).get("auth_url") if isinstance(data.get("data"), dict) else "")
        or ((data.get("data") or {}).get("authUrl") if isinstance(data.get("data"), dict) else "")
        or ""
    ).strip()
    if not auth_url.startswith("http"):
        raise RuntimeError("cpa_auth_url_missing")
    parsed = urlparse(auth_url)
    query = parse_qs(parsed.query)
    state = str(
        data.get("state")
        or data.get("auth_state")
        or data.get("authState")
        or ((data.get("data") or {}).get("state") if isinstance(data.get("data"), dict) else "")
        or ((data.get("data") or {}).get("auth_state") if isinstance(data.get("data"), dict) else "")
        or ((data.get("data") or {}).get("authState") if isinstance(data.get("data"), dict) else "")
        or (query.get("state") or [""])[0]
        or ""
    ).strip()
    return {
        "authorize_url": auth_url,
        "session_id": "",
        "state": state,
        "client_id": str((query.get("client_id") or [""])[0] or ""),
        "redirect_uri": str((query.get("redirect_uri") or [""])[0] or "http://localhost:1455/auth/callback"),
        "cpa_management_origin": origin,
        "email": str(email or "").strip(),
    }


def _start_codex2api_oauth(
    *,
    codex2api_url: str,
    codex2api_admin_key: str,
    email: str,
    proxy_url: str = "",
) -> dict[str, str]:
    body: dict[str, Any] = {"email": email, "login_hint": email}
    if str(proxy_url or "").strip():
        body["proxy_url"] = str(proxy_url).strip()
    data = _request_codex2api_json(
        codex2api_url,
        path="/api/admin/oauth/generate-auth-url",
        admin_key=codex2api_admin_key,
        method="POST",
        body=body,
        timeout=30,
    )
    auth_url = str((data or {}).get("auth_url") or "").strip()
    session_id = str((data or {}).get("session_id") or "").strip()
    if not auth_url or not session_id:
        raise RuntimeError("codex2api_oauth_generate_failed")
    parsed = urlparse(auth_url)
    q = parse_qs(parsed.query)
    return {
        "authorize_url": auth_url,
        "session_id": session_id,
        "state": str((q.get("state") or [""])[-1] or ""),
        "client_id": str((q.get("client_id") or [""])[-1] or ""),
        "redirect_uri": str((q.get("redirect_uri") or [""])[-1] or "http://localhost:1455/auth/callback"),
    }


def _merge_url_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is not None:
            query[key] = [str(value)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query, doseq=True), parsed.fragment))


def _first_callbackish_url(*values: Any) -> str:
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        parsed = urlparse(raw)
        if parse_qs(parsed.query).get("code"):
            return raw
        if raw.startswith(("http://", "https://")) and any(token in raw for token in ("/authorize/continue", "/consent", "/oauth/", "/auth/callback")):
            return raw
    return ""


def _is_consent_like_url(value: Any) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return False
    return any(token in raw for token in ("/authorize/continue", "/authorize/resume", "/consent", "/oauth/"))


def _extract_callback_from_step(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    authorize = info.get("authorize") if isinstance(info.get("authorize"), dict) else {}
    attempts = info.get("attempts") if isinstance(info.get("attempts"), list) else []
    candidate_values: list[Any] = [
        body.get("continue_url"),
        body.get("redirect_url"),
        body.get("url"),
        body.get("callback_url"),
        body.get("return_to"),
        page.get("continue_url"),
        page.get("redirect_url"),
        page.get("url"),
        page.get("callback_url"),
        page.get("return_to"),
        info.get("location"),
        info.get("final_url"),
        authorize.get("continue_url"),
        authorize.get("redirect_url"),
        authorize.get("final_url"),
    ]
    for attempt in attempts:
        if not isinstance(attempt, dict):
            continue
        attempt_body = attempt.get("json") if isinstance(attempt.get("json"), dict) else {}
        candidate_values.extend([
            attempt_body.get("continue_url"),
            attempt_body.get("redirect_url"),
            attempt_body.get("url"),
            attempt_body.get("callback_url"),
            attempt.get("location"),
            attempt.get("final_url"),
        ])
    return _first_callbackish_url(*candidate_values)


def _resolve_callback_step(registrar: PlatformRegistrar, info: dict[str, Any], state: str, *, allow_state_resume: bool = True) -> str:
    candidate = _extract_callback_from_step(info)
    if candidate and extract_oauth_callback_params_from_url(candidate):
        return candidate
    if not allow_state_resume:
        return ""
    try:
        resolved = _resolve_oauth_callback(registrar, candidate or "", state if allow_state_resume else "")
    except Exception:
        resolved = ""
    resolved = str(resolved or "").strip()
    if resolved and extract_oauth_callback_params_from_url(resolved):
        return resolved
    return ""


def _continue_with_optional_about_you(
    registrar: PlatformRegistrar,
    continue_url: str,
    state: str,
    bind_email: str = "",
) -> tuple[str, dict[str, Any]]:
    target = str(continue_url or "").strip() or f"{auth_base}/about-you"
    debug: dict[str, Any] = {"target": target}
    probe = _load_continue_page(registrar, target)
    debug["probe"] = _safe_response_summary(
        {
            "ok": bool(probe.get("ok", True)),
            "status": probe.get("status"),
            "json": probe.get("json") if isinstance(probe.get("json"), dict) else {},
            "text": str(probe.get("text") or "")[:2000],
            "location": probe.get("location") or "",
            "final_url": probe.get("continue_url") or target,
        }
    )
    callback = str(probe.get("callback_url") or "").strip()
    if callback and extract_oauth_callback_params_from_url(callback):
        return callback, debug
    page_url = str(probe.get("continue_url") or target).strip()
    page_html = str(probe.get("text") or "")
    state_info = _registration_state_from_info(
        {
            "json": probe.get("json") if isinstance(probe.get("json"), dict) else {},
            "text": page_html,
            "location": probe.get("location") or "",
            "final_url": page_url,
        }
    )
    debug["state"] = state_info
    if str(state_info.get("kind") or "") != "about_you":
        return "", debug

    first_name, last_name = _random_name()
    full_name = f"{first_name} {last_name}"
    birthdate = _random_birthdate()
    _log_stage(f"about-you 页面识别：{_about_you_shape_log_summary(page_html)}")
    _log_stage("提交 about-you 姓名/生日")
    create_kwargs = {"referer": page_url, "page_context": page_html}
    if bind_email:
        create_kwargs["email"] = bind_email
    create_info = registrar.create_account(full_name, birthdate, **create_kwargs)
    debug["create_account"] = _safe_response_summary(create_info)
    payload_attempts = create_info.get("payload_attempts") or []
    if payload_attempts:
        attempt_summary = ", ".join(
            (
                f"{'+'.join(str(key) for key in (attempt.get('keys') or []) if key != 'name') or 'name'}:"
                f"{attempt.get('status')}"
                f"{('/' + str(attempt.get('error_code'))) if attempt.get('error_code') else ''}"
            )
            for attempt in payload_attempts[:6]
        )
        _log_stage(f"about-you 创建账号接口尝试：{attempt_summary}")
    _log_stage(
        "about-you 创建账号请求："
        f"状态码={create_info.get('status') or '-'}，成功={_zh_bool(create_info.get('ok'))}，"
        f"跳转地址={_short_url(create_info.get('location'))}，最终地址={_short_url(create_info.get('final_url'))}"
    )
    if not create_info.get("ok"):
        error_code = _accounts_error_code(create_info)
        debug["create_account_error_code"] = error_code
        if error_code == "registration_disallowed":
            raise RuntimeError("registration_disallowed")
        if error_code == "missing_email":
            _log_stage("about-you 返回 missing_email，需要先绑定邮箱")
            try:
                submitted_url, submitted_html = _submit_about_you_form(
                    registrar,
                    page_url=page_url,
                    page_html=page_html or str(create_info.get("text") or ""),
                    full_name=full_name,
                    birthdate=birthdate,
                )
                submitted_state = _registration_state_from_info({"final_url": str(submitted_url or ""), "json": {}, "text": str(submitted_html or "")})
                debug["missing_email_form_submit"] = {
                    "url": str(submitted_url or ""),
                    "kind": str(submitted_state.get("kind") or ""),
                    "html_len": len(str(submitted_html or "")),
                }
                if extract_oauth_callback_params_from_url(str(submitted_url or "")):
                    return str(submitted_url), debug
                if str(submitted_state.get("kind") or "") == "add_email":
                    debug["missing_email_continue_url"] = str(submitted_url or "")
                    _log_stage(f"about-you 已切换到绑定邮箱页：地址={_short_url(submitted_url)}")
            except Exception as exc:
                debug["missing_email_form_submit_error"] = str(exc)
                _log_stage(f"about-you 缺少邮箱时切换绑定邮箱页失败：{exc}")
            return "", debug
        try:
            submitted_url, submitted_html = _submit_about_you_form(
                registrar,
                page_url=page_url,
                page_html=page_html or str(create_info.get("text") or ""),
                full_name=full_name,
                birthdate=birthdate,
            )
            debug["form_submit"] = {"url": str(submitted_url or ""), "html_len": len(str(submitted_html or ""))}
            if submitted_url:
                create_info = {
                    **create_info,
                    "ok": "/about-you" not in str(submitted_url).lower(),
                    "location": str(submitted_url),
                    "final_url": str(submitted_url),
                }
                _log_stage(f"about-you 页面表单提交结果：最终地址={_short_url(submitted_url)}")
        except Exception as exc:
            debug["form_submit_error"] = str(exc)
            _log_stage(f"about-you 页面表单提交失败：{exc}")
    callback_target = str(
        ((create_info.get("json") or {}).get("continue_url") if isinstance(create_info.get("json"), dict) else "")
        or create_info.get("location")
        or create_info.get("final_url")
        or page_url
    ).strip()
    callback = _resolve_callback_step(registrar, create_info, state, allow_state_resume=True)
    if not callback and callback_target:
        callback = _resolve_oauth_callback(registrar, callback_target, state)
    debug["callback_ready"] = bool(callback)
    debug["callback_target"] = callback_target[:160]
    debug["next_url"] = callback_target[:300]
    return callback, debug


def _normalize_mail_provider_name(value: Any) -> str:
    raw = str(value or "").strip().lower().replace("_", "-")
    if raw in {"icloud", "icloud-hme"}:
        return "icloud"
    if raw in {"cloudflare-temp-email", "cloudflare-temp", "cloudflare"}:
        return "cloudflare-temp-email"
    if raw in {"hotmail-api", "outlook-api", "microsoft-mail", "hotmail", "outlook"}:
        return "hotmail-api"
    return raw


def _first_text(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""


def _load_webui_mail_defaults(provider_name: str) -> dict[str, Any]:
    provider_name = _normalize_mail_provider_name(provider_name)
    path = DATA_DIR / "webui_config.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        return {}
    for section_name in ("register", "phone_direct", "hero_phone_bind"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        mail_type = _normalize_mail_provider_name(section.get("mail_type") or "")
        if mail_type and mail_type != provider_name:
            continue
        if provider_name == "cloudflare-temp-email":
            return {
                "type": "cloudflare-temp-email",
                "base_url": _first_text(section.get("cf_temp_base_url")),
                "admin_auth": _first_text(section.get("cf_temp_admin_auth")),
                "custom_auth": _first_text(section.get("cf_temp_custom_auth")),
                "domain": _first_text(section.get("cf_temp_domain")),
            }
        if provider_name == "icloud":
            return {
                "type": "icloud",
                "email": _first_text(section.get("icloud_email")),
                "imap_user": _first_text(section.get("icloud_imap_user")),
                "imap_password": _first_text(section.get("icloud_imap_password")),
                "cookies_json": _first_text(section.get("icloud_cookies_json")),
                "cookies_path": _first_text(section.get("icloud_cookies_path")),
                "host": _first_text(section.get("icloud_host"), "icloud.com"),
                "hme_label": _first_text(section.get("icloud_hme_label"), "RegPilot"),
            }
        if provider_name == "hotmail-api":
            return {
                "type": "hotmail-api",
                "base_url": _first_text(section.get("hotmail_api_base_url"), "http://127.0.0.1:17373"),
                "alias_enabled": bool(section.get("hotmail_alias_enabled", True)),
                "alias_max_per_account": section.get("hotmail_alias_max_per_account") or 5,
                "mailboxes": _first_text(section.get("hotmail_mailboxes"), "INBOX,Junk"),
                "sender_filters": _first_text(section.get("hotmail_sender_filters"), "openai,noreply,no-reply"),
                "subject_filters": _first_text(section.get("hotmail_subject_filters"), "code,verification,验证码"),
                "required_keywords": _first_text(section.get("hotmail_required_keywords")),
            }
    return {"type": provider_name} if provider_name else {}


def _load_webui_cloudflare_fallback_provider() -> dict[str, Any]:
    path = DATA_DIR / "webui_config.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:
        data = {}
    if not isinstance(data, dict):
        return {}
    for section_name in ("register", "phone_direct", "hero_phone_bind"):
        section = data.get(section_name)
        if not isinstance(section, dict):
            continue
        provider = {
            "type": "cloudflare-temp-email",
            "base_url": _first_text(section.get("cf_temp_base_url")),
            "admin_auth": _first_text(section.get("cf_temp_admin_auth")),
            "custom_auth": _first_text(section.get("cf_temp_custom_auth")),
            "domain": _first_text(section.get("cf_temp_domain")),
        }
        if provider["base_url"] and provider["admin_auth"] and provider["domain"]:
            return provider
    return {}


def _mailbox_mail_provider_config(account: dict[str, Any], mailbox: dict[str, Any]) -> dict[str, Any]:
    provider_name = _normalize_mail_provider_name(mailbox.get("provider"))
    if not provider_name:
        return {}
    provider = dict(_load_webui_mail_defaults(provider_name))
    provider["type"] = provider_name
    for key in (
        "email",
        "address",
        "alias",
        "login",
        "domain",
        "account_id",
        "temp_token",
        "base_url",
        "api_key",
        "admin_auth",
        "custom_auth",
        "imap_user",
        "imap_password",
        "cookies_json",
        "cookies_path",
        "host",
        "hme_label",
        "alias_source",
        "base_email",
        "client_id",
        "refresh_token",
        "microsoft_account_id",
        "mailboxes",
        "sender_filters",
        "subject_filters",
        "required_keywords",
        "alias_enabled",
        "alias_max_per_account",
    ):
        value = mailbox.get(key)
        if value not in (None, ""):
            provider[key] = value
    if isinstance(mailbox.get("cookies"), dict):
        provider["cookies"] = mailbox["cookies"]
    email = _first_text(mailbox.get("email"), account.get("email"), provider.get("email"))
    if email and "@" not in email:
        email = ""
    if email:
        provider["email"] = email
    return provider


def _mail_wait_config_for_account(
    account: dict[str, Any],
    mailbox: dict[str, Any],
    *,
    proxy: str,
    wait_timeout: int,
    wait_interval: int,
    request_timeout: int,
) -> RegisterConfig:
    provider = _mailbox_mail_provider_config(account, mailbox)
    return RegisterConfig(
        proxy=str(proxy or "").strip(),
        mail=MailConfig(
            wait_timeout=int(wait_timeout or 30),
            wait_interval=int(wait_interval or 2),
            request_timeout=int(request_timeout or 30),
            proxy=str(proxy or "").strip(),
            providers=[provider] if provider else [],
        ),
    )


def _bind_mail_config_for_account(
    account: dict[str, Any],
    mailbox: dict[str, Any],
    *,
    proxy: str,
    wait_timeout: int,
    wait_interval: int,
    request_timeout: int,
) -> dict[str, Any]:
    provider = _mailbox_mail_provider_config(account, mailbox)
    providers = [provider] if provider else []
    provider_type = str(provider.get("type") or "").strip().lower() if provider else ""
    if provider_type in {"icloud", "icloud-hme", "icloud_hme"}:
        fallback_provider = _load_webui_cloudflare_fallback_provider()
        if fallback_provider:
            providers.append(fallback_provider)
    return {
        "proxy": str(proxy or "").strip(),
        "wait_timeout": int(wait_timeout or 30),
        "wait_interval": int(wait_interval or 2),
        "request_timeout": int(request_timeout or 30),
        "providers": providers,
    }


def _login_identifier_for_account(account: dict[str, Any], mailbox: dict[str, Any], fallback_email: str) -> str:
    for value in (mailbox.get("bind_email"), mailbox.get("email"), account.get("email"), fallback_email):
        candidate = str(value or "").strip()
        if "@" in candidate:
            return candidate
    phone = str(mailbox.get("phone_number") or account.get("phone_number") or "").strip()
    source = str(account.get("source") or "").strip().lower()
    if phone and (bool(mailbox.get("phone_number_verified")) or source in {"phone_signup", "phone_direct", "hero_phone_bind"}):
        return phone
    return str(fallback_email or "").strip()


def _bind_email_hint_for_account(account: dict[str, Any], mailbox: dict[str, Any], fallback_email: str) -> str:
    for value in (mailbox.get("bind_email"), mailbox.get("email"), account.get("email"), fallback_email):
        candidate = str(value or "").strip()
        if "@" in candidate:
            return candidate
    return ""





def _safe_response_summary(info: dict[str, Any]) -> dict[str, Any]:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    candidates = []
    for value in [
        body.get("continue_url"), body.get("redirect_url"), body.get("url"), body.get("callback_url"), body.get("return_to"),
        info.get("location"), info.get("final_url"), page.get("continue_url"), page.get("redirect_url"), page.get("url"),
    ]:
        v = str(value or "").strip()
        if v:
            candidates.append(v[:160])
    text = str(info.get("text") or "")
    summary = {
        "status": info.get("status"),
        "ok": info.get("ok"),
        "json_keys": sorted(str(k) for k in body.keys())[:30],
        "page_type": str(page.get("type") or ""),
        "location_prefix": str(info.get("location") or "")[:160],
        "final_url_prefix": str(info.get("final_url") or "")[:160],
        "candidate_prefixes": candidates[:12],
        "text_markers": {
            "has_code": "code=" in text,
            "has_continue": "continue" in text.lower(),
            "has_callback": "callback" in text.lower(),
            "has_consent": "consent" in text.lower(),
        },
    }
    detail = ""
    if isinstance(body, dict):
        for key in ("error", "message", "detail", "reason"):
            value = body.get(key)
            if value:
                detail = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                break
    if detail:
        summary["error_prefix"] = detail[:240]
    return summary

def _enter_login_email_otp_step(registrar: PlatformRegistrar, state: str) -> dict[str, Any]:
    state = str(state or "").strip()
    targets = [
        f"{auth_base}/log-in/email-verification?state={state}" if state else f"{auth_base}/log-in/email-verification",
        f"{auth_base}/email-verification?state={state}" if state else f"{auth_base}/email-verification",
        _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification", state=state) if state else _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification"),
    ]
    attempts: list[dict[str, Any]] = []
    for target in targets:
        headers = _har_browser_fetch_headers(f"/log-in/email-verification?state={state}" if state else "/log-in/email-verification", accept="application/json, text/html, */*", content_type="")
        try:
            resp = registrar.session.get(target, headers=headers, verify=False, timeout=30, allow_redirects=True)
            html = str(getattr(resp, "text", "") or "")
            info = {"ok": 200 <= int(resp.status_code or 0) < 400, "status": int(resp.status_code or 0), "json": _response_json(resp), "text": html[:2000], "html": html, "location": str(resp.headers.get("Location") or ""), "final_url": str(getattr(resp, "url", target) or target), "target": target}
        except Exception as exc:
            info = {"ok": False, "status": 0, "json": {}, "text": "", "location": "", "final_url": target, "target": target, "error": str(exc)}
        attempts.append(info)
        summary = _safe_response_summary(info)
        page_type = str(summary.get("page_type") or "")
        final_url = str(info.get("final_url") or "")
        if info.get("ok") and (page_type == "email_otp_verification" or "email-verification" in final_url):
            return {**info, "attempts": attempts}
    last = attempts[-1] if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "final_url": ""}
    return {**last, "attempts": attempts}


def _send_login_otp(registrar: PlatformRegistrar, state: str) -> dict[str, Any]:
    state = str(state or "").strip()
    referer_path = f"/log-in/email-verification?state={state}" if state else "/log-in/email-verification"
    attempts: list[dict[str, Any]] = []
    route_target = _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification", state=state) if state else _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification")
    route_candidates = [
        (route_target, "json"),
        (route_target, "form"),
        (f"{auth_base}/log-in/email-verification?state={state}" if state else f"{auth_base}/log-in/email-verification", "form"),
    ]
    for payload in (
        {"origin_page_type": "email_otp_send", "data": {"intent": "send"}},
        {"origin_page_type": "email_otp_send", "data": {"intent": "resend"}},
        {"origin_page_type": "email_otp_send"},
        {"origin_page_type": "email_otp_verification", "data": {"intent": "resend"}},
    ):
        info = registrar._post_accounts_payload(payload, referer_path, candidates=route_candidates)
        payload_attempts = info.get("attempts") if isinstance(info.get("attempts"), list) else [info]
        attempts.extend(payload_attempts)
        body = info.get("json") if isinstance(info.get("json"), dict) else {}
        text = str(info.get("text") or body or "")
        final_url = str(info.get("final_url") or "")
        location = str(info.get("location") or "")
        if info.get("ok") or int(info.get("status") or 0) in (200, 204, 302) or "email-verification" in f"{text} {final_url} {location}":
            return {**info, "ok": True, "attempt": "remix:email_otp_send", "attempts": attempts}
    for method, path in (("get", "send"), ("post", "send"), ("post", "resend")):
        headers = _har_browser_fetch_headers(referer_path, accept="application/json", content_type="")
        url = f"{auth_base}/api/accounts/email-otp/{path}"
        try:
            if method == "post":
                headers = _har_browser_fetch_headers(referer_path, accept="application/json", content_type="application/json")
                resp = registrar.session.post(url, json={}, headers=headers, verify=False, timeout=30, allow_redirects=True)
            else:
                resp = registrar.session.get(url, headers=headers, verify=False, timeout=30, allow_redirects=True)
            body = _response_json(resp)
            status = int(resp.status_code or 0)
            final_url = str(getattr(resp, "url", url) or url)
            info = {
                "ok": status in (200, 302),
                "status": status,
                "json": body,
                "text": resp.text[:2000],
                "location": str(resp.headers.get("Location") or ""),
                "final_url": final_url,
                "referer": headers.get("referer") or "",
                "attempt": f"{method}:{path}",
                "authorize": registrar.last_authorize,
            }
        except Exception as exc:
            info = {
                "ok": False,
                "status": 0,
                "json": {},
                "text": "",
                "location": "",
                "final_url": url,
                "referer": headers.get("referer") or "",
                "attempt": f"{method}:{path}",
                "error": str(exc),
                "authorize": registrar.last_authorize,
            }
        attempts.append(info)
        if info.get("ok"):
            return {**info, "attempts": attempts}
    last = attempts[-1] if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "final_url": f"{auth_base}/api/accounts/email-otp/send"}
    return {**last, "attempts": attempts}


def _trigger_passwordless_login_otp(registrar: PlatformRegistrar) -> dict[str, Any]:
    state = str(registrar.last_authorize.get("state") or "").strip()
    referer_path = f"/log-in/password?state={state}" if state else "/log-in/password"
    attempts: list[dict[str, Any]] = []

    headers = _har_browser_fetch_headers(referer_path, accept="application/json", content_type="application/json")
    try:
        resp = registrar.session.post(
            f"{auth_base}/api/accounts/passwordless/send-otp",
            data="",
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        body = _response_json(resp)
        status = int(resp.status_code or 0)
        direct_info = {
            "ok": 200 <= status < 300,
            "status": status,
            "json": body,
            "text": str(getattr(resp, "text", "") or "")[:2000],
            "location": str(resp.headers.get("Location") or ""),
            "final_url": str(getattr(resp, "url", f"{auth_base}/api/accounts/passwordless/send-otp") or f"{auth_base}/api/accounts/passwordless/send-otp"),
            "referer": headers.get("referer") or "",
            "attempt": "passwordless_send_otp",
        }
    except Exception as exc:
        direct_info = {
            "ok": False,
            "status": 0,
            "json": {},
            "text": "",
            "location": "",
            "final_url": f"{auth_base}/api/accounts/passwordless/send-otp",
            "referer": headers.get("referer") or "",
            "attempt": "passwordless_send_otp",
            "error": str(exc),
        }
    attempts.append(direct_info)
    if direct_info.get("ok"):
        return {**direct_info, "attempts": attempts}

    payload = {"origin_page_type": "login_password", "data": {"intent": "passwordless_login_send_otp"}}
    candidates = [
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "json"),
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "form"),
        (f"{auth_base}/api/accounts", "json"),
    ]
    info = registrar._post_accounts_payload(payload, referer_path, candidates=candidates)
    attempts.extend(info.get("attempts") if isinstance(info.get("attempts"), list) else [info])
    ok = bool(info.get("ok")) or int(info.get("status") or 0) in (200, 204, 302)
    if not ok:
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            body = attempt.get("json") if isinstance(attempt.get("json"), dict) else {}
            text = str(attempt.get("text") or body or "")
            if int(attempt.get("status") or 0) in (200, 204, 302) or "email_otp" in text or "email-verification" in text:
                ok = True
                break
    return {**info, "ok": ok, "attempt": "passwordless_login_send_otp", "attempts": attempts}


def _html_attr(attrs: str, name: str) -> str:
    match = re.search(rf'{re.escape(name)}\s*=\s*["\']([^"\']*)["\']', str(attrs or ""), re.I | re.S)
    return str(match.group(1) or "").strip() if match else ""


def _strip_tags(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", str(value or ""))


def _extract_email_otp_form_inputs(html_text: str) -> tuple[str, dict[str, str], str, str]:
    text = str(html_text or "")
    form_matches = list(re.finditer(r"<form\b([^>]*)>(.*?)</form>", text, re.I | re.S))
    if not form_matches:
        return _extract_form_inputs(text)

    def _score_form(match: re.Match[str]) -> tuple[int, int]:
        attrs = match.group(1) or ""
        body = match.group(2) or ""
        haystack = f"{attrs}\n{_strip_tags(body)}".lower()
        score = 0
        for token, weight in [
            ("email-verification", 40),
            ("email verification", 40),
            ("email-otp", 36),
            ("otp", 26),
            ("verification code", 24),
            ("send code", 22),
            ("resend", 18),
            ("email", 12),
            ("log in", 8),
            ("login", 8),
            ("continue", 6),
        ]:
            if token in haystack:
                score += weight
        for token, weight in [("password", -24), ("consent", -18), ("authorize", -18), ("codex", -18), ("signup", -10)]:
            if token in haystack:
                score += weight
        if re.search(r"name\s*=\s*[\"'](?:email|code|otp|state)[\"']", body, re.I):
            score += 8
        if re.search(r"<button\b|type\s*=\s*[\"']submit[\"']", body, re.I):
            score += 4
        return score, len(body)

    form_match = max(form_matches, key=_score_form)
    form_attrs = form_match.group(1) or ""
    form_body = form_match.group(2) or ""
    action = _html_attr(form_attrs, "action")
    fields: dict[str, str] = {}
    email_name = ""
    code_name = ""
    submit_choice: tuple[int, str, str, str] | None = None

    def _submit_score(label: str, input_type: str) -> int:
        haystack = f"{label} {input_type}".lower()
        score = 0
        for token, weight in [("send", 30), ("resend", 28), ("email", 18), ("code", 18), ("verification", 16), ("continue", 8), ("submit", 4)]:
            if token in haystack:
                score += weight
        for token, weight in [("password", -20), ("authorize", -20), ("consent", -20), ("codex", -20)]:
            if token in haystack:
                score += weight
        return score

    for input_match in re.finditer(r"<input\b([^>]*)>", form_body, re.I | re.S):
        attrs = input_match.group(1) or ""
        name = _html_attr(attrs, "name")
        input_type = _html_attr(attrs, "type").lower()
        value = _html_attr(attrs, "value")
        if name and input_type in ("hidden", "checkbox", "radio"):
            if input_type not in ("checkbox", "radio") or re.search(r"\bchecked\b", attrs, re.I):
                fields[name] = value
        if name and input_type in ("submit", "button", "image"):
            candidate = (_submit_score(f"{name} {value}", input_type), name, value, _html_attr(attrs, "formaction"))
            if submit_choice is None or candidate[0] > submit_choice[0]:
                submit_choice = candidate
        if name and not email_name and (input_type == "email" or "email" in name.lower()):
            email_name = name
        if name and not code_name and ("code" in name.lower() or "otp" in name.lower()):
            code_name = name

    for button_match in re.finditer(r"<button\b([^>]*)>(.*?)</button>", form_body, re.I | re.S):
        attrs = button_match.group(1) or ""
        button_type = _html_attr(attrs, "type").lower() or "submit"
        if button_type not in ("", "submit"):
            continue
        name = _html_attr(attrs, "name")
        value = _html_attr(attrs, "value") or _strip_tags(button_match.group(2) or "").strip()
        candidate = (_submit_score(f"{name} {value}", button_type), name, value, _html_attr(attrs, "formaction"))
        if submit_choice is None or candidate[0] > submit_choice[0]:
            submit_choice = candidate

    if submit_choice:
        if submit_choice[1] and submit_choice[1] not in fields:
            fields[submit_choice[1]] = submit_choice[2]
        if submit_choice[3]:
            action = submit_choice[3]
    return action, fields, email_name, code_name


def _submit_login_email_otp_page_form(registrar: PlatformRegistrar, page_info: dict[str, Any]) -> dict[str, Any]:
    page_url = str(page_info.get("final_url") or "").strip()
    page_html = str(page_info.get("html") or page_info.get("text") or "")
    action, fields, email_name, code_name = _extract_email_otp_form_inputs(page_html)
    if not action and not fields:
        return {"ok": False, "status": 0, "json": {}, "text": "", "location": "", "final_url": page_url, "attempt": "page_form", "error": "email_otp_form_not_found"}
    payload = dict(fields)
    if email_name and email_name not in payload:
        email = str(registrar.last_authorize.get("email") or "").strip()
        if email:
            payload[email_name] = email
    if code_name and code_name in payload and not payload.get(code_name):
        payload.pop(code_name, None)
    try:
        final_url, body = _post_form_and_follow(registrar, page_url=page_url or f"{auth_base}/log-in/email-verification", action=action, payload=payload)
        return {"ok": True, "status": 200, "json": {}, "text": body[:2000], "location": "", "final_url": final_url, "attempt": "page_form", "payload_keys": sorted(payload.keys())}
    except Exception as exc:
        return {"ok": False, "status": 0, "json": {}, "text": "", "location": "", "final_url": page_url, "attempt": "page_form", "error": str(exc), "payload_keys": sorted(payload.keys())}


def _validate_login_otp(registrar: PlatformRegistrar, state: str, code: str) -> dict[str, Any]:
    state = str(state or "").strip()
    referer_path = f"/log-in/email-verification?state={state}" if state else "/log-in/email-verification"
    headers = _har_browser_fetch_headers(referer_path)
    device_id = str(getattr(registrar, "device_id", "") or "").strip()
    if device_id:
        headers["oai-device-id"] = device_id
        try:
            headers["openai-sentinel-token"] = build_sentinel_token(registrar.session, device_id, "authorize_continue")
        except Exception:
            pass
    try:
        resp = registrar.session.post(
            f"{auth_base}/api/accounts/email-otp/validate",
            json={"code": str(code).strip()},
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        body = _response_json(resp)
        status = int(resp.status_code or 0)
        final_url = str(getattr(resp, "url", f"{auth_base}/api/accounts/email-otp/validate") or f"{auth_base}/api/accounts/email-otp/validate")
        info = {
            "ok": 200 <= status < 300 or bool(_extract_callback_from_step({"json": body, "location": str(resp.headers.get("Location") or ""), "final_url": final_url})),
            "status": status,
            "json": body,
            "text": resp.text[:2000],
            "location": str(resp.headers.get("Location") or ""),
            "final_url": final_url,
            "referer": headers.get("referer") or "",
            "authorize": registrar.last_authorize,
        }
        if info.get("ok"):
            return info
    except Exception as exc:
        info = {
            "ok": False,
            "status": 0,
            "json": {},
            "text": "",
            "location": "",
            "final_url": f"{auth_base}/api/accounts/email-otp/validate",
            "referer": headers.get("referer") or "",
            "error": str(exc),
            "authorize": registrar.last_authorize,
        }
    attempts = [info]
    route_target = _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification", state=state) if state else _merge_url_query(f"{auth_base}/log-in/email-verification", _data="routes/log-in/email-verification")
    route_candidates = [
        (route_target, "json"),
        (route_target, "form"),
        (f"{auth_base}/log-in/email-verification?state={state}" if state else f"{auth_base}/log-in/email-verification", "form"),
    ]
    clean_code = str(code or "").strip()
    payloads = [
        {"origin_page_type": "email_otp_verification", "data": {"intent": "validate", "code": clean_code}},
        {"origin_page_type": "email_otp_verification", "data": {"code": clean_code}},
        {"origin_page_type": "email_otp_verification", "code": clean_code},
    ]
    if state:
        payloads.insert(1, {"origin_page_type": "email_otp_verification", "data": {"intent": "validate", "code": clean_code, "state": state}})
    for payload in payloads:
        remix_info = registrar._post_accounts_payload(payload, referer_path, candidates=route_candidates)
        payload_attempts = remix_info.get("attempts") if isinstance(remix_info.get("attempts"), list) else [remix_info]
        attempts.extend(payload_attempts)
        callbackish = _extract_callback_from_step(
            {
                "json": remix_info.get("json") if isinstance(remix_info.get("json"), dict) else {},
                "location": str(remix_info.get("location") or ""),
                "final_url": str(remix_info.get("final_url") or ""),
                "text": str(remix_info.get("text") or ""),
            }
        )
        if remix_info.get("ok") or callbackish:
            return {**remix_info, "ok": True, "attempt": "remix:email_otp_validate", "attempts": attempts, "authorize": registrar.last_authorize}
    return {**attempts[-1], "attempts": attempts, "authorize": registrar.last_authorize}


def _handle_email_otp_step(
    registrar: PlatformRegistrar,
    account: dict[str, Any],
    mailbox: dict[str, Any],
    state: str,
    *,
    proxy: str,
    wait_timeout: int,
    wait_interval: int,
    request_timeout: int,
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    def _wait_code_after(mail_cfg: RegisterConfig, mb: dict[str, Any]) -> str:
        code_value = str(wait_for_code(mail_cfg, mb) or "").strip()
        if not code_value:
            return ""
        meta = mb.get("_last_code_meta") if isinstance(mb.get("_last_code_meta"), dict) else {}
        code_received_ms = int(meta.get("received_at_ms") or 0)
        threshold_ms = int(mb.get("_code_after_ts") or 0)
        stale_before_ms = max(0, threshold_ms - 2000)
        if threshold_ms > 0 and code_received_ms <= 0:
            _log_stage(f"邮箱验证码缺少收信时间，已丢弃并重试：code_after_ts={threshold_ms}")
            excluded = list(mb.get("_exclude_codes") or [])
            if code_value and code_value not in excluded:
                excluded.append(code_value)
                mb["_exclude_codes"] = excluded
            return str(wait_for_code(mail_cfg, mb) or "").strip()
        if threshold_ms > 0 and code_received_ms > 0 and code_received_ms < stale_before_ms:
            _log_stage(f"命中旧邮箱验证码，已丢弃并重试：code_received_ms={code_received_ms} < code_after_ts={threshold_ms}")
            excluded = list(mb.get("_exclude_codes") or [])
            if code_value and code_value not in excluded:
                excluded.append(code_value)
                mb["_exclude_codes"] = excluded
            return str(wait_for_code(mail_cfg, mb) or "").strip()
        return code_value

    _log_stage("快速检查邮箱里是否已有可用验证码")
    quick_wait_timeout = min(3, max(1, int(wait_timeout or 1)))
    quick_wait_interval = min(1, max(1, int(wait_interval or 1)))
    quick_mail_config = _mail_wait_config_for_account(
        account,
        mailbox,
        proxy=proxy,
        wait_timeout=quick_wait_timeout,
        wait_interval=quick_wait_interval,
        request_timeout=request_timeout,
    )
    mail_config = _mail_wait_config_for_account(
        account,
        mailbox,
        proxy=proxy,
        wait_timeout=wait_timeout,
        wait_interval=wait_interval,
        request_timeout=request_timeout,
    )
    if int(mailbox.get("_code_after_ts") or 0) <= 0:
        mailbox["_code_after_ts"] = int(time.time() * 1000)
    code = _wait_code_after(quick_mail_config, mailbox)
    debug: dict[str, Any] = {"email_code_received_before_resend": bool(code)}
    _log_stage(f"已有邮箱验证码检查结果：{'已找到' if code else '未找到'}")
    if not code:
        _log_stage("进入邮箱验证码登录页")
        enter_info = _enter_login_email_otp_step(registrar, state)
        debug["enter_email_otp"] = enter_info
        _log_stage(f"邮箱验证码登录页打开结果：{_response_brief(enter_info)}")
        debug["email_otp_page_form"] = {"skipped": True, "reason": "prefer_passwordless_send_otp"}
        _log_stage("跳过邮箱验证码页面表单触发，直接使用无密码接口")
    if not code:
        _log_stage("触发无密码邮箱验证码发送")
        trigger_info = _trigger_passwordless_login_otp(registrar)
        debug["passwordless_login_otp"] = trigger_info
        debug["passwordless_login_otp_summary"] = _safe_response_summary(trigger_info)
        _log_stage(f"无密码邮箱验证码发送结果：{_response_brief(trigger_info)}，方式={trigger_info.get('attempt') or '-'}")
        if trigger_info.get("ok"):
            _log_stage("无密码验证码已触发，等待邮箱验证码")
            code = _wait_code_after(mail_config, mailbox)
    if not code:
        _log_stage("发送登录邮箱验证码")
        send_info = _send_login_otp(registrar, state)
        debug["send_otp"] = send_info
        debug["send_otp_summary"] = _safe_response_summary(send_info)
        _log_stage(f"登录邮箱验证码发送结果：{_response_brief(send_info)}，方式={send_info.get('attempt') or '-'}")
        if not send_info.get("ok"):
            detail = ""
            for attempt in send_info.get("attempts") or [send_info]:
                if not isinstance(attempt, dict):
                    continue
                text = re.sub(r"\s+", " ", str(attempt.get("text") or attempt.get("json") or "")).strip()
                detail += f" {attempt.get('attempt') or '?'}:{attempt.get('status') or 0}:{text[:180]}"
            raise RuntimeError(f"send_otp_{send_info.get('status') or 0}:{detail.strip()}")
        _log_stage("登录验证码已触发，等待邮箱验证码")
        code = _wait_code_after(mail_config, mailbox)
    debug["email_code_received"] = bool(code)
    _log_stage(f"邮箱验证码接收结果：{'已收到' if code else '等待超时'}")
    if code:
        _log_stage(f"邮箱验证码内容：{code}")
    if not code:
        raise RuntimeError("wait_for_code_timeout")
    _log_stage("提交并校验邮箱验证码")
    validate_info = _validate_login_otp(registrar, state, code)
    debug["validate_otp"] = validate_info
    debug["validate_otp_summary"] = _safe_response_summary(validate_info)
    _log_stage(f"邮箱验证码校验结果：{_response_brief(validate_info)}")
    if not validate_info.get("ok"):
        raise RuntimeError(f"validate_otp_{validate_info.get('status') or 0}")
    if _step_requires_phone_verification(validate_info):
        return "", validate_info, debug
    validate_state = _registration_state_from_info(validate_info)
    validate_kind = str(validate_state.get("kind") or "").strip()
    if validate_kind in {"about_you", "add_email", "email_otp"}:
        return "", validate_info, debug
    callback = _resolve_callback_step(registrar, validate_info, state, allow_state_resume=False)
    if not callback:
        consent_url = str((validate_info.get("json") or {}).get("continue_url") or (((validate_info.get("json") or {}).get("page") or {}).get("continue_url")) or "").strip()
        if _is_consent_like_url(consent_url):
            _log_stage(f"邮箱验证码通过，进入授权确认页：{_short_url(consent_url)}")
            callback, consent_summary = _resolve_consent_callback_direct(registrar, consent_url, state)
            debug["consent_direct_summary"] = consent_summary
            _log_stage(f"授权确认页处理结果：回调{_ready_text(callback)}，尝试次数={len((consent_summary or {}).get('attempts') or [])}")
    if not callback:
        _log_stage("邮箱验证码通过后未直接拿到回调，尝试通过 state 恢复授权")
        callback = _resolve_callback_step(registrar, validate_info, state, allow_state_resume=True)
        _log_stage(f"state 恢复授权结果：回调{_ready_text(callback)}")
    return callback, validate_info, debug


def _first_step_continue_url(info: dict[str, Any]) -> str:
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
    ):
        raw = str(value or "").strip()
        if not raw:
            continue
        if raw.startswith("/"):
            return f"{auth_base}{raw}"
        return raw
    return ""


def _step_requires_phone_verification(info: dict[str, Any]) -> bool:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    page_type = str(page.get("type") or body.get("page_type") or info.get("page_type") or "").strip().lower()
    if page_type in {"add_phone", "phone_otp_send", "phone_otp_select_channel", "phone_otp_verification", "phone_verification"}:
        return True
    for value in (body.get("continue_url"), body.get("redirect_url"), body.get("url"), page.get("continue_url"), page.get("redirect_url"), page.get("url"), info.get("location"), info.get("final_url")):
        raw = str(value or "").lower()
        if "/add-phone" in raw or "/phone-verification" in raw or "/phone-otp/" in raw:
            return True
    return False


def _build_reauthorize_sms_config(
    *,
    sms_provider: str = "",
    sms_api_key: str = "",
    hero_sms_api_key: str = "",
    smsbower_api_key: str = "",
    hero_sms_base_url: str = "",
    smsbower_base_url: str = "",
    hero_sms_country: str = "",
    hero_sms_service: str = "",
    hero_sms_min_price: float | str = 0.0,
    hero_sms_max_price: float | str = 0.0,
    sms_wait_timeout: int = 60,
    sms_wait_interval: int = 5,
    sms_resend_after_seconds: int = 30,
    sms_timeout_after_resend_seconds: int = 60,
    sms_release_after_seconds: int = 120,
    sms_retry_count: int = 3,
    sms_auto_retry: bool = False,
) -> HeroSMSConfig:
    provider = _normalize_sms_provider(sms_provider or "hero_sms")
    key = str(sms_api_key or "").strip()
    if not key:
        key = str(smsbower_api_key if provider == "smsbower" else hero_sms_api_key or "").strip()
    if not key and provider == "hero_sms":
        key = str(hero_sms_api_key or "").strip()
    if not key and provider == "smsbower":
        key = str(smsbower_api_key or hero_sms_api_key or "").strip()
    base_url = str(smsbower_base_url if provider == "smsbower" else hero_sms_base_url or "").strip()
    if provider == "smsbower":
        base_url = base_url or SMSBOWER_BASE_URL
    elif provider == "5sim":
        base_url = base_url or FIVESIM_BASE_URL
        if "hero-sms.com" in base_url.lower() or "smsbower" in base_url.lower():
            base_url = FIVESIM_BASE_URL
    else:
        base_url = base_url or "https://hero-sms.com/stubs/handler_api.php"
    try:
        min_price = float(hero_sms_min_price or 0)
    except Exception:
        min_price = 0.0
    try:
        max_price = float(hero_sms_max_price or 0)
    except Exception:
        max_price = 0.0
    country = str(hero_sms_country or "").strip()
    service = str(hero_sms_service or "").strip()
    if provider == "5sim":
        if not country or country.isdigit():
            country = "england"
        if not service or service == "dr":
            service = "openai"
    else:
        country = country or "16"
        service = service or "dr"
    return HeroSMSConfig(
        provider=provider,
        api_key=key,
        base_url=base_url,
        country=country,
        service=service,
        min_price=min_price,
        max_price=max_price,
        wait_timeout=max(15, int(sms_wait_timeout or 60)),
        wait_interval=max(1, int(sms_wait_interval or 5)),
        resend_after_seconds=max(1, int(sms_resend_after_seconds or 30)),
        timeout_after_resend_seconds=max(1, int(sms_timeout_after_resend_seconds or 60)),
        release_after_seconds=max(15, int(sms_release_after_seconds or 120)),
        max_retry_count=max(1, int(sms_retry_count or 3)),
        auto_retry=bool(sms_auto_retry),
    )


def _phone_pool_now() -> str:
    return datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")


def _phone_reuse_pool_path():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / PHONE_REUSE_POOL_NAME


def _load_phone_reuse_pool() -> dict[str, Any]:
    path = _phone_reuse_pool_path()
    if not path.exists():
        return {"items": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {"items": []}
    if not isinstance(data, dict):
        return {"items": []}
    items = data.get("items")
    if not isinstance(items, list):
        data["items"] = []
    return data


def _save_phone_reuse_pool(data: dict[str, Any]) -> None:
    path = _phone_reuse_pool_path()
    payload = data if isinstance(data, dict) else {"items": []}
    payload.setdefault("items", [])
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _phone_pool_key(config: HeroSMSConfig, activation_id: str) -> str:
    return f"{_normalize_sms_provider(config.provider)}:{str(activation_id or '').strip()}"


def _phone_pool_matches_config(item: dict[str, Any], config: HeroSMSConfig) -> bool:
    return (
        str(item.get("status") or "active") == "active"
        and str(item.get("provider") or "") == _normalize_sms_provider(config.provider)
        and str(item.get("country") or "") == str(config.country or "")
        and str(item.get("service") or "") == str(config.service or "")
        and bool(str(item.get("activation_id") or "").strip())
        and bool(str(item.get("phone_number") or "").strip())
        and int(item.get("use_count") or 0) < int(item.get("max_uses") or PHONE_REUSE_LIMIT)
    )


def _find_reusable_phone_activation(config: HeroSMSConfig) -> dict[str, str]:
    pool = _load_phone_reuse_pool()
    for item in pool.get("items") or []:
        if isinstance(item, dict) and _phone_pool_matches_config(item, config):
            return {
                "activation_id": str(item.get("activation_id") or "").strip(),
                "phone_number": str(item.get("phone_number") or "").strip(),
                "reuse_count": str(int(item.get("use_count") or 0)),
                "max_uses": str(int(item.get("max_uses") or PHONE_REUSE_LIMIT)),
                "reused": "1",
            }
    return {}


def _acquire_or_reuse_phone_activation(config: HeroSMSConfig) -> dict[str, str]:
    reused = _find_reusable_phone_activation(config)
    if reused:
        return reused
    activation = acquire_hero_sms_phone(config)
    return {
        "activation_id": str(activation.get("activation_id") or "").strip(),
        "phone_number": str(activation.get("phone_number") or "").strip(),
        "price": str(activation.get("price") or "").strip(),
        "reuse_count": "0",
        "max_uses": str(PHONE_REUSE_LIMIT),
        "reused": "0",
    }


def _retire_phone_activation(config: HeroSMSConfig, activation_id: str, reason: str = "") -> None:
    activation_id = str(activation_id or "").strip()
    if not activation_id:
        return
    pool = _load_phone_reuse_pool()
    key = _phone_pool_key(config, activation_id)
    changed = False
    for item in pool.get("items") or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("key") or "") == key or str(item.get("activation_id") or "") == activation_id:
            item["status"] = "retired"
            item["retired_reason"] = str(reason or "").strip()
            item["updated_at"] = _phone_pool_now()
            changed = True
    if changed:
        _save_phone_reuse_pool(pool)


def _record_phone_activation_success(
    config: HeroSMSConfig,
    activation_id: str,
    phone_number: str,
    *,
    account_id: str = "",
    email: str = "",
) -> dict[str, Any]:
    activation_id = str(activation_id or "").strip()
    phone_number = str(phone_number or "").strip()
    if not activation_id or not phone_number:
        return {"use_count": 0, "max_uses": PHONE_REUSE_LIMIT, "completed": False}
    pool = _load_phone_reuse_pool()
    items = pool.setdefault("items", [])
    key = _phone_pool_key(config, activation_id)
    item = next((row for row in items if isinstance(row, dict) and str(row.get("key") or "") == key), None)
    if item is None:
        item = {
            "key": key,
            "provider": _normalize_sms_provider(config.provider),
            "activation_id": activation_id,
            "phone_number": phone_number,
            "country": str(config.country or ""),
            "service": str(config.service or ""),
            "use_count": 0,
            "max_uses": PHONE_REUSE_LIMIT,
            "status": "active",
            "accounts": [],
            "created_at": _phone_pool_now(),
        }
        items.append(item)
    accounts = item.setdefault("accounts", [])
    if not isinstance(accounts, list):
        accounts = []
        item["accounts"] = accounts
    item["phone_number"] = phone_number
    item["provider"] = _normalize_sms_provider(config.provider)
    item["country"] = str(config.country or "")
    item["service"] = str(config.service or "")
    item["max_uses"] = int(item.get("max_uses") or PHONE_REUSE_LIMIT)
    item["use_count"] = min(int(item.get("max_uses") or PHONE_REUSE_LIMIT), int(item.get("use_count") or 0) + 1)
    if account_id or email:
        accounts.append({"account_id": str(account_id or ""), "email": str(email or ""), "at": _phone_pool_now()})
    completed = int(item["use_count"]) >= int(item["max_uses"])
    item["status"] = "completed" if completed else "active"
    item["updated_at"] = _phone_pool_now()
    _save_phone_reuse_pool(pool)
    return {
        "use_count": int(item["use_count"]),
        "max_uses": int(item["max_uses"]),
        "completed": completed,
        "remaining": max(0, int(item["max_uses"]) - int(item["use_count"])),
    }


def _set_phone_activation_after_success(config: HeroSMSConfig, activation_id: str, usage: dict[str, Any]) -> None:
    if bool(usage.get("completed")):
        set_hero_sms_status(config, activation_id, 6)
    else:
        # SMS-Activate compatible APIs use status=3 to request the next SMS on the same activation.
        set_hero_sms_status(config, activation_id, 3)


def _send_add_phone_number(registrar: PlatformRegistrar, phone_number: str, referer: str = "") -> dict[str, Any]:
    request_url = f"{auth_base}/api/accounts/add-phone/send"
    headers = _har_browser_fetch_headers("/add-phone")
    headers["referer"] = str(referer or f"{auth_base}/add-phone")
    headers["oai-device-id"] = registrar.device_id
    try:
        resp = registrar.session.post(
            request_url,
            json={"phone_number": str(phone_number or "").strip()},
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        body = _response_json(resp)
        status = int(resp.status_code or 0)
        final_url = str(getattr(resp, "url", request_url) or request_url)
        return {
            "ok": status == 200,
            "status": status,
            "json": body,
            "text": str(getattr(resp, "text", "") or "")[:2000],
            "location": str(resp.headers.get("Location") or ""),
            "final_url": final_url,
            "referer": headers.get("referer") or "",
            "authorize": registrar.last_authorize,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "json": {},
            "text": "",
            "location": "",
            "final_url": request_url,
            "referer": headers.get("referer") or "",
            "error": str(exc),
            "authorize": registrar.last_authorize,
        }


def _validate_add_phone_otp(registrar: PlatformRegistrar, code: str, referer: str = "") -> dict[str, Any]:
    request_url = f"{auth_base}/api/accounts/phone-otp/validate"
    headers = _har_browser_fetch_headers("/phone-verification")
    headers["referer"] = str(referer or f"{auth_base}/phone-verification")
    headers["oai-device-id"] = registrar.device_id
    try:
        resp = registrar.session.post(
            request_url,
            json={"code": str(code or "").strip()},
            headers=headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        body = _response_json(resp)
        status = int(resp.status_code or 0)
        final_url = str(getattr(resp, "url", request_url) or request_url)
        return {
            "ok": 200 <= status < 300 or bool(_extract_callback_from_step({"json": body, "location": str(resp.headers.get("Location") or ""), "final_url": final_url})),
            "status": status,
            "json": body,
            "text": str(getattr(resp, "text", "") or "")[:2000],
            "location": str(resp.headers.get("Location") or ""),
            "final_url": final_url,
            "referer": headers.get("referer") or "",
            "authorize": registrar.last_authorize,
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "json": {},
            "text": "",
            "location": "",
            "final_url": request_url,
            "referer": headers.get("referer") or "",
            "error": str(exc),
            "authorize": registrar.last_authorize,
        }


def _continue_with_optional_phone_verification(
    registrar: PlatformRegistrar,
    source_info: dict[str, Any],
    state: str,
    *,
    sms_config: HeroSMSConfig,
    retry_count: int = 1,
    account_id: str = "",
    email: str = "",
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    if not _step_requires_phone_verification(source_info):
        return "", source_info, {"required": False}
    if not str(sms_config.api_key or "").strip():
        _log_stage(f"需要手机二次验证，但未配置接码服务 API Key：{_phone_verification_page_brief(source_info)}")
        raise RuntimeError("sms_api_key_required_for_phone_verification")

    attempts = max(1, int(retry_count or 1))
    last_info: dict[str, Any] = source_info
    debug: dict[str, Any] = {"required": True, "provider": sms_config.provider, "attempts": []}
    referer = _first_step_continue_url(source_info) or f"{auth_base}/add-phone"
    _log_stage(f"开始手机二次验证，接码服务={sms_config.provider or '-'}，{_phone_verification_page_brief(source_info)}")
    for attempt in range(1, attempts + 1):
        activation_id = ""
        phone_number = ""
        reused = False
        try:
            activation = _acquire_or_reuse_phone_activation(sms_config)
            activation_id = str(activation.get("activation_id") or "").strip()
            phone_number = str(activation.get("phone_number") or "").strip()
            phone_price = str(activation.get("price") or "").strip()
            reused = str(activation.get("reused") or "") == "1"
            reuse_text = "复用" if reused else "新取"
            price_text = f"，价格={phone_price}" if phone_price else ""
            _log_stage(f"手机二次验证号码已获取：{reuse_text}号码 {phone_number}{price_text}，第 {attempt}/{attempts} 次")
            send_info = _send_add_phone_number(registrar, phone_number, referer=referer)
            last_info = send_info
            debug["attempts"].append({
                "attempt": attempt,
                "phone": phone_number,
                "activation_id": activation_id,
                "reused": reused,
                "reuse_count": activation.get("reuse_count"),
                "max_uses": activation.get("max_uses"),
                "send_status": send_info.get("status"),
                "send_ok": send_info.get("ok"),
            })
            _log_stage(f"手机二次验证短信发送结果：{_response_brief(send_info)}")
            if not send_info.get("ok"):
                _retire_phone_activation(sms_config, activation_id, f"add_phone_send_{send_info.get('status') or 0}")
                set_hero_sms_status(sms_config, activation_id, 8)
                continue

            def _resend() -> None:
                resend_info = _send_add_phone_number(registrar, phone_number, referer=_first_step_continue_url(send_info) or referer)
                _log_stage(f"手机二次验证短信重发结果：{_response_brief(resend_info)}")
                if not resend_info.get("ok"):
                    raise RuntimeError(f"add_phone_resend_{resend_info.get('status') or 0}")

            _log_stage("等待手机二次验证短信验证码")
            sms_code = poll_hero_sms_code(sms_config, activation_id, on_resend=_resend, timeout_after_resend=60)
            _log_stage(f"已收到手机二次验证短信验证码：{sms_code}")
            validate_info = _validate_add_phone_otp(registrar, sms_code, referer=_first_step_continue_url(send_info) or f"{auth_base}/phone-verification")
            last_info = validate_info
            _log_stage(f"手机二次验证验证码校验结果：{_response_brief(validate_info)}")
            if not validate_info.get("ok"):
                _retire_phone_activation(sms_config, activation_id, f"validate_phone_otp_{validate_info.get('status') or 0}")
                set_hero_sms_status(sms_config, activation_id, 8)
                continue
            callback = _resolve_callback_step(registrar, validate_info, state, allow_state_resume=False)
            if not callback:
                consent_url = str((validate_info.get("json") or {}).get("continue_url") or (((validate_info.get("json") or {}).get("page") or {}).get("continue_url")) or "").strip()
                if consent_url:
                    callback, consent_summary = _resolve_consent_callback_direct(registrar, consent_url, state)
                    debug["consent_after_phone"] = consent_summary
            if callback:
                usage = _record_phone_activation_success(
                    sms_config,
                    activation_id,
                    phone_number,
                    account_id=account_id,
                    email=email,
                )
                _set_phone_activation_after_success(sms_config, activation_id, usage)
                debug["callback_ready"] = True
                debug["phone_number"] = phone_number
                debug["activation_id"] = activation_id
                debug["phone_reuse"] = usage
                _log_stage("手机二次验证已通过，OAuth 回调已拿到")
                return callback, validate_info, debug
            _log_stage("手机二次验证已通过但未拿到 OAuth 回调，释放当前号码并重试")
            _retire_phone_activation(sms_config, activation_id, "callback_missing_after_phone_otp")
            set_hero_sms_status(sms_config, activation_id, 8)
        except Exception as exc:
            _log_stage(f"手机二次验证第 {attempt}/{attempts} 次失败：{exc}")
            debug["attempts"].append({"attempt": attempt, "phone": phone_number, "activation_id": activation_id, "error": str(exc)})
            if activation_id:
                _retire_phone_activation(sms_config, activation_id, str(exc))
                set_hero_sms_status(sms_config, activation_id, 8)
            if attempt >= attempts:
                raise
    return "", last_info, debug





def _callback_url_from_response_info_direct(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    for value in [
        info.get("location"),
        info.get("final_url"),
        body.get("callback_url"),
        body.get("redirect_url"),
        body.get("continue_url"),
        body.get("url"),
        page.get("callback_url"),
        page.get("redirect_url"),
        page.get("continue_url"),
        page.get("url"),
    ]:
        raw = str(value or "").strip()
        if raw.startswith("/"):
            raw = f"{auth_base}{raw}"
        if raw and extract_oauth_callback_params_from_url(raw):
            return raw
    text = str(info.get("text") or "")
    for raw in re.findall(r"https?://[^\"'\s<>]+|/(?:auth/callback)\?[^\"'\s<>]+", text, re.I):
        raw = str(raw or "").strip()
        if raw.startswith("/"):
            raw = f"{auth_base}{raw}"
        if raw and extract_oauth_callback_params_from_url(raw):
            return raw
    return ""

def _resolve_consent_callback_direct(registrar: PlatformRegistrar, consent_url: str, state: str) -> tuple[str, dict[str, Any]]:
    url = str(consent_url or "").strip()
    if not url:
        return "", {"error": "empty_consent_url"}
    if url.startswith("/"):
        url = f"{auth_base}{url}"
    headers = dict(registrar._build_accounts_headers(f"/sign-in-with-chatgpt/codex/consent?state={state}" if state else "/sign-in-with-chatgpt/codex/consent", "authorize_continue"))
    headers["accept"] = "application/json, text/html, */*"
    summary: dict[str, Any] = {"url_prefix": url[:160], "attempts": []}
    try:
        browser_like_steps: list[dict[str, Any]] = []
        params = extract_oauth_callback_params_from_consent_session(registrar.session, url, str(getattr(registrar, "device_id", "") or ""), state=state, debug_steps=browser_like_steps)
        summary["attempts"].append({"method": "browser_like_consent_session", "target_prefix": url[:160], "matched": bool(params), "steps": browser_like_steps[:20]})
        if params:
            code = str(params.get("code") or "").strip()
            cb_state = str(params.get("state") or state or "").strip()
            if code and cb_state:
                return f"http://localhost:1455/auth/callback?code={code}&state={cb_state}", summary
            if code:
                return f"http://localhost:1455/auth/callback?code={code}", summary
    except Exception as exc:
        summary["attempts"].append({"method": "browser_like_consent_session", "target_prefix": url[:160], "error": str(exc)})
    candidates = [url]
    if state and "state=" not in url:
        candidates.append(_merge_url_query(url, state=state))
    for target in dict.fromkeys(candidates):
        for method, kwargs in [
            ("get", {}),
            ("post", {"json": {}}),
            ("post", {"json": {"state": state}} if state else {"json": {}}),
            ("post", {"json": {"action": "approve", "state": state}} if state else {"json": {"action": "approve"}}),
        ]:
            try:
                resp = registrar.session.request(method.upper(), target, headers=headers, verify=False, timeout=8, allow_redirects=False, **kwargs)
                body = _response_json(resp)
                loc = str(resp.headers.get("Location") or "")
                final = str(getattr(resp, "url", target) or target)
                text = str(getattr(resp, "text", "") or "")[:2000]
                info = {"ok": 200 <= int(resp.status_code or 0) < 400, "status": int(resp.status_code or 0), "json": body, "text": text, "location": loc, "final_url": final}
                attempt = _safe_response_summary(info)
                attempt["method"] = method
                attempt["target_prefix"] = target[:160]
                summary["attempts"].append(attempt)
                cb = _callback_url_from_response_info_direct(info)
                if cb:
                    return cb, summary

                # Browser-like confirm click: consent pages are often rendered as an HTML form.
                # Submit the selected form including the clicked submit/button name=value.
                try:
                    action, fields, email_name, code_name = _extract_form_inputs(str(getattr(resp, "text", "") or ""))
                except Exception:
                    action, fields, email_name, code_name = "", {}, "", ""
                if action or fields:
                    workspace_id = str((fields or {}).get("workspace_id") or (fields or {}).get("workspaceId") or "").strip()
                    if workspace_id:
                        ws_headers = dict(headers)
                        ws_headers["referer"] = final or target
                        ws_headers["content-type"] = "application/json"
                        ws_payloads = [
                            {"workspace_id": workspace_id},
                            {"workspaceId": workspace_id},
                            {"id": workspace_id},
                            {"workspace_id": workspace_id, "state": str((fields or {}).get("state") or state or "").strip()},
                        ]
                        for ws_payload in ws_payloads:
                            try:
                                r_ws = registrar.session.post(f"{auth_base}/api/accounts/workspace/select", json=ws_payload, headers=ws_headers, verify=False, timeout=12, allow_redirects=False)
                                info_ws = {"ok": 200 <= int(r_ws.status_code or 0) < 400, "status": int(r_ws.status_code or 0), "json": _response_json(r_ws), "text": str(getattr(r_ws, "text", "") or "")[:2000], "location": str(r_ws.headers.get("Location") or ""), "final_url": str(getattr(r_ws, "url", f"{auth_base}/api/accounts/workspace/select") or f"{auth_base}/api/accounts/workspace/select")}
                                ws_summary = _safe_response_summary(info_ws)
                                ws_summary["method"] = "workspace_select"
                                ws_summary["target_prefix"] = f"{auth_base}/api/accounts/workspace/select"
                                ws_summary["payload_keys"] = sorted(ws_payload.keys())
                                summary["attempts"].append(ws_summary)
                                cb = _callback_url_from_response_info_direct(info_ws)
                                if cb:
                                    return cb, summary
                                ws_data = info_ws.get("json") if isinstance(info_ws.get("json"), dict) else {}
                                orgs = ((ws_data.get("data") or {}).get("orgs") or []) if isinstance(ws_data, dict) else []
                                if orgs:
                                    org_id = str((orgs[0] or {}).get("id") or "").strip()
                                    project_id = str(((orgs[0] or {}).get("projects") or [{}])[0].get("id") or "").strip()
                                    if org_id:
                                        org_headers = dict(ws_headers)
                                        org_headers["referer"] = str(ws_data.get("continue_url") or final or target)
                                        org_body = {"org_id": org_id}
                                        if project_id:
                                            org_body["project_id"] = project_id
                                        r_org = registrar.session.post(f"{auth_base}/api/accounts/organization/select", json=org_body, headers=org_headers, verify=False, timeout=12, allow_redirects=False)
                                        info_org = {"ok": 200 <= int(r_org.status_code or 0) < 400, "status": int(r_org.status_code or 0), "json": _response_json(r_org), "text": str(getattr(r_org, "text", "") or "")[:2000], "location": str(r_org.headers.get("Location") or ""), "final_url": str(getattr(r_org, "url", f"{auth_base}/api/accounts/organization/select") or f"{auth_base}/api/accounts/organization/select")}
                                        org_summary = _safe_response_summary(info_org)
                                        org_summary["method"] = "organization_select"
                                        org_summary["target_prefix"] = f"{auth_base}/api/accounts/organization/select"
                                        org_summary["payload_keys"] = sorted(org_body.keys())
                                        summary["attempts"].append(org_summary)
                                        cb = _callback_url_from_response_info_direct(info_org)
                                        if cb:
                                            return cb, summary
                            except Exception as exc:
                                summary["attempts"].append({"method": "workspace_select", "target_prefix": f"{auth_base}/api/accounts/workspace/select", "payload_keys": sorted(ws_payload.keys()), "error": str(exc)})
                    form_action = action or target
                    if form_action.startswith("/"):
                        form_action = f"{auth_base}{form_action}"
                    elif not form_action.startswith(("http://", "https://")):
                        base = final or target
                        parsed_base = urlparse(base)
                        if form_action.startswith("?"):
                            form_action = urlunparse((parsed_base.scheme, parsed_base.netloc, parsed_base.path, parsed_base.params, form_action[1:], parsed_base.fragment))
                        else:
                            form_action = f"{parsed_base.scheme}://{parsed_base.netloc}/{form_action.lstrip('/')}"
                    payload = dict(fields or {})
                    if state and not payload.get("state"):
                        payload["state"] = state
                    if email_name and email_name not in payload:
                        payload[email_name] = ""
                    if code_name and code_name not in payload:
                        payload[code_name] = ""
                    form_headers = dict(headers)
                    form_headers["content-type"] = "application/x-www-form-urlencoded"
                    form_headers["referer"] = final or target
                    try:
                        r_form = registrar.session.post(form_action, data=payload, headers=form_headers, verify=False, timeout=12, allow_redirects=False)
                        info_form = {"ok": 200 <= int(r_form.status_code or 0) < 400, "status": int(r_form.status_code or 0), "json": _response_json(r_form), "text": str(getattr(r_form, "text", "") or "")[:2000], "location": str(r_form.headers.get("Location") or ""), "final_url": str(getattr(r_form, "url", form_action) or form_action)}
                        form_summary = _safe_response_summary(info_form)
                        form_summary["method"] = "form_post"
                        form_summary["target_prefix"] = form_action[:160]
                        form_summary["payload_keys"] = sorted(payload.keys())[:20]
                        summary["attempts"].append(form_summary)
                        cb = _callback_url_from_response_info_direct(info_form)
                        if cb:
                            return cb, summary
                        form_follow = str(info_form.get("location") or info_form.get("final_url") or "").strip()
                        if form_follow.startswith("/"):
                            form_follow = f"{auth_base}{form_follow}"
                        if form_follow and form_follow != form_action:
                            r_follow = registrar.session.get(form_follow, headers=headers, verify=False, timeout=12, allow_redirects=True)
                            info_follow = {"ok": 200 <= int(r_follow.status_code or 0) < 400, "status": int(r_follow.status_code or 0), "json": _response_json(r_follow), "text": str(getattr(r_follow, "text", "") or "")[:2000], "location": str(r_follow.headers.get("Location") or ""), "final_url": str(getattr(r_follow, "url", form_follow) or form_follow)}
                            follow_summary = _safe_response_summary(info_follow)
                            follow_summary["method"] = "form_follow"
                            follow_summary["target_prefix"] = form_follow[:160]
                            summary["attempts"].append(follow_summary)
                            cb = _callback_url_from_response_info_direct(info_follow)
                            if cb:
                                return cb, summary
                    except Exception as exc:
                        summary["attempts"].append({"method": "form_post", "target_prefix": str(form_action)[:160], "error": str(exc)})

                for follow in [body.get("continue_url") if isinstance(body, dict) else "", body.get("redirect_url") if isinstance(body, dict) else "", loc, final]:
                    follow = str(follow or "").strip()
                    if not follow or follow == target:
                        continue
                    if follow.startswith("/"):
                        follow = f"{auth_base}{follow}"
                    try:
                        r2 = registrar.session.get(follow, headers=headers, verify=False, timeout=8, allow_redirects=True)
                        info2 = {"ok": 200 <= int(r2.status_code or 0) < 400, "status": int(r2.status_code or 0), "json": _response_json(r2), "text": str(getattr(r2, "text", "") or "")[:2000], "location": str(r2.headers.get("Location") or ""), "final_url": str(getattr(r2, "url", follow) or follow)}
                        summary["attempts"].append({**_safe_response_summary(info2), "method": "follow", "target_prefix": follow[:160]})
                        cb = _callback_url_from_response_info_direct(info2)
                        if cb:
                            return cb, summary
                    except Exception as exc:
                        summary["attempts"].append({"method": "follow", "target_prefix": follow[:160], "error": str(exc)})
            except Exception as exc:
                summary["attempts"].append({"method": method, "target_prefix": target[:160], "error": str(exc)})
    return "", summary

def _login_username_payload(identifier: str) -> dict[str, str]:
    value = str(identifier or "").strip()
    normalized_phone = re.sub(r"\s+", "", value)
    if re.fullmatch(r"\+?[0-9]{6,20}", normalized_phone):
        return {"kind": "phone_number", "value": normalized_phone}
    return {"kind": "email", "value": value}


def _attempt_password_login(registrar: PlatformRegistrar, email: str, password: str) -> dict[str, Any]:
    state = str(registrar.last_authorize.get("state") or "").strip()
    referer_path = f"/log-in/password?state={state}" if state else "/log-in/password"
    attempts: list[dict[str, Any]] = []
    auth_failure: dict[str, Any] | None = None
    username_payload = _login_username_payload(email)

    direct_attempts = [
        (f"{auth_base}/api/accounts/password/verify", {"password": password}, "auth"),
        (f"{auth_base}/api/accounts/password/verify", {"username": email, "password": password}, "auth"),
        (f"{auth_base}/api/accounts/password/verify", {"username": username_payload, "password": password}, "auth"),
        (f"{auth_base}/api/accounts/password/verify", {"password": password}, "password_verify"),
        (f"{auth_base}/api/accounts/password/verify", {"username": email, "password": password}, "password_verify"),
        (f"{auth_base}/api/accounts/password/verify", {"username": username_payload, "password": password}, "password_verify"),
        (f"{auth_base}/api/auth/password", {"password": password}, "auth"),
    ]
    for url, payload, sentinel_flow in direct_attempts:
        headers = _har_browser_fetch_headers(referer_path)
        try:
            resp = registrar.session.post(url, json=payload, headers=headers, verify=False, timeout=30, allow_redirects=False)
            body = _response_json(resp)
            status = int(resp.status_code or 0)
            location = str(resp.headers.get("Location") or "")
            final_url = str(getattr(resp, "url", url) or url)
            ok = 200 <= status < 300 or bool(_first_callbackish_url(location, body.get("continue_url") if isinstance(body, dict) else "", final_url))
            attempt = {
                "url": url,
                "body_mode": "direct_json",
                "payload_keys": sorted(payload.keys()),
                "ok": ok,
                "status": status,
                "json": body,
                "text": resp.text[:2000],
                "location": location,
                "final_url": final_url,
                "referer": headers.get("referer") or "",
                "sentinel_token_present": bool(headers.get("OpenAI-Sentinel-Token")),
                "sentinel_error": headers.get("x-openai-sentinel-error") or "",
            }
        except Exception as exc:
            attempt = {"url": url, "body_mode": "direct_json", "payload_keys": sorted(payload.keys()), "ok": False, "status": 0, "json": {}, "text": "", "location": "", "final_url": url, "error": str(exc)}
        attempts.append(attempt)
        if attempt.get("ok"):
            return {**attempt, "attempts": attempts, "authorize": registrar.last_authorize}
        if int(attempt.get("status") or 0) == 401 and auth_failure is None:
            auth_failure = attempt
        if int(attempt.get("status") or 0) in (403, 422):
            return {**attempt, "attempts": attempts, "authorize": registrar.last_authorize}

    remix_payloads = [
        {"origin_page_type": "login_password", "data": {"intent": "validate", "username": username_payload, "password": password}},
    ]
    candidates = [
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "json"),
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "form"),
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "json"),
        (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "form"),
        (f"{auth_base}/api/accounts", "json"),
    ]
    for payload in remix_payloads:
        info = registrar._post_accounts_payload(payload, referer_path, candidates=candidates)
        attempts.extend(info.get("attempts") or [info])
        if info.get("ok"):
            return {**info, "attempts": attempts, "authorize": registrar.last_authorize}
        if int(info.get("status") or 0) in (403, 422):
            return {**info, "attempts": attempts, "authorize": registrar.last_authorize}
    last = attempts[-1] if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "error": "no_login_attempts"}
    if auth_failure is not None:
        return {**auth_failure, "attempts": attempts, "authorize": registrar.last_authorize}
    return {**last, "attempts": attempts, "authorize": registrar.last_authorize}


def _now_text() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _mark_reauthorize_failed(account: dict[str, Any], message: str, *, mailbox: dict[str, Any] | None = None) -> dict[str, Any]:
    account["status"] = "auth_failed"
    account["last_error"] = str(message or "reauthorize_failed")
    if mailbox is not None:
        account["mailbox"] = mailbox
    return upsert_account(account)


def _mark_reauthorize_authorized(account: dict[str, Any], *, callback_url: str = "", mailbox: dict[str, Any] | None = None) -> dict[str, Any]:
    now = _now_text()
    account["status"] = "authorized"
    account["last_error"] = ""
    account["last_auth_at"] = now
    account["last_sub2api_submit_at"] = now
    if callback_url:
        account["callback_url"] = str(callback_url)
    if mailbox is not None:
        account["mailbox"] = mailbox
    account["source"] = str(account.get("source") or "manual")
    return upsert_account(account)


def _registration_reauth_blocker(account: dict[str, Any], mailbox: dict[str, Any]) -> str:
    source_error = str(mailbox.get("source_error") or "").strip()
    has_auth_artifact = any(str(account.get(key) or "").strip() for key in ("callback_url", "access_token", "refresh_token", "id_token"))
    if source_error == "registration_disallowed" and not has_auth_artifact:
        return "account_not_created_registration_disallowed"
    return ""


def _mark_unusable_reauthorize_source(account: dict[str, Any], message: str, *, mailbox: dict[str, Any]) -> dict[str, Any]:
    account["status"] = "auth_failed"
    account["last_error"] = str(message or "reauthorize_blocked")
    account["usable_for_reauth"] = False
    account["mailbox"] = mailbox
    return upsert_account(account)


def _direct_exchange_local_callback(
    config: Sub2APIOAuthFlowConfig,
    prepared: Any,
    callback_url: str,
    *,
    email: str,
    password: str,
    mailbox: dict[str, Any],
) -> RegistrationResult:
    params = extract_oauth_callback_params_from_url(callback_url) or {}
    code = str(params.get("code") or "").strip()
    if not code:
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=callback_url, error="local_callback_code_missing")
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": prepared.redirect_uri,
        "client_id": prepared.client_id,
        "code_verifier": prepared.code_verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
    response = None
    data: dict[str, Any] = {}
    registrar = PlatformRegistrar(str(getattr(config, "proxy", "") or "").strip())
    try:
        response = registrar.session.post(
            f"{auth_base}/oauth/token",
            headers=headers,
            data=payload,
            verify=False,
            timeout=60,
        )
        data = _response_json(response)
    except Exception as exc:
        registrar.close()
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=callback_url, error=f"direct_oauth_token_failed:{exc or 'request_failed'}")
    finally:
        try:
            registrar.close()
        except Exception:
            pass
    if response is None:
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=callback_url, error="direct_oauth_token_failed:request_failed")
    if response.status_code != 200:
        detail = str(data.get("error") or data.get("error_description") or data.get("message") or "").strip() if isinstance(data, dict) else ""
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=callback_url, error=f"direct_oauth_token_http_{response.status_code}:{detail}")
    access_token = str(data.get("access_token") or "").strip()
    refresh_token = str(data.get("refresh_token") or "").strip()
    id_token = str(data.get("id_token") or "").strip()
    if not access_token or not refresh_token or not id_token:
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=callback_url, error="direct_oauth_token_missing_tokens")
    payload = _decode_jwt_payload(id_token) or _decode_jwt_payload(access_token) or {}
    return RegistrationResult(ok=True, email=str(payload.get("email") or email).strip(), password=password, access_token=access_token, refresh_token=refresh_token, id_token=id_token, mailbox=mailbox, callback_url=callback_url)


def _compact_consent_debug_summary(consent_summary: dict[str, Any] | None) -> dict[str, Any]:
    summary = consent_summary if isinstance(consent_summary, dict) else {}
    compact_attempts: list[dict[str, Any]] = []
    for attempt in (summary.get("attempts") or [])[:3]:
        if not isinstance(attempt, dict):
            continue
        compact: dict[str, Any] = {
            "method": attempt.get("method"),
            "matched": attempt.get("matched"),
            "status": attempt.get("status"),
            "page_type": attempt.get("page_type"),
            "target_prefix": str(attempt.get("target_prefix") or "")[:120],
            "final_url_prefix": str(attempt.get("final_url_prefix") or "")[:120],
            "location_prefix": str(attempt.get("location_prefix") or "")[:120],
            "json_keys": attempt.get("json_keys"),
            "text_markers": attempt.get("text_markers"),
        }
        steps: list[dict[str, Any]] = []
        for step in (attempt.get("steps") or [])[:5]:
            if not isinstance(step, dict):
                continue
            steps.append(
                {
                    "method": step.get("method"),
                    "source": step.get("source"),
                    "status": step.get("status"),
                    "content_type_prefix": step.get("content_type_prefix"),
                    "final_url_prefix": str(step.get("final_url_prefix") or "")[:120],
                    "location_prefix": str(step.get("location_prefix") or "")[:120],
                    "json_keys": step.get("json_keys"),
                    "text_markers": step.get("text_markers"),
                }
            )
        if steps:
            compact["steps"] = steps
        compact_attempts.append({k: v for k, v in compact.items() if v not in (None, "", [])})
    return {"url_prefix": str(summary.get("url_prefix") or "")[:120], "attempts": compact_attempts}


def _exchange_local_tokens_after_cpa(
    registrar: PlatformRegistrar,
    account: dict[str, Any],
    mailbox: dict[str, Any],
    *,
    email: str,
    password: str,
    wait_timeout: int = 60,
    wait_interval: int = 2,
    request_timeout: int = 30,
) -> RegistrationResult:
    _log_stage("CPA 回调提交后开始附加获取本地 token")
    local_config = Sub2APIOAuthFlowConfig(proxy=str(registrar.proxy or "").strip(), login_hint=str(email or "").strip())
    prepared = build_openai_oauth_authorize_url(local_config)
    session_device_id = str(registrar.device_id or prepared.device_id).strip()
    prepared.device_id = session_device_id
    parsed_authorize = urlparse(prepared.authorize_url)
    authorize_params = parse_qs(parsed_authorize.query, keep_blank_values=True)
    authorize_params["device_id"] = [session_device_id]
    authorize_params["login_hint"] = [str(email or "").strip()]
    authorize_params.pop("max_age", None)
    authorize_params.pop("prompt", None)
    prepared.authorize_url = urlunparse(parsed_authorize._replace(query=urlencode(authorize_params, doseq=True)))
    registrar.session.cookies.set("oai-did", session_device_id, domain=".auth.openai.com")
    registrar.session.cookies.set("oai-did", session_device_id, domain="auth.openai.com")
    response = registrar.session.get(prepared.authorize_url, headers=get_common_headers(), verify=False, timeout=30, allow_redirects=True)
    state = prepared.state
    final_url = str(getattr(response, "url", prepared.authorize_url) or prepared.authorize_url)
    authorize_info = {"ok": 200 <= int(getattr(response, "status_code", 0) or 0) < 400, "status": int(getattr(response, "status_code", 0) or 0), "json": _response_json(response), "text": str(getattr(response, "text", "") or "")[:2000], "location": str(getattr(response, "headers", {}).get("Location") or ""), "final_url": final_url}
    registrar.last_authorize = {
        "email": email,
        "state": prepared.state,
        "nonce": prepared.nonce,
        "code_verifier": prepared.code_verifier,
        "code_challenge": prepared.code_challenge,
        "external_authorize": False,
        "screen_hint": "login",
        "flow_kind": "login",
        "final_url": final_url,
        "status": str(getattr(response, "status_code", "") or ""),
    }
    _log_stage(f"本地 token 授权入口已打开：状态码={getattr(response, 'status_code', '') or '-'}，最终地址={_short_url(final_url)}")
    _log_stage(f"本地 token 授权入口摘要：{_response_brief(authorize_info)}")
    callback = final_url if extract_oauth_callback_params_from_url(final_url) else ""
    local_state = _registration_state_from_info(authorize_info)
    if not callback and str(local_state.get("kind") or "") == "password":
        _log_stage("本地 token 授权入口要求登录，先提交密码")
        password_info = _attempt_password_login(registrar, email, password)
        _log_stage(f"本地 token 密码登录结果：{_response_brief(password_info)}")
        callback = _resolve_callback_step(registrar, password_info, state, allow_state_resume=False)
        if not callback and not password_info.get("ok"):
            _log_stage("本地 token 密码登录失败，切换邮箱验证码")
            try:
                callback, validate_info, _ = _handle_email_otp_step(
                    registrar,
                    account,
                    mailbox,
                    state,
                    proxy=str(registrar.proxy or "").strip(),
                    wait_timeout=wait_timeout,
                    wait_interval=wait_interval,
                    request_timeout=request_timeout,
                )
                _log_stage(f"本地 token 邮箱验证码后回调解析结果：回调{_ready_text(callback)}")
                if not callback:
                    authorize_info = validate_info
            except Exception as exc:
                _log_stage(f"本地 token 邮箱验证码流程失败：{exc}")
        if not callback and password_info.get("ok"):
            consent_url = _first_step_continue_url(password_info)
            if consent_url:
                callback, consent_summary = _resolve_consent_callback_direct(registrar, consent_url, state)
                _log_stage(f"本地 token 密码登录后授权确认处理结果：回调{_ready_text(callback)}，尝试次数={len((consent_summary or {}).get('attempts') or [])}")
                if not callback:
                    _log_stage(f"本地 token 授权确认调试摘要：{_compact_consent_debug_summary(consent_summary)}")
    elif not callback and str(local_state.get("kind") or "") == "email_otp":
        _log_stage("本地 token 授权入口直接进入邮箱验证码")
        try:
            callback, validate_info, _ = _handle_email_otp_step(
                registrar,
                account,
                mailbox,
                state,
                proxy=str(registrar.proxy or "").strip(),
                wait_timeout=wait_timeout,
                wait_interval=wait_interval,
                request_timeout=request_timeout,
            )
            _log_stage(f"本地 token 邮箱验证码后回调解析结果：回调{_ready_text(callback)}")
            if not callback:
                authorize_info = validate_info
        except Exception as exc:
            _log_stage(f"本地 token 邮箱验证码流程失败：{exc}")
    if not callback:
        _log_stage("快速解析本地 token OAuth 回调")
        callback_target = _first_step_continue_url(authorize_info) or final_url
        callback = _resolve_oauth_callback(registrar, callback_target, state, max_steps=3, request_timeout=5, include_codex_consent=False)
        _log_stage(f"本地 token OAuth 回调解析结果：回调{_ready_text(callback)}")
    if not callback:
        _log_stage("处理 CPA 后的本地 token 授权确认页")
        consent_target = _first_step_continue_url(authorize_info) or final_url
        callback, consent_summary = _resolve_consent_callback_direct(registrar, consent_target, state)
        _log_stage(f"本地 token 授权确认处理结果：回调{_ready_text(callback)}，尝试次数={len((consent_summary or {}).get('attempts') or [])}")
        if not callback:
            _log_stage(f"本地 token 授权确认调试摘要：{_compact_consent_debug_summary(consent_summary)}")
    if not callback:
        _log_stage("CPA 后未拿到本地 token 回调")
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=final_url, error="local_callback_not_reached_after_cpa")
    result = _direct_exchange_local_callback(local_config, prepared, callback, email=email, password=password, mailbox=mailbox)
    if not result.ok:
        _log_stage(f"本地 token 直接换取失败：{result.error or '-'}")
        try:
            result = exchange_callback_code(local_config, prepared, callback)
        except Exception as exc:
            _log_stage(f"本地 token 主流程换取失败：{exc}")
    if not result.ok:
        _log_stage(f"主流程失败后再次尝试直接换取本地 token：{result.error or '-'}")
        direct_result = _direct_exchange_local_callback(local_config, prepared, callback, email=email, password=password, mailbox=mailbox)
        if direct_result.ok or not result.error:
            result = direct_result
    _log_stage(f"本地 token 换取结果：成功={_zh_bool(result.ok)}，错误={result.error or '-'}")
    result.email = result.email or email
    result.password = password
    result.mailbox = mailbox
    return result


def _finalize_cpa_submit_with_optional_local_tokens(
    registrar: PlatformRegistrar,
    account: dict[str, Any],
    mailbox: dict[str, Any],
    *,
    email: str,
    password: str,
    cpa_callback_url: str,
    cpa_result: dict[str, Any],
    debug: dict[str, Any],
) -> ReauthorizeAutoOutcome:
    if not bool(cpa_result.get("ok")):
        updated = _mark_reauthorize_failed(account, str(cpa_result.get("message") or "cpa_callback_submit_failed"), mailbox=mailbox)
        return ReauthorizeAutoOutcome(ok=False, message=str(cpa_result.get("message") or "cpa_callback_submit_failed"), account=updated, callback_url=str(cpa_callback_url), codex2api_import_submit_ok=False, codex2api_import_submit_message=str(cpa_result.get("message") or ""), debug=debug)
    _log_stage("CPA 回调已提交，主任务成功")
    _log_stage("仅提交 CPA 授权，跳过本地 token / sub2api 后续链路")
    mailbox["_cpa_submit_ok"] = True
    mailbox["_cpa_submit_message"] = str(cpa_result.get("message") or "CPA callback submitted")
    debug["local_token_after_cpa"] = {"skipped": True, "reason": "cpa_only"}
    updated = _mark_reauthorize_authorized(account, callback_url=str(cpa_callback_url), mailbox=mailbox)
    return ReauthorizeAutoOutcome(ok=True, message=str(cpa_result.get("message") or "CPA callback submitted"), account=updated, callback_url=str(cpa_callback_url), codex2api_import_submit_ok=True, codex2api_import_submit_message=str(cpa_result.get("message") or ""), debug=debug)


def _save_result_and_import_codex2api(
    account: dict[str, Any],
    result: RegistrationResult,
    *,
    source: str,
    codex2api_url: str = "",
    codex2api_admin_key: str = "",
    codex2api_proxy_url: str = "",
) -> ReauthorizeFinishOutcome:
    if not result.ok:
        updated = _mark_reauthorize_failed(account, str(result.error or "reauthorize_exchange_failed"))
        return ReauthorizeFinishOutcome(ok=False, message=account["last_error"], account=updated, callback_url=str(result.callback_url or ""))

    email = str(account.get("email") or result.email or "").strip()
    result.email = result.email or email
    result.password = str(account.get("password") or "")
    result.mailbox = account.get("mailbox") if isinstance(account.get("mailbox"), dict) else {}

    codex2api_result: dict[str, Any] = {}
    if str(codex2api_url or "").strip() and str(codex2api_admin_key or "").strip():
        try:
            codex2api_result = import_result_to_codex2api(
                result,
                codex2api_url=codex2api_url,
                admin_key=codex2api_admin_key,
                account_name=email,
                proxy_url=str(codex2api_proxy_url or "").strip(),
            )
        except Exception as exc:
            codex2api_result = {"ok": False, "message": str(exc or "codex2api_import_failed")}

    updated = save_registration_result_to_account(result, source=source, account_id=str(account.get("id") or ""))
    codex2api_ok = bool(codex2api_result.get("ok")) if codex2api_result else False
    overall_ok = codex2api_ok if codex2api_result else True
    if overall_ok:
        updated = _mark_reauthorize_authorized(updated, callback_url=str(result.callback_url or ""))
    else:
        updated = _mark_reauthorize_failed(updated, str(codex2api_result.get("message") or "codex2api_import_failed"))

    return ReauthorizeFinishOutcome(
        ok=overall_ok,
        message="reauthorize_finished" if overall_ok else str(codex2api_result.get("message") or "codex2api_import_failed"),
        account=updated,
        callback_url=str(result.callback_url or ""),
        codex2api_import_submit_ok=codex2api_ok,
        codex2api_import_submit_message=str(codex2api_result.get("message") or "") if codex2api_result else "",
    )


def start_account_reauthorize(account_id: str, *, proxy: str = "") -> ReauthorizeStartOutcome:
    account = get_account(account_id)
    if not account:
        return ReauthorizeStartOutcome(ok=False, message="account_not_found")
    email = str(account.get("email") or "").strip()
    password = str(account.get("password") or "")
    mailbox = account.get("mailbox") if isinstance(account.get("mailbox"), dict) else {}
    if not email or not password:
        return ReauthorizeStartOutcome(ok=False, message="account_email_or_password_missing", account=account)
    cfg = Sub2APIOAuthFlowConfig(login_hint=email, proxy=str(proxy or "").strip())
    prepared = build_openai_oauth_authorize_url(cfg)
    account["status"] = "authorizing"
    account["last_error"] = ""
    updated = upsert_account(account)
    return ReauthorizeStartOutcome(ok=True, message="reauthorize_authorize_ready", account=updated, authorize_url=str(prepared.authorize_url or ""), state=str(prepared.state or ""), nonce=str(prepared.nonce or ""), redirect_uri=str(prepared.redirect_uri or ""), client_id=str(prepared.client_id or ""), code_verifier=str(prepared.code_verifier or ""), bind_email=str(mailbox.get("bind_email") or email))


def finish_account_reauthorize(
    account_id: str,
    *,
    callback_or_code: str,
    code_verifier: str,
    state: str,
    redirect_uri: str,
    client_id: str,
    codex2api_url: str = "",
    codex2api_admin_key: str = "",
    codex2api_proxy_url: str = "",
    proxy: str = "",
) -> ReauthorizeFinishOutcome:
    account = get_account(account_id)
    if not account:
        return ReauthorizeFinishOutcome(ok=False, message="account_not_found")
    email = str(account.get("email") or "").strip()
    cfg = Sub2APIOAuthFlowConfig(login_hint=email, redirect_uri=str(redirect_uri or "").strip() or "http://localhost:1455/auth/callback", proxy=str(proxy or "").strip())
    prepared = build_openai_oauth_authorize_url(cfg)
    prepared.state = str(state or prepared.state)
    prepared.code_verifier = str(code_verifier or prepared.code_verifier)
    prepared.client_id = str(client_id or prepared.client_id)
    prepared.redirect_uri = str(redirect_uri or prepared.redirect_uri)
    try:
        result = exchange_callback_code(cfg, prepared, callback_or_code)
    except Exception as exc:
        result = RegistrationResult(ok=False, email=email, error=str(exc or "reauthorize_exchange_failed"))
    return _save_result_and_import_codex2api(account, result, source="reauthorize", codex2api_url=codex2api_url, codex2api_admin_key=codex2api_admin_key, codex2api_proxy_url=codex2api_proxy_url)


def auto_reauthorize_account_with_email_otp(
    account_id: str,
    *,
    codex2api_url: str = "",
    codex2api_admin_key: str = "",
    codex2api_proxy_url: str = "",
    proxy: str = "",
    wait_timeout: int = 60,
    wait_interval: int = 2,
    request_timeout: int = 30,
    sms_provider: str = "",
    sms_api_key: str = "",
    hero_sms_api_key: str = "",
    smsbower_api_key: str = "",
    hero_sms_base_url: str = "",
    smsbower_base_url: str = "",
    hero_sms_country: str = "",
    hero_sms_service: str = "",
    hero_sms_min_price: float | str = 0.0,
    hero_sms_max_price: float | str = 0.0,
    hero_sms_wait_timeout: int = 180,
    hero_sms_wait_interval: int = 5,
    hero_sms_auto_retry: bool = False,
    hero_sms_retry_count: int = 3,
    sms_wait_timeout: int | None = None,
    sms_wait_interval: int | None = None,
    sms_resend_after_seconds: int | None = None,
    sms_timeout_after_resend_seconds: int | None = None,
    sms_release_after_seconds: int | None = None,
    sms_auto_retry: bool | None = None,
    sms_retry_count: int | None = None,
    allow_phone_verification: bool = False,
) -> ReauthorizeAutoOutcome:
    account = get_account(account_id)
    if not account:
        return ReauthorizeAutoOutcome(ok=False, message="account_not_found")
    email = str(account.get("email") or "").strip()
    password = str(account.get("password") or "")
    mailbox = account.get("mailbox") if isinstance(account.get("mailbox"), dict) else {}
    if not email or not password:
        return ReauthorizeAutoOutcome(ok=False, message="account_email_or_password_missing", account=account)
    if not mailbox or not str(mailbox.get("provider") or "").strip():
        return ReauthorizeAutoOutcome(ok=False, message="mailbox_missing", account=account)
    if not str(codex2api_url or "").strip() or not str(codex2api_admin_key or "").strip():
        return ReauthorizeAutoOutcome(ok=False, message="cpa_config_missing", account=account)
    account["status"] = "authorizing"
    account["last_error"] = ""
    account = upsert_account(account)

    debug: dict[str, Any] = {}
    registrar_proxy = str(proxy or "").strip()
    sms_config = _build_reauthorize_sms_config(
        sms_provider=sms_provider,
        sms_api_key=sms_api_key,
        hero_sms_api_key=hero_sms_api_key,
        smsbower_api_key=smsbower_api_key,
        hero_sms_base_url=hero_sms_base_url,
        smsbower_base_url=smsbower_base_url,
        hero_sms_country=hero_sms_country,
        hero_sms_service=hero_sms_service,
        hero_sms_min_price=hero_sms_min_price,
        hero_sms_max_price=hero_sms_max_price,
        sms_wait_timeout=sms_wait_timeout if sms_wait_timeout not in (None, "") else hero_sms_wait_timeout,
        sms_wait_interval=sms_wait_interval if sms_wait_interval not in (None, "") else hero_sms_wait_interval,
        sms_resend_after_seconds=sms_resend_after_seconds if sms_resend_after_seconds not in (None, "") else 30,
        sms_timeout_after_resend_seconds=sms_timeout_after_resend_seconds if sms_timeout_after_resend_seconds not in (None, "") else 60,
        sms_release_after_seconds=sms_release_after_seconds if sms_release_after_seconds not in (None, "") else 120,
        sms_auto_retry=sms_auto_retry if sms_auto_retry is not None else hero_sms_auto_retry,
        sms_retry_count=sms_retry_count if sms_retry_count not in (None, "") else hero_sms_retry_count,
    )
    sms_retry_count = sms_config.max_retry_count if sms_config.auto_retry else 1
    _log_stage(f"OpenAI 代理：{_proxy_text(registrar_proxy)}")
    registrar = PlatformRegistrar(registrar_proxy)
    try:
        _log_stage("生成 CPA OAuth 授权地址")
        oauth_info = _start_cpa_oauth(
            cpa_url=codex2api_url,
            cpa_management_key=codex2api_admin_key,
            email=email,
            proxy_url=codex2api_proxy_url,
        )
        _log_stage(f"CPA 账号代理：{_proxy_text(codex2api_proxy_url)}")
        debug["cpa_oauth"] = oauth_info
        _log_stage("CPA OAuth 授权地址已生成")
        _log_stage("打开 OpenAI 授权页")
        mailbox["_code_after_ts"] = int(time.time() * 1000) - 5000
        login_identifier = _login_identifier_for_account(account, mailbox, email)
        if login_identifier != email:
            _log_stage(f"当前账号使用手机号登录：{login_identifier}")
        info = registrar.start_authorize(email=login_identifier, authorize_url=oauth_info["authorize_url"], screen_hint="login")
        debug["start"] = info
        _log_stage(f"OpenAI 授权页打开结果：{_response_brief(info)}")
        _log_stage("建立登录会话")
        establish_info = registrar.establish_signup_session()
        debug["establish"] = establish_info
        _log_stage(f"登录会话建立结果：成功={_zh_bool(establish_info.get('ok'))}，流程类型={establish_info.get('flow_kind') or '-'}")
        if not establish_info.get("ok"):
            updated = _mark_reauthorize_failed(account, "session_establishment_failed")
            return ReauthorizeAutoOutcome(ok=False, message="session_establishment_failed", account=updated, debug=debug)

        if str(mailbox.get("bind_email") or "").strip() or "@" in email:
            mailbox["bind_email"] = str(mailbox.get("bind_email") or email)
        state = str(oauth_info.get("state") or registrar.last_authorize.get("state") or "").strip()
        start_state = _registration_state_from_info({"final_url": str(info.get("final_url") or ""), "json": {}, "text": ""})
        _log_stage(f"当前授权页：类型={start_state.get('kind') or '-'}，地址={_short_url(start_state.get('url') or info.get('final_url'))}")
        if str(start_state.get("kind") or "") == "email_otp":
            _log_stage("授权页直接进入邮箱验证码，先校验验证码")
            try:
                callback_or_code, validate_info, email_otp_debug = _handle_email_otp_step(
                    registrar,
                    account,
                    mailbox,
                    state,
                    proxy=proxy,
                    wait_timeout=wait_timeout,
                    wait_interval=wait_interval,
                    request_timeout=request_timeout,
                )
            except Exception as exc:
                updated = _mark_reauthorize_failed(account, str(exc), mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message=str(exc), account=updated, debug=debug)
            debug["pre_password_email_otp"] = email_otp_debug
            _log_stage(f"授权确认回调结果：回调{_ready_text(callback_or_code)}")
            if callback_or_code:
                cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
                return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
            _log_stage("邮箱验证码已通过但未拿到回调，继续走密码登录")
        elif str(start_state.get("kind") or "") == "password":
            _log_stage("授权页进入密码页，准备提交密码")
        elif str(start_state.get("kind") or "") == "callback":
            callback_or_code = str(start_state.get("url") or "")
            cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
            return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
        elif str(start_state.get("kind") or "") not in {"continue", "unknown", ""}:
            updated = _mark_reauthorize_failed(account, f"unsupported_reauthorize_page:{start_state.get('kind')}", mailbox=mailbox)
            return ReauthorizeAutoOutcome(ok=False, message=updated.get("last_error") or "unsupported_reauthorize_page", account=updated, debug=debug)

        _log_stage("提交密码登录")
        password_info = _attempt_password_login(registrar, login_identifier, password)
        debug["login_password"] = password_info
        _log_stage(f"密码登录结果：{_response_brief(password_info)}")
        if not password_info.get("ok"):
            password_error = f"login_password_{password_info.get('status') or 0}"
            if _login_username_payload(login_identifier).get("kind") == "phone_number":
                message = f"{password_error}:phone_password_login_failed"
                updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
            _log_stage(f"密码登录失败，切换为邮箱验证码登录：原因={password_error}")
            try:
                callback_or_code, validate_info, email_otp_debug = _handle_email_otp_step(
                    registrar,
                    account,
                    mailbox,
                    state,
                    proxy=proxy,
                    wait_timeout=wait_timeout,
                    wait_interval=wait_interval,
                    request_timeout=request_timeout,
                )
            except Exception as exc:
                message = f"{password_error}; email_otp_fallback_failed:{exc}"
                updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
            debug["password_fallback_email_otp"] = email_otp_debug
            phone_required_after_email_otp = _step_requires_phone_verification(validate_info)
            if phone_required_after_email_otp:
                _log_phone_required_after_email_otp(validate_info, "密码登录失败后的邮箱验证码登录")
                return _fail_manual_phone_verification_required(account, mailbox, debug, validate_info)
            _log_stage(f"授权确认回调结果：回调{_ready_text(callback_or_code)}")
            if not callback_or_code:
                updated = _mark_reauthorize_failed(account, "missing_callback_after_auth", mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message="missing_callback_after_auth", account=updated, debug=debug)
            cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
            return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)

        phone_required_after_password = _step_requires_phone_verification(password_info)
        if phone_required_after_password:
            _log_stage(f"密码登录后 OpenAI 要求手机二次验证：{_phone_verification_page_brief(password_info)}")
            return _fail_manual_phone_verification_required(account, mailbox, debug, password_info)
        callback_or_code = ""

        _log_stage("尝试解析密码登录后的 OAuth 回调")
        callback_or_code = callback_or_code or _resolve_callback_step(registrar, password_info, state, allow_state_resume=False)
        _log_stage(f"密码登录后回调解析结果：回调{_ready_text(callback_or_code)}")
        if not callback_or_code:
            password_step_state = _registration_state_from_info(
                {
                    "final_url": _first_step_continue_url(password_info),
                    "json": password_info.get("json") if isinstance(password_info.get("json"), dict) else {},
                    "text": str(password_info.get("text") or ""),
                }
            )
            if str(password_step_state.get("kind") or "") == "about_you":
                _log_stage("密码登录后进入 about-you，继续提交姓名/生日")
                about_you_bind_email = _bind_email_hint_for_account(account, mailbox, email)
                if not about_you_bind_email:
                    try:
                        about_you_bind_email, prepared_mailbox = _prepare_bind_mailbox(
                            _bind_mail_config_for_account(
                                account,
                                mailbox,
                                proxy=proxy,
                                wait_timeout=wait_timeout,
                                wait_interval=wait_interval,
                                request_timeout=request_timeout,
                            ),
                            "",
                        )
                        if prepared_mailbox:
                            mailbox.update(prepared_mailbox)
                        if about_you_bind_email:
                            mailbox["bind_email"] = about_you_bind_email
                            mailbox["email"] = about_you_bind_email
                            _log_stage(f"about-you 前已准备绑定邮箱：{about_you_bind_email}")
                    except Exception as exc:
                        debug["about_you_bind_email_prepare_error"] = str(exc)
                try:
                    callback_or_code, about_you_debug = _continue_with_optional_about_you(
                        registrar,
                        str(password_step_state.get("url") or _first_step_continue_url(password_info) or ""),
                        state,
                        bind_email=about_you_bind_email,
                    )
                    debug["about_you_after_password"] = about_you_debug
                except Exception as exc:
                    message = f"about_you_after_password_failed:{exc}"
                    updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                    return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                _log_stage(f"about-you 后回调解析结果：回调{_ready_text(callback_or_code)}")
                if not callback_or_code and about_you_debug.get("create_account_error_code") == "missing_email":
                    _log_stage("about-you 缺少邮箱，先绑定邮箱再继续")
                    try:
                        add_email_url, resolved_bind_email = _continue_with_optional_add_email(
                            registrar,
                            continue_url=str(about_you_debug.get("missing_email_continue_url") or f"{auth_base}/add-email"),
                            bind_email=_bind_email_hint_for_account(account, mailbox, email),
                            bind_mail_config=_bind_mail_config_for_account(
                                account,
                                mailbox,
                                proxy=proxy,
                                wait_timeout=wait_timeout,
                                wait_interval=wait_interval,
                                request_timeout=request_timeout,
                            ),
                        )
                    except Exception as exc:
                        message = f"bind_email_before_about_you_retry_failed:{exc}"
                        updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                        return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                    if resolved_bind_email:
                        mailbox["bind_email"] = resolved_bind_email
                        mailbox["email"] = resolved_bind_email
                    debug["add_email_before_about_you_retry"] = {"url": str(add_email_url or ""), "bind_email": str(resolved_bind_email or "")}
                    if extract_oauth_callback_params_from_url(add_email_url):
                        callback_or_code = str(add_email_url)
                    if not callback_or_code:
                        callback_or_code, about_you_retry_debug = _continue_with_optional_about_you(
                            registrar,
                            str(add_email_url or f"{auth_base}/about-you"),
                            state,
                        )
                        debug["about_you_after_email_bind"] = about_you_retry_debug
                        _log_stage(f"绑定邮箱后 about-you 回调解析结果：回调{_ready_text(callback_or_code)}")
                if not callback_or_code:
                    about_you_next_url = str(about_you_debug.get("next_url") or "").strip()
                    about_you_next_state = _registration_state_from_info({"final_url": about_you_next_url, "json": {}, "text": ""})
                    if str(about_you_next_state.get("kind") or "") == "email_otp":
                        _log_stage("about-you 后进入邮箱验证码，开始校验")
                        try:
                            callback_or_code, validate_info, email_otp_debug = _handle_email_otp_step(
                                registrar,
                                account,
                                mailbox,
                                state,
                                proxy=proxy,
                                wait_timeout=wait_timeout,
                                wait_interval=wait_interval,
                                request_timeout=request_timeout,
                            )
                        except Exception as exc:
                            message = f"email_otp_after_about_you_failed:{exc}"
                            updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                            return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                        debug["email_otp_after_about_you"] = email_otp_debug
                        phone_required_after_email_otp = _step_requires_phone_verification(validate_info)
                        if phone_required_after_email_otp:
                            _log_phone_required_after_email_otp(validate_info, "about-you 后的邮箱验证码")
                            return _fail_manual_phone_verification_required(account, mailbox, debug, validate_info)
                if callback_or_code:
                    cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
                    return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
            if str(password_step_state.get("kind") or "") == "add_email":
                _log_stage("密码登录后要求绑定邮箱")
                try:
                    add_email_url, resolved_bind_email = _continue_with_optional_add_email(
                        registrar,
                        continue_url=str(password_step_state.get("url") or _first_step_continue_url(password_info) or ""),
                        bind_email=_bind_email_hint_for_account(account, mailbox, email),
                        bind_mail_config=_bind_mail_config_for_account(
                            account,
                            mailbox,
                            proxy=proxy,
                            wait_timeout=wait_timeout,
                            wait_interval=wait_interval,
                            request_timeout=request_timeout,
                        ),
                    )
                except Exception as exc:
                    message = f"bind_email_after_password_failed:{exc}"
                    updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                    return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                if resolved_bind_email:
                    mailbox["bind_email"] = resolved_bind_email
                    mailbox["email"] = resolved_bind_email
                debug["add_email_after_password"] = {"url": str(add_email_url or ""), "bind_email": str(resolved_bind_email or "")}
                _log_stage(f"绑定邮箱流程结果：地址={_short_url(add_email_url)}")
                if extract_oauth_callback_params_from_url(add_email_url):
                    callback_or_code = str(add_email_url)
                else:
                    add_email_state = _registration_state_from_info({"final_url": str(add_email_url or ""), "json": {}, "text": ""})
                    if str(add_email_state.get("kind") or "") == "email_otp":
                        _log_stage("绑定邮箱后进入邮箱验证码，开始校验")
                        try:
                            callback_or_code, validate_info, email_otp_debug = _handle_email_otp_step(
                                registrar,
                                account,
                                mailbox,
                                state,
                                proxy=proxy,
                                wait_timeout=wait_timeout,
                                wait_interval=wait_interval,
                                request_timeout=request_timeout,
                            )
                        except Exception as exc:
                            message = f"email_otp_after_bind_email_failed:{exc}"
                            updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                            return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                        debug["email_otp_after_add_email"] = email_otp_debug
                        phone_required_after_email_otp = _step_requires_phone_verification(validate_info)
                        if phone_required_after_email_otp:
                            _log_phone_required_after_email_otp(validate_info, "绑定邮箱后的邮箱验证码登录")
                            return _fail_manual_phone_verification_required(account, mailbox, debug, validate_info)
                    if not callback_or_code:
                        callback_or_code = _resolve_callback_step(
                            registrar,
                            {"ok": True, "status": 200, "json": {"continue_url": str(add_email_url or "")}, "final_url": str(add_email_url or ""), "text": ""},
                            state,
                            allow_state_resume=True,
                        )
                _log_stage(f"绑定邮箱后回调解析结果：回调{_ready_text(callback_or_code)}")
                if callback_or_code:
                    cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
                    return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
            elif str(password_step_state.get("kind") or "") == "email_otp":
                _log_stage("密码登录后进入邮箱验证码，开始校验")
                try:
                    callback_or_code, validate_info, email_otp_debug = _handle_email_otp_step(
                        registrar,
                        account,
                        mailbox,
                        state,
                        proxy=proxy,
                        wait_timeout=wait_timeout,
                        wait_interval=wait_interval,
                        request_timeout=request_timeout,
                    )
                except Exception as exc:
                    message = f"email_otp_after_password_failed:{exc}"
                    updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                    return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                debug["email_otp_after_password"] = email_otp_debug
                phone_required_after_email_otp = _step_requires_phone_verification(validate_info)
                if phone_required_after_email_otp:
                    _log_phone_required_after_email_otp(validate_info, "密码页后的邮箱验证码登录")
                    return _fail_manual_phone_verification_required(account, mailbox, debug, validate_info)
                email_otp_state = _registration_state_from_info(validate_info)
                if str(email_otp_state.get("kind") or "") == "about_you":
                    _log_stage("邮箱验证码后进入 about-you，继续提交姓名/生日")
                    try:
                        callback_or_code, about_you_debug = _continue_with_optional_about_you(
                            registrar,
                            str(email_otp_state.get("url") or _first_step_continue_url(validate_info) or ""),
                            state,
                        )
                        debug["about_you_after_email_otp"] = about_you_debug
                    except Exception as exc:
                        message = f"about_you_after_email_otp_failed:{exc}"
                        updated = _mark_reauthorize_failed(account, message, mailbox=mailbox)
                        return ReauthorizeAutoOutcome(ok=False, message=message, account=updated, debug=debug)
                elif str(email_otp_state.get("kind") or "") == "add_email":
                    _log_stage("邮箱验证码后要求绑定邮箱，停止重复发送邮箱验证码")
                    updated = _mark_reauthorize_failed(account, "missing_callback_after_auth", mailbox=mailbox)
                    return ReauthorizeAutoOutcome(ok=False, message="missing_callback_after_auth", account=updated, debug=debug)
                _log_stage(f"密码页邮箱验证码后回调解析结果：回调{_ready_text(callback_or_code)}")
                if callback_or_code:
                    cpa_result = _submit_callback_to_cpa(callback_or_code, cpa_url=codex2api_url, cpa_management_key=codex2api_admin_key, expected_state=oauth_info.get("state") or "")
                    return _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
        if phone_required_after_password and not callback_or_code:
            updated = _mark_reauthorize_failed(account, "missing_callback_after_phone_verification", mailbox=mailbox)
            return ReauthorizeAutoOutcome(ok=False, message="missing_callback_after_phone_verification", account=updated, debug=debug)
        code = ""
        if not callback_or_code:
            password_page = (password_info.get("json") or {}).get("page") if isinstance(password_info.get("json"), dict) else {}
            state = str(oauth_info.get("state") or registrar.last_authorize.get("state") or "").strip()
            if isinstance(password_page, dict) and str(password_page.get("type") or "") == "email_otp_verification":
                otp_info = {"ok": True, "status": 0, "skipped": True, "reason": "password_verify_entered_email_otp_verification"}
            else:
                _log_stage("发送登录邮箱验证码")
                otp_info = _send_login_otp(registrar, state)
            debug["send_otp"] = otp_info
            _log_stage(f"登录邮箱验证码发送结果：{_response_brief(otp_info)}")
            if not otp_info.get("ok"):
                updated = _mark_reauthorize_failed(account, f"send_otp_{otp_info.get('status') or 0}", mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message=account["last_error"], account=updated, debug=debug)
            _log_stage("等待邮箱验证码")
            code = str(
                wait_for_code(
                    _mail_wait_config_for_account(
                        account,
                        mailbox,
                        proxy=proxy,
                        wait_timeout=wait_timeout,
                        wait_interval=wait_interval,
                        request_timeout=request_timeout,
                    ),
                    mailbox,
                )
                or ""
            ).strip()
            _log_stage(f"邮箱验证码接收结果：{'已收到' if code else '等待超时'}")
            if not code:
                updated = _mark_reauthorize_failed(account, "wait_for_code_timeout", mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message="wait_for_code_timeout", account=updated, debug=debug)
            _log_stage("提交并校验邮箱验证码")
            validate_info = _validate_login_otp(registrar, state, code)
            debug["validate_otp"] = validate_info
            debug["validate_otp_summary"] = _safe_response_summary(validate_info)
            _log_stage(f"邮箱验证码校验结果：{_response_brief(validate_info)}")
            if not validate_info.get("ok"):
                updated = _mark_reauthorize_failed(account, f"validate_otp_{validate_info.get('status') or 0}", mailbox=mailbox)
                return ReauthorizeAutoOutcome(ok=False, message=account["last_error"], account=updated, code=code, debug=debug)
            phone_required_after_email_otp = _step_requires_phone_verification(validate_info)
            if phone_required_after_email_otp:
                _log_phone_required_after_email_otp(validate_info, "登录邮箱验证码")
                return _fail_manual_phone_verification_required(account, mailbox, debug, validate_info, code=code)
            _log_stage("尝试解析邮箱验证码后的 OAuth 回调")
            tried_direct_consent = False
            callback_or_code = callback_or_code or _resolve_callback_step(registrar, validate_info, state, allow_state_resume=False)
            if not callback_or_code:
                consent_url = str((validate_info.get("json") or {}).get("continue_url") or (((validate_info.get("json") or {}).get("page") or {}).get("continue_url")) or "").strip()
                if _is_consent_like_url(consent_url):
                    _log_stage(f"邮箱验证码通过，进入授权确认页：{_short_url(consent_url, 100)}")
                    tried_direct_consent = True
                    callback_or_code, consent_summary = _resolve_consent_callback_direct(registrar, consent_url, state)
                    debug["consent_direct_summary"] = consent_summary
                    _log_stage(f"授权确认页处理结果：回调{_ready_text(callback_or_code)}，尝试次数={len((consent_summary or {}).get('attempts') or [])}")
            if not callback_or_code and not tried_direct_consent:
                callback_or_code = _resolve_callback_step(registrar, validate_info, state, allow_state_resume=True)
            _log_stage(f"邮箱验证码后回调解析结果：回调{_ready_text(callback_or_code)}")

        if not callback_or_code:
            resume_summary = {}
            try:
                resume_url = f"{auth_base}/authorize/resume?state={state}" if state else f"{auth_base}/sign-in-with-chatgpt/codex/consent"
                resp = registrar.session.get(resume_url, headers={"accept": "application/json, text/html, */*", "referer": f"{auth_base}/log-in/email-verification?state={state}"}, verify=False, timeout=30, allow_redirects=False)
                resume_summary = _safe_response_summary({"ok": 200 <= int(resp.status_code or 0) < 400, "status": int(resp.status_code or 0), "json": _response_json(resp), "text": resp.text[:2000], "location": str(resp.headers.get("Location") or ""), "final_url": str(getattr(resp, "url", resume_url) or resume_url)})
                debug["resume_probe"] = resume_summary
                _log_stage(f"授权恢复探测摘要：{resume_summary}")
            except Exception as exc:
                debug["resume_probe"] = {"error": str(exc)}
                _log_stage(f"授权恢复探测失败：{exc}")
            updated = _mark_reauthorize_failed(account, "missing_callback_after_auth", mailbox=mailbox)
            return ReauthorizeAutoOutcome(ok=False, message="missing_callback_after_auth", account=updated, code=code, debug=debug)

        cb_params = extract_oauth_callback_params_from_url(str(callback_or_code)) or {}
        cb_code = str(cb_params.get("code") or "").strip()
        cb_state = str(cb_params.get("state") or "").strip()
        expected_state = str(oauth_info.get("state") or "").strip()
        debug["callback_summary"] = {
            "has_code": bool(cb_code),
            "code_len": len(cb_code),
            "state_matches": bool(cb_state and expected_state and cb_state == expected_state),
            "state_len": len(cb_state),
            "expected_state_len": len(expected_state),
            "url_prefix": str(callback_or_code)[:80],
        }
        _log_stage(f"OAuth 回调校验：包含授权码={_zh_bool(cb_code)}，授权码长度={len(cb_code)}，state 匹配={_zh_bool(cb_state and expected_state and cb_state == expected_state)}")
        _log_stage("提交 OAuth 回调到 CPA")
        cpa_result = _submit_callback_to_cpa(
            callback_or_code,
            cpa_url=codex2api_url,
            cpa_management_key=codex2api_admin_key,
            expected_state=oauth_info.get("state") or "",
        )
        _log_stage(f"CPA 回调提交结果：成功={_zh_bool(cpa_result.get('ok'))}")
        outcome = _finalize_cpa_submit_with_optional_local_tokens(registrar, account, mailbox, email=email, password=password, cpa_callback_url=str(callback_or_code), cpa_result=cpa_result, debug=debug)
        outcome.code = code
        return outcome
    except Exception as exc:
        updated = _mark_reauthorize_failed(account, str(exc or "reauthorize_failed"))
        return ReauthorizeAutoOutcome(ok=False, message=account["last_error"], account=updated, debug=debug)
    finally:
        try:
            registrar.close()
        except Exception:
            pass
