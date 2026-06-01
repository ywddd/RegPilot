from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import re
import threading
import time
from contextlib import nullcontext
from typing import Any

from .cli import load_config
from .config import DATA_DIR, LOG_DIR, RegisterConfig, ensure_dirs, parse_bool
from .job_runner import run_job as _run_job_impl
from .job_store import JobCancelledError, JobStore as _BaseJobStore
from .json_store import write_json_atomic
from .logging_utils import reset_log_context, set_log_context
from .register_core import environment_profile_context, prepare_environment_profile_from_payload, run_placeholder, save_result, summarize_environment_profile, PlatformRegistrar, _random_birthdate, _random_name, _random_password, _exchange_registered_account_tokens, _about_you_shape_log_summary, _accounts_error_code
from .oauth_token_flow import HERO_SMS_MAX_RETRY_COUNT, HERO_SMS_RELEASE_AFTER_SECONDS, HERO_SMS_RESEND_AFTER_SECONDS, _continue_with_optional_add_email, _load_continue_page, _probe_phone_signup_password_page, _resolve_oauth_callback, _save_partial_hero_phone_bind_result, _set_phone_flow_stage, _submit_about_you_form, acquire_hero_sms_phone, fetch_country_name_zh_map, fetch_hero_sms_countries, fetch_hero_sms_price_summary, fetch_hero_sms_quote_list, import_result_to_codex2api, poll_hero_sms_code, set_hero_sms_status
from .sms_provider_config import SMSBOWER_BASE_URL, build_sms_config_from_values, normalize_sms_provider, sms_api_key_from_values, sms_provider_from_values


WEBUI_CONFIG_PATH = DATA_DIR / "webui_config.json"
WEBUI_CONFIG_LAST_VALID_PATH = DATA_DIR / "webui_config.last_valid.json"


def _zh_task_error(message: Any) -> str:
    text = str(message or "").strip()
    exact = {
        "job_stopped_by_user": "任务已被手动停止",
        "registration_target_not_reached": "注册目标未达成",
        "missing_callback_after_auth": "授权完成后未拿到 OAuth 回调",
        "missing_callback_after_phone_verification": "手机二次验证后未拿到 OAuth 回调",
        "phone_verification_required_sms_key_missing": "需要手机二次验证，但未配置接码服务",
        "manual_phone_verification_required": "无法自动授权：需要人工完成手机二次验证",
        "wait_for_code_timeout": "等待验证码超时",
    }
    if text in exact:
        return exact[text]
    text = re.sub(r"login_password_(\d+)", r"密码登录失败（状态码=\1）", text)
    text = text.replace("account_not_created_registration_disallowed", "账号未创建：about-you 被上游拒绝")
    text = re.sub(r"send_otp_(\d+)", r"发送验证码失败（状态码=\1）", text)
    text = re.sub(r"validate_otp_(\d+)", r"验证码校验失败（状态码=\1）", text)
    return text or "-"


DEFAULT_HERO_COUNTRY_LABEL_BY_ID = {
    "6": "印度尼西亚",
    "52": "泰国",
    "187": "美国（实体）",
    "16": "英格兰",
    "43": "德国",
    "73": "法国",
    "10": "越南",
}


def _hero_country_label(country_id: str, eng_name: str = "") -> str:
    normalized_id = str(country_id or "").strip()
    if normalized_id in DEFAULT_HERO_COUNTRY_LABEL_BY_ID:
        return DEFAULT_HERO_COUNTRY_LABEL_BY_ID[normalized_id]
    normalized_eng = str(eng_name or "").strip()
    if normalized_eng:
        zh_map = fetch_country_name_zh_map()
        return str(zh_map.get(normalized_eng) or normalized_eng).strip()
    return f"国家 #{country_id}"
WEBUI_CONFIG_DEFAULTS: dict[str, dict[str, Any]] = {
    "logs": {
        "job_log_max_mb": 100,
    },
    "register": {
        "proxy": "",
        "env_random_enabled": False,
        "env_proxy_pool": "",
        "env_ua_pool": "",
        "env_accept_language_pool": "",
        "env_timezone_pool": "",
        "env_viewport_pool": "",
        "total": 1,
        "threads": 1,
        "default_password": "",
        "request_timeout": 30,
        "wait_timeout": 60,
        "wait_interval": 2,
        "mail_type": "cloudflare-temp-email",
        "icloud_email": "",
        "icloud_imap_user": "",
        "icloud_imap_password": "",
        "icloud_cookies_json": "",
        "icloud_cookies_path": "",
        "icloud_host": "icloud.com",
        "icloud_hme_label": "RegPilot",
        "cf_temp_base_url": "",
        "cf_temp_admin_auth": "",
        "cf_temp_custom_auth": "",
        "cf_temp_domain": "",
        "cf_temp_use_random_subdomain": False,
        "hotmail_api_base_url": "http://127.0.0.1:17373",
        "hotmail_alias_enabled": True,
        "hotmail_alias_max_per_account": 5,
        "hotmail_mailboxes": "INBOX,Junk",
        "hotmail_sender_filters": "openai,noreply,no-reply",
        "hotmail_subject_filters": "code,verification,验证码",
        "hotmail_required_keywords": "",
        "codex2api_url": "",
        "codex2api_admin_key": "",
        "codex2api_proxy_url": "",
        "codex2api_auto_import": False,
        "sms_provider": "hero_sms",
        "sms_api_key": "",
        "hero_sms_api_key": "",
        "hero_sms_base_url": "https://hero-sms.com/stubs/handler_api.php",
        "smsbower_api_key": "",
        "smsbower_base_url": SMSBOWER_BASE_URL,
        "fivesim_api_key": "",
        "hero_sms_country": "16",
        "hero_sms_country_label": "英格兰 (United Kingdom)",
        "hero_sms_service": "dr",
        "hero_sms_min_price": "",
        "hero_sms_max_price": "0.023",
        "sms_wait_timeout": 60,
        "sms_wait_interval": 5,
        "sms_resend_after_seconds": 30,
        "sms_timeout_after_resend_seconds": 60,
        "sms_release_after_seconds": 120,
        "sms_auto_retry": False,
        "sms_retry_count": 3,
    },
    "hero_phone_bind": {
        "proxy": "",
        "env_random_enabled": False,
        "env_proxy_pool": "",
        "env_ua_pool": "",
        "env_accept_language_pool": "",
        "env_timezone_pool": "",
        "env_viewport_pool": "",
        "codex2api_url": "",
        "codex2api_admin_key": "",
        "codex2api_proxy_url": "",
        "codex2api_auto_import": False,
        "hero_sms_api_key": "",
        "hero_sms_base_url": "https://hero-sms.com/stubs/handler_api.php",
        "sms_provider": "hero_sms",
        "sms_api_key": "",
        "smsbower_api_key": "",
        "smsbower_base_url": SMSBOWER_BASE_URL,
        "fivesim_api_key": "",
        "hero_sms_country": "16",
        "hero_sms_country_label": "英格兰 (United Kingdom)",
        "hero_sms_service": "dr",
        "hero_sms_min_price": "",
        "hero_sms_max_price": "0.023",
        "sms_wait_timeout": 60,
        "sms_wait_interval": 5,
        "sms_resend_after_seconds": 30,
        "sms_timeout_after_resend_seconds": 60,
        "sms_release_after_seconds": 120,
        "sms_auto_retry": False,
        "sms_retry_count": 3,
        "mail_type": "cloudflare-temp-email",
        "icloud_email": "",
        "icloud_imap_user": "",
        "icloud_imap_password": "",
        "icloud_cookies_json": "",
        "icloud_cookies_path": "",
        "icloud_host": "icloud.com",
        "icloud_hme_label": "RegPilot",
        "cf_temp_base_url": "",
        "cf_temp_admin_auth": "",
        "cf_temp_custom_auth": "",
        "cf_temp_domain": "",
        "cf_temp_use_random_subdomain": False,
        "hotmail_api_base_url": "http://127.0.0.1:17373",
        "hotmail_alias_enabled": True,
        "hotmail_alias_max_per_account": 5,
        "hotmail_mailboxes": "INBOX,Junk",
        "hotmail_sender_filters": "openai,noreply,no-reply",
        "hotmail_subject_filters": "code,verification,验证码",
        "hotmail_required_keywords": "",
    },
}


def _load_last_result() -> dict[str, Any]:
    path = DATA_DIR / "last_result.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _apply_last_result_prefill(config: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    merged = json.loads(json.dumps(config))
    last_result = _load_last_result()
    email = str(last_result.get("email") or "").strip()
    password = str(last_result.get("password") or "").strip()
    if email:
        hero_inject = merged.get("hero_inject") or {}
        if not str(hero_inject.get("email") or "").strip():
            hero_inject["email"] = email
    if password:
        hero_inject = merged.get("hero_inject") or {}
        if not str(hero_inject.get("password") or "").strip():
            hero_inject["password"] = password
    return merged


LEGACY_WEBUI_REMOVED = True

class JobStore(_BaseJobStore):
    def __init__(self, *, restore: bool = False) -> None:
        super().__init__(
            restore=restore,
            log_dir_getter=lambda: LOG_DIR,
            prune_callback=lambda: _prune_job_logs(),
            error_translator=_zh_task_error,
        )


JOBS = JobStore(restore=True)
_JOB_EXECUTION_LOCK = threading.Lock()
_CPA_OAUTH_LOCK = threading.Lock()


def _job_log_max_bytes() -> int:
    try:
        config = _load_webui_config()
        logs = config.get("logs") if isinstance(config.get("logs"), dict) else {}
        mb = float(logs.get("job_log_max_mb") or 100)
        return max(1, int(mb * 1024 * 1024))
    except Exception:
        return 100 * 1024 * 1024


def _prune_job_logs() -> None:
    log_dir = LOG_DIR / "jobs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
        files = [path for path in log_dir.glob("*.log") if path.is_file()]
        total = sum(path.stat().st_size for path in files)
        max_bytes = _job_log_max_bytes()
        if total <= max_bytes:
            return
        for path in sorted(files, key=lambda item: item.stat().st_mtime):
            try:
                size = path.stat().st_size
                path.unlink()
                total -= size
            except Exception:
                continue
            if total <= max_bytes:
                break
    except Exception:
        pass


def _namespace(**values: Any) -> argparse.Namespace:
    return argparse.Namespace(**values)


def _clone_webui_config_defaults() -> dict[str, dict[str, Any]]:
    return json.loads(json.dumps(WEBUI_CONFIG_DEFAULTS))


_WEBUI_LEGACY_KEY_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("hero_sms_wait_timeout", "sms_wait_timeout"),
    ("hero_sms_wait_interval", "sms_wait_interval"),
    ("hero_sms_resend_after_seconds", "sms_resend_after_seconds"),
    ("hero_sms_timeout_after_resend_seconds", "sms_timeout_after_resend_seconds"),
    ("hero_sms_release_after_seconds", "sms_release_after_seconds"),
    ("hero_sms_auto_retry", "sms_auto_retry"),
    ("hero_sms_retry_count", "sms_retry_count"),
)


def _migrate_legacy_webui_config(config: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(config, dict):
        return config
    for section in config.values():
        if not isinstance(section, dict):
            continue
        for old_key, new_key in _WEBUI_LEGACY_KEY_MIGRATIONS:
            if old_key in section and new_key not in section:
                section[new_key] = section[old_key]
        provider = str(section.get("sms_provider") or "").strip().lower().replace("-", "_")
        if provider in {"5sim", "five_sim", "fivesim", "five"} and not str(section.get("fivesim_api_key") or "").strip():
            section["fivesim_api_key"] = str(section.get("sms_api_key") or section.get("hero_sms_api_key") or "").strip()
    return config


def _merge_webui_config(raw: Any) -> dict[str, dict[str, Any]]:
    merged = _clone_webui_config_defaults()
    if not isinstance(raw, dict):
        return merged
    raw = _migrate_legacy_webui_config(raw)
    for section, defaults in merged.items():
        candidate = raw.get(section)
        if not isinstance(candidate, dict):
            continue
        for key in defaults:
            if key in candidate:
                merged[section][key] = candidate[key]
    return merged


def _read_webui_config_json(path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _backup_corrupt_webui_config() -> None:
    try:
        if not WEBUI_CONFIG_PATH.exists():
            return
        backup_path = WEBUI_CONFIG_PATH.with_name(f"webui_config.corrupt-{time.strftime('%Y%m%d-%H%M%S')}.json")
        backup_path.write_bytes(WEBUI_CONFIG_PATH.read_bytes())
    except Exception:
        pass


def _webui_config_last_valid_path():
    default_path = DATA_DIR / "webui_config.last_valid.json"
    if WEBUI_CONFIG_LAST_VALID_PATH != default_path:
        return WEBUI_CONFIG_LAST_VALID_PATH
    return WEBUI_CONFIG_PATH.with_name("webui_config.last_valid.json")


def _write_last_valid_webui_config(config: dict[str, dict[str, Any]]) -> None:
    try:
        ensure_dirs()
        write_json_atomic(_webui_config_last_valid_path(), config)
    except Exception:
        pass


def _load_webui_config() -> dict[str, dict[str, Any]]:
    ensure_dirs()
    return _get_cached_webui_config()


_WEBUI_CONFIG_CACHE: dict[str, Any] = {
    "signature": None,
    "data": None,
}
_WEBUI_CONFIG_LOCK = threading.Lock()


def _webui_config_signature() -> tuple[Any, Any]:
    try:
        mtime_webui = WEBUI_CONFIG_PATH.stat().st_mtime if WEBUI_CONFIG_PATH.exists() else None
    except Exception:
        mtime_webui = None
    try:
        last_result_path = DATA_DIR / "last_result.json"
        mtime_last = last_result_path.stat().st_mtime if last_result_path.exists() else None
    except Exception:
        mtime_last = None
    return mtime_webui, mtime_last


def _load_webui_config_uncached() -> dict[str, dict[str, Any]]:
    if not WEBUI_CONFIG_PATH.exists():
        return _apply_last_result_prefill(_clone_webui_config_defaults())
    try:
        merged = _merge_webui_config(_read_webui_config_json(WEBUI_CONFIG_PATH))
    except Exception:
        _backup_corrupt_webui_config()
        try:
            merged = _merge_webui_config(_read_webui_config_json(_webui_config_last_valid_path()))
        except Exception:
            merged = _clone_webui_config_defaults()
        return _apply_last_result_prefill(merged)
    _write_last_valid_webui_config(merged)
    return _apply_last_result_prefill(merged)


def _get_cached_webui_config() -> dict[str, dict[str, Any]]:
    signature = _webui_config_signature()
    with _WEBUI_CONFIG_LOCK:
        if _WEBUI_CONFIG_CACHE["data"] is not None and _WEBUI_CONFIG_CACHE["signature"] == signature:
            return json.loads(json.dumps(_WEBUI_CONFIG_CACHE["data"]))
        data = _load_webui_config_uncached()
        _WEBUI_CONFIG_CACHE["data"] = data
        _WEBUI_CONFIG_CACHE["signature"] = signature
        return json.loads(json.dumps(data))


def _invalidate_webui_config_cache() -> None:
    with _WEBUI_CONFIG_LOCK:
        _WEBUI_CONFIG_CACHE["data"] = None
        _WEBUI_CONFIG_CACHE["signature"] = None


_WEBUI_BOOL_KEYS = {
    "env_random_enabled",
    "cf_temp_use_random_subdomain",
    "hotmail_alias_enabled",
    "codex2api_auto_import",
    "sms_auto_retry",
    "hero_sms_auto_retry",
    "auto_pause_on_expired",
}

_WEBUI_POSITIVE_INT_KEYS = {
    "total",
    "threads",
    "request_timeout",
    "wait_timeout",
    "wait_interval",
    "sms_wait_timeout",
    "sms_wait_interval",
    "sms_resend_after_seconds",
    "sms_timeout_after_resend_seconds",
    "sms_release_after_seconds",
    "sms_retry_count",
    "concurrency",
    "priority",
    "rate_multiplier",
    "job_log_max_mb",
    "hotmail_alias_max_per_account",
}


def _positive_int_from_payload(payload: dict[str, Any], key: str, default: int = 1) -> int:
    raw = payload.get(key, default)
    if raw in (None, ""):
        return default
    if isinstance(raw, bool):
        raise ValueError(f"invalid_{key}")
    if isinstance(raw, float) and not raw.is_integer():
        raise ValueError(f"invalid_{key}")
    if isinstance(raw, str):
        text = raw.strip()
        if not re.fullmatch(r"\d+", text):
            raise ValueError(f"invalid_{key}")
        raw = text
    try:
        value = int(raw)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"invalid_{key}")
    if value < 1:
        raise ValueError(f"invalid_{key}")
    return value


def _sanitize_webui_config_value(key: str, value: Any, default: Any) -> Any:
    if default == "" and value in (None, ""):
        return ""
    if key in _WEBUI_BOOL_KEYS:
        return _bool_from_payload({key: value}, key, bool(default))
    if key in _WEBUI_POSITIVE_INT_KEYS:
        return _positive_int_from_payload({key: value}, key, int(default or 1))
    return value


def _save_webui_config(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    merged = _clone_webui_config_defaults()
    if isinstance(payload, dict):
        for section, defaults in merged.items():
            candidate = payload.get(section)
            if not isinstance(candidate, dict):
                continue
            for key in defaults:
                if key in candidate:
                    merged[section][key] = _sanitize_webui_config_value(key, candidate[key], defaults[key])
    ensure_dirs()
    write_json_atomic(WEBUI_CONFIG_PATH, merged)
    _write_last_valid_webui_config(merged)
    _invalidate_webui_config_cache()
    return merged


def _reset_webui_config() -> dict[str, dict[str, Any]]:
    merged = _apply_last_result_prefill(_clone_webui_config_defaults())
    ensure_dirs()
    write_json_atomic(WEBUI_CONFIG_PATH, merged)
    _write_last_valid_webui_config(merged)
    _invalidate_webui_config_cache()
    return merged


def _bool_from_payload(payload: dict[str, Any], key: str, default: bool = False) -> bool:
    return parse_bool(payload.get(key, default), default=default, key=key)


def _bool_from_renamed_payload(payload: dict[str, Any], key: str, legacy_key: str, default: bool = False) -> bool:
    if payload.get(key) not in (None, ""):
        return _bool_from_payload(payload, key, default)
    return _bool_from_payload(payload, legacy_key, default)


def _renamed_payload_value(payload: dict[str, Any], key: str, legacy_key: str, default: Any = None) -> Any:
    value = payload.get(key)
    if value not in (None, ""):
        return value
    value = payload.get(legacy_key)
    if value not in (None, ""):
        return value
    return default


def _positive_int_from_renamed_payload(payload: dict[str, Any], key: str, legacy_key: str, default: int, minimum: int = 1) -> int:
    return max(minimum, int(_renamed_payload_value(payload, key, legacy_key, default) or default))


def _cloudflare_mail_provider_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    cf_temp_base_url = str(payload.get("cf_temp_base_url") or "").strip()
    cf_temp_base_url = re.sub(r"^(https?):/(?!/)", r"\1://", cf_temp_base_url, flags=re.I)
    return {
        "type": "cloudflare-temp-email",
        "base_url": cf_temp_base_url,
        "admin_auth": str(payload.get("cf_temp_admin_auth") or "").strip(),
        "custom_auth": str(payload.get("cf_temp_custom_auth") or "").strip(),
        "domain": str(payload.get("cf_temp_domain") or "").strip(),
        "use_random_subdomain": _bool_from_payload(payload, "cf_temp_use_random_subdomain"),
    }


def _cloudflare_mail_provider_is_ready(provider: dict[str, Any]) -> bool:
    return bool(
        str(provider.get("base_url") or "").strip()
        and str(provider.get("admin_auth") or "").strip()
        and str(provider.get("domain") or "").strip()
    )


def _hotmail_mail_provider_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    base_url = str(payload.get("hotmail_api_base_url") or "").strip()
    base_url = re.sub(r"^(https?):/(?!/)", r"\1://", base_url, flags=re.I)
    return {
        "type": "hotmail-api",
        "base_url": base_url,
        "alias_enabled": _bool_from_payload(payload, "hotmail_alias_enabled", True),
        "alias_max_per_account": int(payload.get("hotmail_alias_max_per_account") or 5),
        "mailboxes": str(payload.get("hotmail_mailboxes") or "INBOX,Junk").strip(),
        "sender_filters": str(payload.get("hotmail_sender_filters") or "openai,noreply,no-reply").strip(),
        "subject_filters": str(payload.get("hotmail_subject_filters") or "code,verification,验证码").strip(),
        "required_keywords": str(payload.get("hotmail_required_keywords") or "").strip(),
        "top": 10,
    }


def _register_config_from_payload(payload: dict[str, Any]):
    mail_type = str(payload.get("mail_type") or "cloudflare-temp-email").strip().lower()
    provider: dict[str, Any] = {"type": mail_type}
    if mail_type in {"icloud", "icloud-hme", "icloud_hme"}:
        provider["type"] = "icloud"
        provider.update(
            {
                "email": str(payload.get("icloud_email") or "").strip(),
                "imap_user": str(payload.get("icloud_imap_user") or "").strip(),
                "imap_password": str(payload.get("icloud_imap_password") or "").strip(),
                "cookies_json": str(payload.get("icloud_cookies_json") or "").strip(),
                "cookies_path": str(payload.get("icloud_cookies_path") or "").strip(),
                "host": str(payload.get("icloud_host") or "icloud.com").strip() or "icloud.com",
                "hme_label": str(payload.get("icloud_hme_label") or "RegPilot").strip() or "RegPilot",
            }
        )
    elif mail_type == "cloudflare-temp-email":
        provider.update(_cloudflare_mail_provider_from_payload(payload))
    elif mail_type in {"hotmail-api", "outlook-api", "microsoft-mail"}:
        provider.update(_hotmail_mail_provider_from_payload(payload))
    providers = [provider]
    if mail_type in {"icloud", "icloud-hme", "icloud_hme"}:
        fallback_provider = _cloudflare_mail_provider_from_payload(payload)
        if _cloudflare_mail_provider_is_ready(fallback_provider):
            providers.append(fallback_provider)
    raw = {
        "proxy": str(payload.get("proxy") or "").strip(),
        "total": int(payload.get("total") or 1),
        "threads": int(payload.get("threads") or 1),
        "mail": {
            "request_timeout": int(payload.get("request_timeout") or 30),
            "wait_timeout": int(payload.get("wait_timeout") or 60),
            "wait_interval": int(payload.get("wait_interval") or 2),
            "providers": providers,
        },
    }
    args = _namespace(
        config="",
        proxy=raw["proxy"],
        env_random_enabled=_bool_from_payload(payload, "env_random_enabled"),
        env_proxy_pool=str(payload.get("env_proxy_pool") or "").strip(),
        env_ua_pool=str(payload.get("env_ua_pool") or "").strip(),
        env_accept_language_pool=str(payload.get("env_accept_language_pool") or "").strip(),
        env_timezone_pool=str(payload.get("env_timezone_pool") or "").strip(),
        env_viewport_pool=str(payload.get("env_viewport_pool") or "").strip(),
        total=raw["total"],
        threads=raw["threads"],
        default_password=str(payload.get("default_password") or ""),
        codex2api_url=str(payload.get("codex2api_url") or "").strip(),
        codex2api_admin_key=str(payload.get("codex2api_admin_key") or "").strip(),
        codex2api_proxy_url=str(payload.get("codex2api_proxy_url") or "").strip(),
        codex2api_auto_import=_bool_from_payload(payload, "codex2api_auto_import"),
        hero_sms_api_key=str(payload.get("hero_sms_api_key") or "").strip(),
        hero_sms_base_url=str(payload.get("hero_sms_base_url") or "").strip(),
        sms_provider=str(payload.get("sms_provider") or "hero_sms").strip(),
        sms_api_key=str(payload.get("sms_api_key") or "").strip(),
        smsbower_api_key=str(payload.get("smsbower_api_key") or "").strip(),
        fivesim_api_key=str(payload.get("fivesim_api_key") or "").strip(),
        smsbower_base_url=str(payload.get("smsbower_base_url") or SMSBOWER_BASE_URL).strip(),
        hero_sms_country=str(payload.get("hero_sms_country") or "").strip(),
        hero_sms_service=str(payload.get("hero_sms_service") or "").strip(),
        hero_sms_min_price=float(payload.get("hero_sms_min_price") or 0),
        hero_sms_max_price=float(payload.get("hero_sms_max_price") or 0),
        hero_sms_wait_timeout=_positive_int_from_renamed_payload(payload, "sms_wait_timeout", "hero_sms_wait_timeout", 180),
        hero_sms_wait_interval=_positive_int_from_renamed_payload(payload, "sms_wait_interval", "hero_sms_wait_interval", 5),
        hero_sms_auto_retry=_bool_from_renamed_payload(payload, "sms_auto_retry", "hero_sms_auto_retry"),
        hero_sms_retry_count=_positive_int_from_renamed_payload(payload, "sms_retry_count", "hero_sms_retry_count", 3),
    )
    cfg = load_config(args)
    cfg.mail.request_timeout = raw["mail"]["request_timeout"]
    cfg.mail.wait_timeout = raw["mail"]["wait_timeout"]
    cfg.mail.wait_interval = raw["mail"]["wait_interval"]
    cfg.mail.providers = raw["mail"]["providers"]
    cfg.sms_provider = str(payload.get("sms_provider") or "hero_sms").strip() or "hero_sms"
    cfg.sms_api_key = str(payload.get("sms_api_key") or "").strip()
    cfg.smsbower_api_key = str(payload.get("smsbower_api_key") or "").strip()
    cfg.fivesim_api_key = str(payload.get("fivesim_api_key") or "").strip()
    cfg.smsbower_base_url = str(payload.get("smsbower_base_url") or SMSBOWER_BASE_URL).strip() or SMSBOWER_BASE_URL
    cfg.hero_sms_auto_retry = _bool_from_renamed_payload(payload, "sms_auto_retry", "hero_sms_auto_retry")
    cfg.hero_sms_retry_count = _positive_int_from_renamed_payload(payload, "sms_retry_count", "hero_sms_retry_count", 3)
    cfg.default_password = str(payload.get("default_password") or "")
    cfg.hero_sms_min_price = float(payload.get("hero_sms_min_price") or 0)
    return cfg


def _mail_config_dict_from_payload(payload: dict[str, Any]) -> dict[str, Any]:
    mail_type = str(payload.get("mail_type") or "cloudflare-temp-email").strip().lower()
    provider: dict[str, Any] = {"type": mail_type}
    if mail_type in {"icloud", "icloud-hme", "icloud_hme"}:
        provider["type"] = "icloud"
        provider.update(
            {
                "email": str(payload.get("icloud_email") or "").strip(),
                "imap_user": str(payload.get("icloud_imap_user") or "").strip(),
                "imap_password": str(payload.get("icloud_imap_password") or "").strip(),
                "cookies_json": str(payload.get("icloud_cookies_json") or "").strip(),
                "cookies_path": str(payload.get("icloud_cookies_path") or "").strip(),
                "host": str(payload.get("icloud_host") or "icloud.com").strip() or "icloud.com",
                "hme_label": str(payload.get("icloud_hme_label") or "RegPilot").strip() or "RegPilot",
            }
        )
    elif mail_type == "cloudflare-temp-email":
        provider.update(_cloudflare_mail_provider_from_payload(payload))
    elif mail_type in {"hotmail-api", "outlook-api", "microsoft-mail"}:
        provider.update(_hotmail_mail_provider_from_payload(payload))
    providers = [provider]
    if mail_type in {"icloud", "icloud-hme", "icloud_hme"}:
        fallback_provider = _cloudflare_mail_provider_from_payload(payload)
        if _cloudflare_mail_provider_is_ready(fallback_provider):
            providers.append(fallback_provider)
    return {
        "request_timeout": int(payload.get("request_timeout") or 30),
        "wait_timeout": int(payload.get("wait_timeout") or 60),
        "bind_email_wait_timeout": int(payload.get("bind_email_wait_timeout") or payload.get("add_email_wait_timeout") or 180),
        "wait_interval": int(payload.get("wait_interval") or 2),
        "providers": providers,
    }


def _provider_matches_email(provider: dict[str, Any], email: str) -> bool:
    normalized_email = str(email or "").strip().lower()
    if not normalized_email or "@" not in normalized_email:
        return False
    domain = normalized_email.rsplit("@", 1)[-1]
    for key in ("email", "address", "alias", "login"):
        value = str(provider.get(key) or "").strip().lower()
        if value and value == normalized_email:
            return True
    provider_domain = str(provider.get("domain") or "").strip().lower().lstrip("@")
    return bool(provider_domain and provider_domain == domain)


def _enrich_mailbox_with_bind_mail_provider(mailbox: dict[str, Any], mail_config: dict[str, Any], bind_email: str) -> dict[str, Any]:
    if not isinstance(mailbox, dict):
        mailbox = {}
    email = str(bind_email or mailbox.get("bind_email") or mailbox.get("email") or "").strip()
    providers = mail_config.get("providers") if isinstance(mail_config, dict) else []
    provider = providers[0] if isinstance(providers, list) and providers and isinstance(providers[0], dict) else {}
    if isinstance(providers, list):
        mailbox_provider = str(mailbox.get("provider") or "").strip().lower()
        matched = next(
            (
                item
                for item in providers
                if isinstance(item, dict)
                and (
                    (mailbox_provider and str(item.get("type") or "").strip().lower() == mailbox_provider)
                    or _provider_matches_email(item, email)
                )
            ),
            None,
        )
        if isinstance(matched, dict):
            provider = matched
    provider_type = str(provider.get("type") or mailbox.get("provider") or "").strip()
    if not email or not provider_type:
        return mailbox
    out = dict(mailbox)
    out.setdefault("provider", provider_type)
    out.setdefault("email", email)
    out.setdefault("bind_email", email)
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
        value = provider.get(key)
        if value not in (None, "") and not out.get(key):
            out[key] = value
    return out


def _phone_signup_entry_error(*items: Any) -> str:
    joined = " ".join(str(item or "") for item in items)
    if "authorize_hydra_invalid_request" in joined:
        return "authorize_hydra_invalid_request"
    if "Your session has ended" in joined:
        return "session_ended"
    if "/error?" in joined and "AuthApiFailure" in joined:
        return "auth_api_failure"
    return ""


def _sms_retry_exhausted_message(provider: str, attempts: int, error: str) -> str:
    normalized = normalize_sms_provider(provider or "hero_sms", strict=False)
    return f"{normalized}_retry_exhausted_after_{max(1, int(attempts or 1))}_attempts: {str(error or '').strip() or 'unknown_error'}"


def _unwrap_sms_retry_error(error: str) -> str:
    text = str(error or "").strip()
    match = re.match(r"^(?:hero_sms|smsbower)_retry_exhausted_after_\d+_attempts:\s*(.+)$", text)
    return match.group(1).strip() if match else text


def _is_sms_inventory_error(error: str) -> bool:
    text = str(error or "").upper()
    return "NO_BALANCE" in text or "NO_NUMBERS" in text


def _sms_retry_count_from_payload(payload: dict[str, Any], auto_retry: bool) -> int:
    if not auto_retry:
        return 1
    try:
        return _positive_int_from_renamed_payload(payload, "sms_retry_count", "hero_sms_retry_count", HERO_SMS_MAX_RETRY_COUNT)
    except (TypeError, ValueError):
        return HERO_SMS_MAX_RETRY_COUNT


def _safe_register_failure_summary(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    error_body = body.get("error") if isinstance(body.get("error"), dict) else {}
    text = re.sub(r"\s+", " ", str(info.get("text") or "")).strip()
    text = re.sub(r"\+?\d{6,20}", "[phone]", text)
    text = re.sub(r"(?i)(password|token|secret|key)[\"'=:\s]+[^,}\s\"]+", r"\1=[redacted]", text)
    code = str(body.get("code") or error_body.get("code") or "").strip()
    message = str(body.get("message") or error_body.get("message") or body.get("error") or "").strip()
    if not code and re.search(r"invalid_auth_step|Invalid authorization step", text, re.I):
        code = "invalid_auth_step"
    if not message and code == "invalid_auth_step":
        message = "Invalid authorization step."
    fields = [
        f"status={info.get('status')}",
    ]
    if code:
        fields.append(f"code={code[:80]}")
    if message:
        fields.append(f"message={message[:160]}")
    elif text:
        fields.append(f"message={text[:160]}")
    if code == "invalid_auth_step":
        fields.append("action=replace_phone_or_environment")
    if info.get("sentinel_error"):
        fields.append(f"sentinel_error={str(info.get('sentinel_error'))[:180]}")
    else:
        fields.append(f"sentinel_present={bool(info.get('sentinel_token_present'))}")
    return " ".join(fields)


def _run_job(kind: str, func, *args: Any, **kwargs: Any) -> dict[str, str]:
    return _run_job_impl(
        JOBS,
        _JOB_EXECUTION_LOCK,
        kind,
        func,
        *args,
        error_translator=_zh_task_error,
        cancelled_error_type=JobCancelledError,
        **kwargs,
    )


def _run_register(payload: dict[str, Any]) -> dict[str, Any]:
    cfg = _register_config_from_payload(payload)
    requested_total = max(1, int(getattr(cfg, "total", 1) or 1))
    try:
        disallowed_retry_count = max(1, int(payload.get("registration_disallowed_retry_count") or 5))
    except (TypeError, ValueError):
        disallowed_retry_count = 5
    attempts = max(requested_total, requested_total * disallowed_retry_count)
    result = None
    successes: list[Any] = []
    failures: list[Any] = []

    def summarize(item: Any) -> dict[str, Any]:
        mailbox = item.mailbox if isinstance(item.mailbox, dict) else {}
        return {
            "ok": bool(item.ok),
            "email": str(item.email or ""),
            "error": str(item.error or ""),
            "callback_url": str(mailbox.get("_callback_url", item.callback_url or "") or ""),
            "has_access_token": bool(item.access_token),
            "import_submit_ok": bool(mailbox.get("_cpa_submit_ok")),
            "import_submit_message": str(mailbox.get("_cpa_submit_message") or ""),
        }

    for attempt in range(1, attempts + 1):
        print(f"阶段：注册尝试 {attempt}/{attempts}（目标成功 {len(successes) + 1}/{requested_total}）")
        result = run_placeholder(cfg)
        if result.ok:
            successes.append(result)
            if len(successes) >= requested_total:
                break
            continue
        failures.append(result)
        if str(result.error or "") == "registration_disallowed" and attempt < attempts:
            print("阶段：本次被上游拒绝创建账号，已更换邮箱/资料后重试")
            time.sleep(2)
            continue
        break
    assert result is not None
    path = save_result(result)
    mailbox = result.mailbox if isinstance(result.mailbox, dict) else {}
    ok = len(successes) >= requested_total
    error = "" if ok else str(result.error or "registration_target_not_reached")
    return {
        "ok": ok,
        "target_total": requested_total,
        "success_count": len(successes),
        "failure_count": len(failures),
        "attempt_count": len(successes) + len(failures),
        "items": [summarize(item) for item in successes],
        "failures": [summarize(item) for item in failures[-5:]],
        "email": str(result.email or ""),
        "error": error,
        "callback_url": str(mailbox.get("_callback_url", result.callback_url or "") or ""),
        "has_access_token": bool(result.access_token),
        "import_submit_ok": bool(mailbox.get("_cpa_submit_ok")),
        "import_submit_message": str(mailbox.get("_cpa_submit_message") or ""),
        "saved_result": str(path),
    }


def _hero_sms_payload_with_fallback(payload: dict[str, Any]) -> dict[str, Any]:
    merged = dict(payload or {})
    has_explicit_provider_key = bool(str(merged.get("hero_sms_api_key") or "").strip() or str(merged.get("smsbower_api_key") or "").strip() or str(merged.get("fivesim_api_key") or "").strip())
    webui_config = _load_webui_config()
    register_cfg = (webui_config.get("register") or {}) if isinstance(webui_config, dict) else {}
    for key in (
        "env_random_enabled",
        "env_proxy_pool",
        "env_ua_pool",
        "env_accept_language_pool",
        "env_timezone_pool",
        "env_viewport_pool",
        "sms_provider",
        "sms_api_key",
        "hero_sms_api_key",
        "hero_sms_base_url",
        "smsbower_api_key",
        "fivesim_api_key",
        "smsbower_base_url",
        "hero_sms_service",
        "hero_sms_country",
        "hero_sms_max_price",
        "sms_wait_timeout",
        "sms_wait_interval",
        "sms_resend_after_seconds",
        "sms_timeout_after_resend_seconds",
        "sms_release_after_seconds",
        "sms_auto_retry",
        "sms_retry_count",
        "hero_sms_wait_timeout",
        "hero_sms_wait_interval",
        "hero_sms_auto_retry",
        "hero_sms_retry_count",
    ):
        current = merged.get(key)
        if key == "sms_provider" and current in (None, "") and has_explicit_provider_key:
            continue
        if current in (None, ""):
            merged[key] = register_cfg.get(key)
    return merged


def _sms_provider_from_payload(payload: dict[str, Any]) -> str:
    return sms_provider_from_values(payload)


def _sms_api_key_from_payload(payload: dict[str, Any], provider: str) -> str:
    return sms_api_key_from_values(payload, provider)


def _sms_config_from_payload(payload: dict[str, Any]):
    payload = _hero_sms_payload_with_fallback(payload)
    return build_sms_config_from_values(payload)


def _hero_price_lookup(payload: dict[str, Any]) -> dict[str, Any]:
    config = _sms_config_from_payload(payload)
    if not config.api_key:
        raise ValueError("sms_api_key_required")
    country = str(config.country or "16").strip() or "16"
    eng_name = ""
    try:
        countries = fetch_hero_sms_countries(config)
        eng_name = next((str(item.get("eng") or "") for item in countries if str(item.get("id") or "") == country), "")
    except Exception:
        eng_name = ""
    label = _hero_country_label(country, eng_name)
    summary = fetch_hero_sms_price_summary(config, country_label=label)
    if config.provider == "smsbower":
        return {"ok": True, "provider": config.provider, **summary}
    if config.provider == "5sim":
        return {"ok": True, "provider": config.provider, **summary}
    quotes = fetch_hero_sms_quote_list(config)
    quote_list = quotes.get("quote_list") or []
    rent_list = quotes.get("rent_list") or []
    if quote_list:
        top_line = " | ".join(f"${float(item['price']):.4f} x{int(item['quantity'])}" for item in quote_list[:12])
        operator_count = int(quotes.get("operator_count") or 0)
        summary["summary"] = (
            f"Operators: {operator_count or 1}; "
            f"Price tiers: {len(quote_list)}; {top_line}"
        )
    return {"ok": True, "provider": config.provider, **summary, **quotes}


def _hero_country_lookup(payload: dict[str, Any]) -> dict[str, Any]:
    config = _sms_config_from_payload(payload)
    if not config.api_key:
        raise ValueError("sms_api_key_required")
    selected = str(config.country or "16").strip() or "16"
    items = fetch_hero_sms_countries(config)
    return {
        "ok": True,
        "provider": config.provider,
        "selected_country": selected,
        "items": [
            {
                "id": item["id"],
                "label": str(item.get("label") or "") or _hero_country_label(item["id"], str(item.get("eng") or "")),
                "eng": str(item.get("eng") or ""),
                "visible": bool(item.get("visible")),
            }
            for item in items
            if item.get("visible") is not False
        ],
    }


def _sms_wait_progress_message(info: dict[str, Any]) -> str:
    elapsed = int(info.get("elapsed") or 0)
    remaining = int(info.get("remaining") or 0)
    if info.get("resent"):
        after_resend_elapsed = int(info.get("after_resend_elapsed") or 0)
        after_resend_limit = int(info.get("timeout_after_resend") or 0)
        if after_resend_limit > 0:
            return (
                "阶段：等待短信验证码中"
                f"（重发后已等待 {after_resend_elapsed}/{after_resend_limit} 秒，总计 {elapsed} 秒，剩余约 {remaining} 秒）"
            )
        return f"阶段：等待短信验证码中（重发后已等待 {after_resend_elapsed} 秒，总计 {elapsed} 秒，剩余约 {remaining} 秒）"
    resend_after_seconds = max(1, int(info.get("resend_after_seconds") or HERO_SMS_RESEND_AFTER_SECONDS))
    resend_remaining = max(0, resend_after_seconds - elapsed)
    return f"阶段：等待短信验证码中（已等待 {elapsed}/{resend_after_seconds} 秒，距离自动重发约 {resend_remaining} 秒）"


def _phone_direct_once(
    payload: dict[str, Any],
    *,
    env_profile: Any = None,
    effective_proxy: str = "",
    manage_environment: bool = True,
    log_environment: bool = True,
    worker_index: int = 0,
    worker_total: int = 0,
) -> dict[str, Any]:
    hero_sms = _sms_config_from_payload(payload)
    if not hero_sms.api_key:
        raise ValueError("sms_api_key_required")
    codex2api_url = str(payload.get("codex2api_url") or "").strip()
    codex2api_admin_key = str(payload.get("codex2api_admin_key") or "").strip()
    wants_codex2api = bool(_bool_from_payload(payload, "codex2api_auto_import") and codex2api_url and codex2api_admin_key)

    env_profile = env_profile or prepare_environment_profile_from_payload(payload, fallback_proxy=str(payload.get("proxy") or ""))
    effective_proxy = str(effective_proxy or env_profile.proxy or payload.get("proxy") or "").strip()
    if log_environment:
        print(f"阶段：环境模块 {summarize_environment_profile(env_profile)}")
    env_context = environment_profile_context(env_profile) if manage_environment else nullcontext()
    with env_context:
        last_error = ""
        attempted_phones: list[str] = []
        attempt_limit = _sms_retry_count_from_payload(payload, hero_sms.auto_retry)
        for attempt_index in range(1, attempt_limit + 1):
            activation = acquire_hero_sms_phone(hero_sms)
            phone_number = str(activation.get("phone_number") or "").strip()
            if phone_number:
                attempted_phones.append(phone_number)
            activation_id = str(activation.get("activation_id") or "").strip()
            phone_price = str(activation.get("price") or "").strip()
            phone_verified = False
            activation_released = False
            password = str(payload.get("default_password") or "").strip() or _random_password()
            first_name, last_name = _random_name()
            birthdate = _random_birthdate()
            full_name = f"{first_name} {last_name}"

            phone_flow = {
                "phone_number": phone_number,
                "activation_id": activation_id,
                "activation_price": phone_price,
                "provider": hero_sms.provider,
                "stage": "signup_phone_acquired",
                "status": "phone_ready",
                "purpose": "signup",
                "bind_email": "",
                "callback": {"url": "", "source": ""},
                "import_submit_ok": None,
                "import_submit_message": "",
                "error": {"code": "", "message": "", "retryable": False, "recovery_action": "stop"},
            }
            attempt_text = f"（第 {attempt_index}/{attempt_limit} 次）" if hero_sms.auto_retry else ""
            price_text = f"，价格 {phone_price}" if phone_price else ""
            _save_partial_hero_phone_bind_result(phone_flow=phone_flow, password=password, note=f"已获取注册手机号{price_text}，准备开始主链{attempt_text}")
            worker_text = f"并发单元 {worker_index}/{worker_total} " if worker_index and worker_total else ""
            print(f"阶段：{worker_text}已获取注册手机号 {phone_number}{price_text}{attempt_text}（新取，仅本次直注使用）")
            print(f"阶段：本次账号密码：{password}")

            registrar = PlatformRegistrar(effective_proxy)
            try:
                print("阶段：准备打开手机号注册页（网络请求最多约90秒，失败会自动换号）")
                info = registrar.start_phone_signup(phone_number)
                print(f"阶段：已打开手机号注册页（状态 {info.get('status')}）")
                password_probe = _probe_phone_signup_password_page(registrar, phone_number)
                print(
                    "阶段：注册密码页检测 "
                    f"状态码={password_probe.get('status') or '-'} 匹配={'是' if password_probe.get('matched') else '否'} 标题={password_probe.get('title') or '-'} 最终地址={password_probe.get('final_url')}"
                )
                create_start: dict[str, Any] = {}
                if not password_probe.get("matched"):
                    create_start = registrar.create_account_start(phone_number)
                    print(f"阶段：手机号注册入口初始化结果 状态码={create_start.get('status') or '-'} 成功={'是' if create_start.get('ok') else '否'}")
                    password_probe = _probe_phone_signup_password_page(registrar, phone_number)
                    print(
                        "阶段：注册密码页二次检测 "
                        f"状态码={password_probe.get('status') or '-'} 匹配={'是' if password_probe.get('matched') else '否'} 标题={password_probe.get('title') or '-'} 最终地址={password_probe.get('final_url')}"
                    )
                if not password_probe.get("matched"):
                    entry_error = _phone_signup_entry_error(
                        password_probe.get("final_url"),
                        password_probe.get("text"),
                        create_start.get("final_url"),
                        create_start.get("text"),
                    )
                    suffix = f": {entry_error}" if entry_error else ""
                    raise RuntimeError(f"phone_signup_password_page_not_reached{suffix}")
                else:
                    print("阶段：已进入手机号注册密码页")

                register_info = registrar.register_user(phone_number, password)
                if not register_info.get("ok"):
                    failure_summary = _safe_register_failure_summary(register_info)
                    print(f"阶段：注册提交失败 {failure_summary}")
                    raise RuntimeError(f"register_user_{register_info.get('status')}: {failure_summary}")
                otp_info = registrar.send_phone_otp()
                print(f"阶段：已请求短信验证码（状态 {otp_info.get('status')}，{'成功' if otp_info.get('ok') else '失败'}）")
                if not otp_info.get("ok"):
                    raise RuntimeError(f"send_phone_otp_{otp_info.get('status')}")
                print("阶段：等待短信验证码（30秒后自动重发，重发后最多等待60秒）")

                def _trigger_gpt_phone_resend() -> None:
                    resend_info = registrar.resend_phone_otp()
                    print(f"阶段：已重发短信验证码（HTTP {resend_info.get('status')}，业务{'成功' if resend_info.get('ok') else '失败'}）")
                    if not resend_info.get("ok"):
                        raise RuntimeError(f"resend_phone_otp_{resend_info.get('status')}")

                def _log_sms_wait_progress(info: dict[str, Any]) -> None:
                    print(_sms_wait_progress_message(info))

                poll_kwargs: dict[str, Any] = {
                    "on_resend": _trigger_gpt_phone_resend,
                    "on_progress": _log_sms_wait_progress,
                    "timeout_after_resend": 60,
                }
                sms_code = poll_hero_sms_code(hero_sms, activation_id, **poll_kwargs)
                print(f"阶段：已收到短信验证码：{sms_code}")
                validate_info = registrar.validate_phone_signup_otp(sms_code)
                print(f"阶段：短信验证码校验结果（状态 {validate_info.get('status')}，{'成功' if validate_info.get('ok') else '失败'}）")
                if not validate_info.get("ok"):
                    raise RuntimeError(f"validate_phone_signup_otp_{validate_info.get('status')}")
                phone_verified = True
                set_hero_sms_status(hero_sms, activation_id, 6)
                activation_released = True
                print("阶段：手机直注短信验证码已校验成功，已释放手机号")
                print("阶段：手机直注号码已完成使用，不加入复用池")

                validate_continue_url = str(((validate_info.get("json") or {}).get("continue_url") or validate_info.get("final_url") or "")).strip()
                continue_probe = _load_continue_page(registrar, validate_continue_url)
                probed_continue_url = str(continue_probe.get("continue_url") or validate_continue_url or "").strip()
                probed_page_type = str(continue_probe.get("page_type") or "").strip()
                continue_text = str(continue_probe.get("text") or "")
                print(f"阶段：短信校验后继续页：页面类型={probed_page_type or '-'}，最终地址={probed_continue_url}")

                needs_about_you = bool(
                    probed_page_type == "about_you"
                    or probed_continue_url.endswith("/about-you")
                    or "/about-you" in probed_continue_url
                    or "about-you" in continue_text
                    or "autocomplete=\"name\"" in continue_text
                    or "name=\"birthday\"" in continue_text
                    or "name=\"age\"" in continue_text
                )
                if needs_about_you:
                    print(f"阶段：about-you 页面识别 {_about_you_shape_log_summary(continue_text)}")
                    try:
                        create_info = registrar.create_account(
                            full_name,
                            birthdate,
                            referer=probed_continue_url or validate_continue_url,
                            page_context=continue_text,
                        )
                    except TypeError:
                        create_info = registrar.create_account(full_name, birthdate, referer=probed_continue_url or validate_continue_url)
                    print(
                        "阶段：about-you 创建账号请求 "
                        f"状态码={create_info.get('status') or '-'} 成功={'是' if create_info.get('ok') else '否'} 跳转地址={create_info.get('location') or '-'} 最终地址={create_info.get('final_url') or '-'}"
                    )
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
                        print(f"阶段：about-you 创建账号接口尝试：{attempt_summary}")
                    create_error_code = _accounts_error_code(create_info)
                    if create_error_code == "registration_disallowed":
                        raise RuntimeError("registration_disallowed")
                    if create_info.get("ok"):
                        submitted_url = str(
                            ((create_info.get("json") or {}).get("continue_url") or create_info.get("location") or create_info.get("final_url") or probed_continue_url)
                        ).strip()
                        if submitted_url:
                            probed_continue_url = submitted_url
                            print(f"阶段：about-you 已通过创建账号接口提交：最终地址={probed_continue_url}")
                    if not create_info.get("ok") or not probed_continue_url or "/about-you" in probed_continue_url:
                        submitted_url, _ = _submit_about_you_form(
                            registrar,
                            page_url=probed_continue_url or validate_continue_url,
                            page_html=continue_text,
                            full_name=full_name,
                            birthdate=birthdate,
                        )
                        probed_continue_url = str(submitted_url or probed_continue_url).strip()
                        print(f"阶段：about-you 已通过页面表单提交：最终地址={probed_continue_url}")

                bind_email = ""
                callback_url = _resolve_oauth_callback(registrar, probed_continue_url, str((info or {}).get("state") or ""))
                if not callback_url:
                    print("阶段：手机号注册完成，开始后续 OAuth 回调")
                    info = registrar.start_authorize(email=bind_email or phone_number, screen_hint="login")
                    print(f"阶段：后续 OAuth 入口已打开（状态 {info.get('status')}）")
                    callback_url = _resolve_oauth_callback(registrar, str(info.get("final_url") or ""), str((info or {}).get("state") or ""))
                if not callback_url:
                    raise RuntimeError("callback_not_reached")
                phone_flow["callback"] = {"url": callback_url, "source": "resolved"}
                phone_flow["stage"] = "callback_fetched"
                phone_flow["status"] = "callback_ready"
                _save_partial_hero_phone_bind_result(phone_flow=phone_flow, password=password, note="已拿到 OAuth 回调，准备可选绑邮箱与 token 交换")
                print(f"阶段：已拿到 OAuth 回调 {callback_url}")

                mailbox = {
                    "phone_number": phone_number,
                    "phone_number_verified": True,
                    "activation_id": activation_id,
                    "bind_email": "",
                    "_signup_callback_url": callback_url,
                }
                exchange_config = RegisterConfig(
                    proxy=effective_proxy,
                    codex2api_url=codex2api_url,
                    codex2api_admin_key=codex2api_admin_key,
                    codex2api_proxy_url=str(payload.get("codex2api_proxy_url") or "").strip(),
                    codex2api_auto_import=wants_codex2api,
                    sms_provider=hero_sms.provider,
                    sms_api_key=hero_sms.api_key,
                    hero_sms_api_key=hero_sms.api_key if hero_sms.provider == "hero_sms" else "",
                    smsbower_api_key=hero_sms.api_key if hero_sms.provider == "smsbower" else "",
                    hero_sms_base_url=hero_sms.base_url if hero_sms.provider == "hero_sms" else "",
                    smsbower_base_url=hero_sms.base_url if hero_sms.provider == "smsbower" else "",
                    hero_sms_country=hero_sms.country,
                    hero_sms_service=hero_sms.service,
                    hero_sms_min_price=hero_sms.min_price,
                    hero_sms_max_price=hero_sms.max_price,
                    hero_sms_wait_timeout=hero_sms.wait_timeout,
                    hero_sms_wait_interval=hero_sms.wait_interval,
                    hero_sms_auto_retry=False,
                )
                mail_config = _mail_config_dict_from_payload(payload)
                exchange_config.mail.request_timeout = int(mail_config.get("request_timeout") or 30)
                exchange_config.mail.wait_timeout = int(mail_config.get("wait_timeout") or 60)
                exchange_config.mail.wait_interval = int(mail_config.get("wait_interval") or 2)
                exchange_config.mail.providers = list(mail_config.get("providers") or [])
                exchange_config.mail.proxy = effective_proxy
                print("阶段：手机号注册完成，开始重新打开 OAuth 获取平台 token/CPA 回调")
                print("阶段：等待 CPA OAuth 状态锁，避免并发授权 state 被覆盖")
                with _CPA_OAUTH_LOCK:
                    print("阶段：已进入 CPA OAuth 状态锁，开始获取并提交 CPA 回调")
                    token_result = _exchange_registered_account_tokens(
                        config=exchange_config,
                        registrar=registrar,
                        email=phone_number,
                        password=password,
                        mailbox=mailbox,
                        code_verifier="",
                        callback_url=callback_url,
                    )
                if not token_result.ok:
                    raise RuntimeError(str(token_result.error or "token_exchange_failed"))
                token_result.password = password
                token_result.mailbox = token_result.mailbox or mailbox
                bind_email = str((token_result.mailbox or {}).get("bind_email") or "")
                token_result.mailbox = _enrich_mailbox_with_bind_mail_provider(token_result.mailbox or {}, mail_config, bind_email)
                callback_url = str(getattr(token_result, "callback_url", "") or callback_url).strip()
                token_result.email = bind_email or str(getattr(token_result, "email", "") or "") or phone_number
                token_result.callback_url = callback_url
                phone_flow["bind_email"] = bind_email
                phone_flow["callback"] = {"url": callback_url, "source": "resolved"}
                save_result(token_result)
                try:
                    from .accounts_store import save_registration_result_to_account

                    save_registration_result_to_account(token_result, source="phone_signup")
                    print("阶段：账号已保存到账号池")
                except Exception as exc:
                    print(f"阶段：账号池保存失败：{exc}")
                codex2api_result: dict[str, Any] = {}
                if wants_codex2api:
                    if bool((token_result.mailbox or {}).get("_cpa_submit_ok")):
                        codex2api_result = {"ok": True, "message": str((token_result.mailbox or {}).get("_cpa_submit_message") or "CPA callback submitted")}
                    else:
                        try:
                            codex2api_result = import_result_to_codex2api(
                                token_result,
                                codex2api_url=codex2api_url,
                                admin_key=codex2api_admin_key,
                                account_name=token_result.email or bind_email or phone_number,
                                proxy_url=str(payload.get("codex2api_proxy_url") or "").strip(),
                            )
                        except Exception as exc:
                            codex2api_result = {"ok": False, "message": str(exc or "codex2api_import_failed")}
                            print(f"阶段：Codex2API 导入失败：{codex2api_result['message']}")
                any_import_ok = bool(codex2api_result.get("ok"))
                if wants_codex2api and not any_import_ok:
                    raise RuntimeError(
                        str(
                            codex2api_result.get("message")
                            or "import_submit_failed"
                        )
                    )
                phone_flow["stage"] = "callback_submitted"
                phone_flow["status"] = "callback_submitted"
                phone_flow["import_submit_ok"] = bool(codex2api_result.get("ok")) if codex2api_result else False
                phone_flow["import_submit_message"] = str(codex2api_result.get("message") or "") if codex2api_result else ""
                phone_flow["codex2api_import_submit_ok"] = bool(codex2api_result.get("ok")) if codex2api_result else False
                phone_flow["codex2api_import_submit_message"] = str(codex2api_result.get("message") or "") if codex2api_result else ""
                _save_partial_hero_phone_bind_result(phone_flow=phone_flow, password=password, note="已完成 token 导入")
                return {
                    "ok": True,
                    "phone_number": phone_number,
                    "password": password,
                    "bind_email": bind_email,
                    "email": bind_email,
                    "callback_url": callback_url,
                    "import_submit_ok": bool(codex2api_result.get("ok")) if codex2api_result else False,
                    "import_submit_message": str(codex2api_result.get("message") or "") if codex2api_result else "",
                    "codex2api_import_submit_ok": bool(codex2api_result.get("ok")) if codex2api_result else False,
                    "codex2api_import_submit_message": str(codex2api_result.get("message") or "") if codex2api_result else "",
                    "phones_attempted": list(attempted_phones),
                }
            except Exception as exc:
                last_error = str(exc)
                try:
                    if activation_id and not phone_verified and not activation_released:
                        set_hero_sms_status(hero_sms, activation_id, 8)
                except Exception:
                    pass
                if not hero_sms.auto_retry:
                    print(f"阶段：当前号码流程失败，未开启自动重试，错误={last_error}")
                    try:
                        setattr(exc, "phones_attempted", list(attempted_phones))
                        setattr(exc, "phone_number", phone_number)
                    except Exception:
                        pass
                    raise
                if attempt_index >= attempt_limit:
                    print(f"阶段：当前号码流程失败，已达到最大重试次数（{attempt_index}/{attempt_limit}），错误={last_error}")
                    retry_error = RuntimeError(_sms_retry_exhausted_message(hero_sms.provider, attempt_limit, last_error))
                    try:
                        setattr(retry_error, "phones_attempted", list(attempted_phones))
                        setattr(retry_error, "phone_number", phone_number)
                    except Exception:
                        pass
                    raise retry_error
                print(f"阶段：当前号码流程失败，自动重试下一个号码（{attempt_index}/{attempt_limit}），错误={last_error}")
            finally:
                registrar.close()

        raise RuntimeError(last_error or "phone_direct_failed")


def _hero_phone_bind(payload: dict[str, Any]) -> dict[str, Any]:
    return _phone_direct_once(payload)


def _phone_direct(payload: dict[str, Any]) -> dict[str, Any]:
    requested_total = max(1, int(payload.get("total") or 1))
    requested_threads = max(1, int(payload.get("threads") or 1))
    worker_count = max(1, min(requested_total, requested_threads))
    if requested_total == 1:
        item = _phone_direct_once(payload)
        return {
            **item,
            "ok": bool(item.get("ok")),
            "target_total": 1,
            "success_count": 1 if item.get("ok") else 0,
            "failure_count": 0 if item.get("ok") else 1,
            "items": [item] if item.get("ok") else [],
            "failures": [] if item.get("ok") else [item],
        }

    rotate_environment = _bool_from_payload(payload, "env_random_enabled")
    env_profile = None if rotate_environment else prepare_environment_profile_from_payload(payload, fallback_proxy=str(payload.get("proxy") or ""))
    effective_proxy = "" if env_profile is None else str(env_profile.proxy or payload.get("proxy") or "").strip()
    print(f"阶段：手机直注批量启动 目标={requested_total} 线程={worker_count}")
    if env_profile is None:
        print("阶段：环境模块 随机环境已启用：每个并发单元/换号都会重新抽取 UA/语言/时区/视口/代理")
    else:
        print(f"阶段：环境模块 {summarize_environment_profile(env_profile)}")
    successes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def _worker(index: int) -> dict[str, Any]:
        worker_log_tokens = set_log_context(worker_id=f"{index}/{requested_total}")
        try:
            worker_payload = dict(payload or {})
            worker_payload["total"] = 1
            worker_payload["threads"] = 1
            print(f"阶段：手机直注并发单元 {index}/{requested_total} 已启动")
            if rotate_environment:
                hero_sms = _sms_config_from_payload(worker_payload)
                attempt_limit = _sms_retry_count_from_payload(worker_payload, hero_sms.auto_retry)
                attempted_phones: list[str] = []
                last_error = ""
                for attempt_index in range(1, attempt_limit + 1):
                    attempt_payload = dict(worker_payload)
                    attempt_payload["sms_retry_count"] = 1
                    attempt_payload["hero_sms_retry_count"] = 1
                    attempt_env_profile = prepare_environment_profile_from_payload(attempt_payload, fallback_proxy=str(attempt_payload.get("proxy") or ""))
                    attempt_proxy = str(attempt_env_profile.proxy or attempt_payload.get("proxy") or "").strip()
                    print(
                        f"阶段：并发单元 {index}/{requested_total} 第 {attempt_index}/{attempt_limit} 次环境 "
                        f"{summarize_environment_profile(attempt_env_profile)}"
                    )
                    try:
                        item = _phone_direct_once(
                            attempt_payload,
                            env_profile=attempt_env_profile,
                            effective_proxy=attempt_proxy,
                            manage_environment=True,
                            log_environment=False,
                            worker_index=index,
                            worker_total=requested_total,
                        )
                        for phone in item.get("phones_attempted") or []:
                            if phone and phone not in attempted_phones:
                                attempted_phones.append(str(phone))
                        if attempted_phones:
                            item["phones_attempted"] = list(attempted_phones)
                        print(f"阶段：手机直注并发单元 {index}/{requested_total} 已完成")
                        return item
                    except Exception as exc:
                        last_error = _unwrap_sms_retry_error(str(exc))
                        phones = getattr(exc, "phones_attempted", None)
                        if phones:
                            for phone in phones:
                                if phone and phone not in attempted_phones:
                                    attempted_phones.append(str(phone))
                        else:
                            phone = str(getattr(exc, "phone_number", "") or "")
                            if phone and phone not in attempted_phones:
                                attempted_phones.append(phone)
                        if _is_sms_inventory_error(last_error) or not hero_sms.auto_retry or attempt_index >= attempt_limit:
                            retry_error = RuntimeError(_sms_retry_exhausted_message(hero_sms.provider, attempt_limit, last_error))
                            try:
                                setattr(retry_error, "phones_attempted", list(attempted_phones))
                                if attempted_phones:
                                    setattr(retry_error, "phone_number", attempted_phones[-1])
                            except Exception:
                                pass
                            raise retry_error
                        print(
                            f"阶段：并发单元 {index}/{requested_total} 当前环境/号码失败，"
                            f"将重新抽取环境并换号重试（{attempt_index}/{attempt_limit}），错误={last_error}"
                        )
                raise RuntimeError(last_error or "phone_direct_failed")
            item = _phone_direct_once(
                worker_payload,
                env_profile=env_profile,
                effective_proxy=effective_proxy,
                manage_environment=False,
                log_environment=False,
                worker_index=index,
                worker_total=requested_total,
            )
            print(f"阶段：手机直注并发单元 {index}/{requested_total} 已完成")
            return item
        finally:
            reset_log_context(worker_log_tokens)

    executor_context = nullcontext() if rotate_environment else environment_profile_context(env_profile)
    with executor_context:
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {executor.submit(_worker, index): index for index in range(1, requested_total + 1)}
            for future in as_completed(futures):
                index = futures[future]
                try:
                    item = future.result()
                    if item.get("ok"):
                        successes.append(item)
                    else:
                        failures.append({"ok": False, "worker": index, "error": str(item.get("error") or "phone_direct_failed"), **item})
                except Exception as exc:
                    error_item = {"ok": False, "worker": index, "error": str(exc)}
                    phones_attempted = getattr(exc, "phones_attempted", None)
                    if phones_attempted:
                        error_item["phones_attempted"] = list(phones_attempted)
                        error_item["phone_number"] = str(error_item["phones_attempted"][-1] or "")
                    failures.append(error_item)
                    print(f"阶段：手机直注并发单元 {index}/{requested_total} 失败：{exc}")

    ok = len(successes) >= requested_total
    result: dict[str, Any] = {
        "ok": ok,
        "target_total": requested_total,
        "threads": worker_count,
        "success_count": len(successes),
        "failure_count": len(failures),
        "items": successes,
        "failures": failures[-10:],
    }
    if successes:
        result.update(
            {
                "phone_number": str(successes[-1].get("phone_number") or ""),
                "password": str(successes[-1].get("password") or ""),
                "bind_email": str(successes[-1].get("bind_email") or ""),
                "email": str(successes[-1].get("email") or ""),
                "callback_url": str(successes[-1].get("callback_url") or ""),
            }
        )
    if not ok:
        result["error"] = "phone_direct_target_not_reached"
    print(f"阶段：手机直注批量完成 成功={len(successes)}/{requested_total} 失败={len(failures)}")
    return result


def _delete_data_file(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    path = (DATA_DIR / name).resolve()
    if (
        path.parent != DATA_DIR.resolve()
        or path.suffix.lower() != ".json"
        or path.name == WEBUI_CONFIG_PATH.name
        or not path.exists()
    ):
        raise ValueError("file_not_found")
    path.unlink()
    return {"ok": True, "deleted": path.name}


def _data_files() -> list[dict[str, Any]]:
    ensure_dirs()
    files: list[dict[str, Any]] = []
    for path in sorted(DATA_DIR.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True):
        if path.name == WEBUI_CONFIG_PATH.name:
            continue
        stat = path.stat()
        files.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            }
        )
    return files


def _export_config_bytes() -> bytes:
    config = _load_webui_config()
    return (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
