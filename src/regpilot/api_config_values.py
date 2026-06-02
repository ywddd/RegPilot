from __future__ import annotations

import math
import re
from typing import Any

from fastapi import HTTPException

from . import microsoft_mail_pool
from .api_tasks import (
    _load_webui_config as _load_webui_config_with_defaults,
    _save_webui_config as _save_webui_config_with_defaults,
)
from .sms_provider_config import sms_api_key_from_values, sms_provider_from_values


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


def _prefer_reauthorize_sms_values(payload: Any) -> dict[str, Any]:
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
