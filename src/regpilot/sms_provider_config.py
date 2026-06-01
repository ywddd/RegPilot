from __future__ import annotations

from typing import Any

from .oauth_token_flow import (
    FIVESIM_BASE_URL,
    HERO_SMS_MAX_RETRY_COUNT,
    HERO_SMS_RELEASE_AFTER_SECONDS,
    HERO_SMS_RESEND_AFTER_SECONDS,
    HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS,
    HeroSMSConfig,
    SMSBOWER_BASE_URL,
)

HERO_SMS_BASE_URL = "https://hero-sms.com/stubs/handler_api.php"


def normalize_sms_provider(value: Any, *, default: str = "hero_sms", strict: bool = True) -> str:
    raw = str(value if value not in (None, "") else default).strip().lower().replace("-", "_").replace(" ", "_")
    if raw in {"5sim", "five_sim", "fivesim", "five"}:
        return "5sim"
    if raw in {"hero_sms", "herosms", "hero"}:
        return "hero_sms"
    if raw in {"smsbower", "sms_bower", "smsbower_page"}:
        return "smsbower"
    if strict:
        raise ValueError("invalid_sms_provider")
    return "hero_sms"


def sms_provider_from_values(values: dict[str, Any], *, default: str = "hero_sms") -> str:
    return normalize_sms_provider(values.get("sms_provider") or values.get("phone_sms_provider"), default=default)


def sms_api_key_from_values(values: dict[str, Any], provider: str | None = None) -> str:
    resolved_provider = provider or sms_provider_from_values(values)
    generic_key = str(values.get("sms_api_key") or "").strip()
    if resolved_provider == "smsbower":
        return str(values.get("smsbower_api_key") or generic_key or "").strip()
    if resolved_provider == "5sim":
        return str(values.get("fivesim_api_key") or generic_key or values.get("hero_sms_api_key") or "").strip()
    return str(values.get("hero_sms_api_key") or generic_key or "").strip()


def sms_base_url_from_values(values: dict[str, Any], provider: str) -> str:
    if provider == "smsbower":
        return str(values.get("smsbower_base_url") or SMSBOWER_BASE_URL).strip() or SMSBOWER_BASE_URL
    if provider == "5sim":
        base_url = str(values.get("fivesim_base_url") or values.get("hero_sms_base_url") or FIVESIM_BASE_URL).strip() or FIVESIM_BASE_URL
        lowered = base_url.lower()
        if "hero-sms.com" in lowered or "smsbower" in lowered:
            return FIVESIM_BASE_URL
        return base_url
    return str(values.get("hero_sms_base_url") or HERO_SMS_BASE_URL).strip() or HERO_SMS_BASE_URL


def sms_country_service_from_values(values: dict[str, Any], provider: str) -> tuple[str, str]:
    default_country = "england" if provider == "5sim" else "16"
    default_service = "openai" if provider == "5sim" else "dr"
    country = str(values.get("hero_sms_country") or "").strip()
    service = str(values.get("hero_sms_service") or "").strip()
    if provider == "5sim":
        if not country or country.isdigit():
            country = default_country
        if not service or service == "dr":
            service = default_service
    else:
        country = country or default_country
        service = service or default_service
    return country, service


def _float_from_values(values: dict[str, Any], key: str, default: float = 0.0) -> float:
    raw = values.get(key)
    if raw in (None, ""):
        return default
    try:
        return float(raw)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"invalid_{key}") from None


def _positive_int_from_values(
    values: dict[str, Any],
    key: str,
    legacy_key: str = "",
    default: int = 1,
    minimum: int = 1,
) -> int:
    raw = values.get(key)
    if raw in (None, "") and legacy_key:
        raw = values.get(legacy_key)
    if raw in (None, ""):
        return max(minimum, int(default))
    try:
        return max(minimum, int(raw))
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"invalid_{key}") from None


def _bool_from_values(values: dict[str, Any], key: str, legacy_key: str = "", default: bool = False) -> bool:
    raw = values.get(key)
    if raw in (None, "") and legacy_key:
        raw = values.get(legacy_key)
    if raw in (None, ""):
        return bool(default)
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
    raise ValueError(f"invalid_{key}")


def build_sms_config_from_values(
    values: dict[str, Any],
    *,
    default_wait_timeout: int = 60,
    default_wait_interval: int = 5,
    default_resend_after_seconds: int = HERO_SMS_RESEND_AFTER_SECONDS,
    default_timeout_after_resend_seconds: int = HERO_SMS_TIMEOUT_AFTER_RESEND_SECONDS,
    default_release_after_seconds: int = HERO_SMS_RELEASE_AFTER_SECONDS,
    default_retry_count: int = HERO_SMS_MAX_RETRY_COUNT,
) -> HeroSMSConfig:
    provider = sms_provider_from_values(values)
    country, service = sms_country_service_from_values(values, provider)
    return HeroSMSConfig(
        provider=provider,
        api_key=sms_api_key_from_values(values, provider),
        base_url=sms_base_url_from_values(values, provider),
        country=country,
        service=service,
        min_price=_float_from_values(values, "hero_sms_min_price"),
        max_price=_float_from_values(values, "hero_sms_max_price"),
        wait_timeout=_positive_int_from_values(values, "sms_wait_timeout", "hero_sms_wait_timeout", default_wait_timeout, 15),
        wait_interval=_positive_int_from_values(values, "sms_wait_interval", "hero_sms_wait_interval", default_wait_interval, 1),
        auto_retry=_bool_from_values(values, "sms_auto_retry", "hero_sms_auto_retry"),
        resend_after_seconds=_positive_int_from_values(values, "sms_resend_after_seconds", "hero_sms_resend_after_seconds", default_resend_after_seconds, 1),
        timeout_after_resend_seconds=_positive_int_from_values(values, "sms_timeout_after_resend_seconds", "hero_sms_timeout_after_resend_seconds", default_timeout_after_resend_seconds, 1),
        release_after_seconds=_positive_int_from_values(values, "sms_release_after_seconds", "hero_sms_release_after_seconds", default_release_after_seconds, 15),
        max_retry_count=_positive_int_from_values(values, "sms_retry_count", "hero_sms_retry_count", default_retry_count, 1),
    )
