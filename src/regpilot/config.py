from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
LOG_DIR = BASE_DIR / "logs"


def parse_bool(value: object, *, default: bool = False, key: str = "boolean") -> bool:
    if value in (None, ""):
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    raise ValueError(f"invalid_{key}")


@dataclass
class MailConfig:
    request_timeout: int = 30
    wait_timeout: int = 30
    wait_interval: int = 2
    providers: list[dict] = field(default_factory=list)
    proxy: str = ""


@dataclass
class RegisterConfig:
    proxy: str = ""
    env_random_enabled: bool = False
    env_proxy_pool: str = ""
    env_ua_pool: str = ""
    env_accept_language_pool: str = ""
    env_timezone_pool: str = ""
    env_viewport_pool: str = ""
    total: int = 1
    threads: int = 1
    default_password: str = ""
    mail: MailConfig = field(default_factory=MailConfig)
    codex2api_url: str = ""
    codex2api_admin_key: str = ""
    codex2api_proxy_url: str = ""
    codex2api_auto_import: bool = False
    hero_sms_api_key: str = ""
    hero_sms_base_url: str = "https://hero-sms.com/stubs/handler_api.php"
    sms_provider: str = "hero_sms"
    sms_api_key: str = ""
    smsbower_api_key: str = ""
    fivesim_api_key: str = ""
    smsbower_base_url: str = "https://smsbower.page/stubs/handler_api.php"
    hero_sms_country: str = "16"
    hero_sms_service: str = "dr"
    hero_sms_min_price: float = 0.0
    hero_sms_max_price: float = 0.0
    hero_sms_wait_timeout: int = 180
    hero_sms_wait_interval: int = 5
    hero_sms_auto_retry: bool = False
    hero_sms_retry_count: int = 3
    reuse_phone_number: str = ""
    reuse_activation_id: str = ""


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
