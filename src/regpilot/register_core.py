from __future__ import annotations

import base64
import contextvars
import hashlib
import html
import json
import random
import re
import secrets
import string
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse, urlencode, urlunparse
from zoneinfo import ZoneInfo

import requests
import urllib3
from curl_cffi import requests as curl_requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .config import DATA_DIR, RegisterConfig, parse_bool
from .logging_utils import log
from . import mail_provider

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

auth_base = "https://auth.openai.com"
platform_base = "https://platform.openai.com"
platform_oauth_client_id = "app_EMoamEEZ73f0CkXaXp7hrann"
platform_oauth_redirect_uri = f"{platform_base}/auth/callback"
platform_oauth_audience = "https://api.openai.com/v1"
chatgpt_signup_client_id = "app_X8zY6vW2pQ9tR3dE7nK1jL5gH"
chatgpt_signup_redirect_uri = "https://chatgpt.com/api/auth/callback/openai"
chatgpt_signup_scope = "openid email profile offline_access model.request model.read organization.read organization.write"
default_timeout = 30
DEFAULT_ENV_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.7103.92 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.7049.115 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.6998.166 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.6943.127 Safari/537.36",
]
DEFAULT_ENV_ACCEPT_LANGUAGE_POOL = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.9,zh-CN;q=0.8",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.8",
]
DEFAULT_ENV_TIMEZONE_POOL = [
    "America/New_York",
    "America/Chicago",
    "America/Los_Angeles",
    "Europe/London",
    "Asia/Singapore",
]
DEFAULT_ENV_VIEWPORT_POOL = [
    (1920, 1080),
    (1680, 1050),
    (1600, 900),
    (1536, 864),
    (1440, 900),
    (1366, 768),
]
_ENV_SPLIT_RE = re.compile(r"[\r\n,;]+")
_ENV_LOCK = threading.RLock()


@dataclass
class EnvironmentProfile:
    user_agent: str
    accept_language: str
    timezone: str
    viewport_width: int
    viewport_height: int
    proxy: str = ""
    randomized: bool = False


def _chrome_major_from_ua(ua: str) -> str:
    match = re.search(r"Chrome/(\d+)", str(ua or ""))
    return str(match.group(1)) if match else "136"


def _chrome_full_from_ua(ua: str) -> str:
    match = re.search(r"Chrome/([0-9.]+)", str(ua or ""))
    return str(match.group(1)) if match else "136.0.7103.92"


def _sec_ch_ua_for_major(major: str) -> str:
    safe_major = str(major or "136").strip() or "136"
    return f'"Not(A:Brand";v="99", "Google Chrome";v="{safe_major}", "Chromium";v="{safe_major}"'


def _sec_ch_ua_full_version_list(full_version: str) -> str:
    safe = str(full_version or "136.0.7103.92").strip() or "136.0.7103.92"
    return f'"Chromium";v="{safe}", "Not:A-Brand";v="99.0.0.0", "Google Chrome";v="{safe}"'


def _split_pool_text(raw: str) -> list[str]:
    text = str(raw or "").strip()
    if not text:
        return []
    items = [part.strip() for part in _ENV_SPLIT_RE.split(text)]
    return [item for item in items if item]


def _parse_viewport(item: str) -> tuple[int, int] | None:
    token = str(item or "").strip().lower().replace(" ", "")
    if not token:
        return None
    match = re.match(r"^(\d{3,4})[x\*](\d{3,4})$", token)
    if not match:
        return None
    width = int(match.group(1))
    height = int(match.group(2))
    if width < 320 or height < 320:
        return None
    return width, height


def _viewport_pool_from_text(raw: str) -> list[tuple[int, int]]:
    parsed: list[tuple[int, int]] = []
    for token in _split_pool_text(raw):
        viewport = _parse_viewport(token)
        if viewport:
            parsed.append(viewport)
    return parsed


def _build_common_headers() -> dict[str, str]:
    return {
        "accept": "application/json",
        "accept-language": get_accept_language(),
        "content-type": "application/json",
        "origin": auth_base,
        "priority": "u=1, i",
        "user-agent": get_user_agent(),
        "sec-ch-ua": get_sec_ch_ua(),
        "sec-ch-ua-arch": '"x86_64"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version-list": get_sec_ch_ua_full_version_list(),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-model": '""',
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"10.0.0"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }


def _build_navigate_headers() -> dict[str, str]:
    return {
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": get_accept_language(),
        "user-agent": get_user_agent(),
        "sec-ch-ua": get_sec_ch_ua(),
        "sec-ch-ua-arch": '"x86_64"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-full-version-list": get_sec_ch_ua_full_version_list(),
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-model": '""',
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"10.0.0"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "same-origin",
        "sec-fetch-user": "?1",
        "upgrade-insecure-requests": "1",
    }


def _default_environment_profile(proxy: str = "") -> EnvironmentProfile:
    ua = DEFAULT_ENV_UA_POOL[0]
    viewport = DEFAULT_ENV_VIEWPORT_POOL[0]
    return EnvironmentProfile(
        user_agent=ua,
        accept_language=DEFAULT_ENV_ACCEPT_LANGUAGE_POOL[0],
        timezone=DEFAULT_ENV_TIMEZONE_POOL[0],
        viewport_width=int(viewport[0]),
        viewport_height=int(viewport[1]),
        proxy=str(proxy or "").strip(),
        randomized=False,
    )


def build_environment_profile(
    *,
    enabled: bool,
    fallback_proxy: str = "",
    proxy_pool_text: str = "",
    ua_pool_text: str = "",
    accept_language_pool_text: str = "",
    timezone_pool_text: str = "",
    viewport_pool_text: str = "",
) -> EnvironmentProfile:
    fallback = _default_environment_profile(proxy=fallback_proxy)
    if not enabled:
        return fallback

    ua_pool = _split_pool_text(ua_pool_text) or list(DEFAULT_ENV_UA_POOL)
    lang_pool = _split_pool_text(accept_language_pool_text) or list(DEFAULT_ENV_ACCEPT_LANGUAGE_POOL)
    tz_pool = _split_pool_text(timezone_pool_text) or list(DEFAULT_ENV_TIMEZONE_POOL)
    viewport_pool = _viewport_pool_from_text(viewport_pool_text) or list(DEFAULT_ENV_VIEWPORT_POOL)
    proxy_pool = _split_pool_text(proxy_pool_text)
    selected_proxy = random.choice(proxy_pool) if proxy_pool else str(fallback_proxy or "").strip()
    viewport = random.choice(viewport_pool)
    return EnvironmentProfile(
        user_agent=random.choice(ua_pool),
        accept_language=random.choice(lang_pool),
        timezone=random.choice(tz_pool),
        viewport_width=int(viewport[0]),
        viewport_height=int(viewport[1]),
        proxy=selected_proxy,
        randomized=True,
    )


def prepare_environment_profile_from_config(config: RegisterConfig) -> EnvironmentProfile:
    return build_environment_profile(
        enabled=parse_bool(getattr(config, "env_random_enabled", False), key="env_random_enabled"),
        fallback_proxy=str(getattr(config, "proxy", "") or ""),
        proxy_pool_text=str(getattr(config, "env_proxy_pool", "") or ""),
        ua_pool_text=str(getattr(config, "env_ua_pool", "") or ""),
        accept_language_pool_text=str(getattr(config, "env_accept_language_pool", "") or ""),
        timezone_pool_text=str(getattr(config, "env_timezone_pool", "") or ""),
        viewport_pool_text=str(getattr(config, "env_viewport_pool", "") or ""),
    )


def prepare_environment_profile_from_payload(payload: dict[str, Any], fallback_proxy: str = "") -> EnvironmentProfile:
    data = payload if isinstance(payload, dict) else {}
    return build_environment_profile(
        enabled=parse_bool(data.get("env_random_enabled"), key="env_random_enabled"),
        fallback_proxy=str(data.get("proxy") or fallback_proxy or ""),
        proxy_pool_text=str(data.get("env_proxy_pool") or ""),
        ua_pool_text=str(data.get("env_ua_pool") or ""),
        accept_language_pool_text=str(data.get("env_accept_language_pool") or ""),
        timezone_pool_text=str(data.get("env_timezone_pool") or ""),
        viewport_pool_text=str(data.get("env_viewport_pool") or ""),
    )


def summarize_environment_profile(profile: EnvironmentProfile) -> str:
    ua_major = _chrome_major_from_ua(profile.user_agent)
    mode = "随机" if profile.randomized else "默认"
    proxy_text = profile.proxy if profile.proxy else "无"
    return (
        f"{mode} UA=Chrome/{ua_major} 语言={profile.accept_language} "
        f"时区={profile.timezone} 视口={profile.viewport_width}x{profile.viewport_height} 代理={proxy_text}"
    )


def _snapshot_environment_state() -> dict[str, Any]:
    return {
        "user_agent": _user_agent_var.get(),
        "sec_ch_ua": _sec_ch_ua_var.get(),
        "sec_ch_ua_full_version_list": _sec_ch_ua_full_version_list_var.get(),
        "current_accept_language": _accept_language_var.get(),
        "current_timezone": _timezone_var.get(),
        "current_viewport_width": _viewport_width_var.get(),
        "current_viewport_height": _viewport_height_var.get(),
        "common_headers": _build_common_headers(),
        "navigate_headers": _build_navigate_headers(),
    }


def _apply_environment_state(profile: EnvironmentProfile) -> None:
    ua = str(profile.user_agent).strip() or DEFAULT_ENV_UA_POOL[0]
    major = _chrome_major_from_ua(ua)
    full = _chrome_full_from_ua(ua)
    accept_language = str(profile.accept_language).strip() or DEFAULT_ENV_ACCEPT_LANGUAGE_POOL[0]
    timezone = str(profile.timezone).strip() or DEFAULT_ENV_TIMEZONE_POOL[0]
    viewport_width = int(profile.viewport_width or DEFAULT_ENV_VIEWPORT_POOL[0][0])
    viewport_height = int(profile.viewport_height or DEFAULT_ENV_VIEWPORT_POOL[0][1])
    _user_agent_var.set(ua)
    _sec_ch_ua_var.set(_sec_ch_ua_for_major(major))
    _sec_ch_ua_full_version_list_var.set(_sec_ch_ua_full_version_list(full))
    _accept_language_var.set(accept_language)
    _timezone_var.set(timezone)
    _viewport_width_var.set(viewport_width)
    _viewport_height_var.set(viewport_height)


def _restore_environment_state(snapshot: dict[str, Any]) -> None:
    ua = str(snapshot.get("user_agent") or DEFAULT_ENV_UA_POOL[0])
    _user_agent_var.set(ua)
    _sec_ch_ua_var.set(str(snapshot.get("sec_ch_ua") or _sec_ch_ua_for_major(_chrome_major_from_ua(ua))))
    _sec_ch_ua_full_version_list_var.set(
        str(snapshot.get("sec_ch_ua_full_version_list") or _sec_ch_ua_full_version_list(_chrome_full_from_ua(ua)))
    )
    _accept_language_var.set(str(snapshot.get("current_accept_language") or DEFAULT_ENV_ACCEPT_LANGUAGE_POOL[0]))
    _timezone_var.set(str(snapshot.get("current_timezone") or DEFAULT_ENV_TIMEZONE_POOL[0]))
    _viewport_width_var.set(int(snapshot.get("current_viewport_width") or DEFAULT_ENV_VIEWPORT_POOL[0][0]))
    _viewport_height_var.set(int(snapshot.get("current_viewport_height") or DEFAULT_ENV_VIEWPORT_POOL[0][1]))


@contextmanager
def environment_profile_context(profile: EnvironmentProfile):
    snapshot = _snapshot_environment_state()
    _apply_environment_state(profile)
    try:
        yield
    finally:
        _restore_environment_state(snapshot)


_DEFAULT_ENV = _default_environment_profile()
_user_agent_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_user_agent", default=_DEFAULT_ENV.user_agent
)
_sec_ch_ua_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_sec_ch_ua", default=_sec_ch_ua_for_major(_chrome_major_from_ua(_DEFAULT_ENV.user_agent))
)
_sec_ch_ua_full_version_list_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_sec_ch_ua_full_version_list",
    default=_sec_ch_ua_full_version_list(_chrome_full_from_ua(_DEFAULT_ENV.user_agent)),
)
_accept_language_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_accept_language", default=_DEFAULT_ENV.accept_language
)
_timezone_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_timezone", default=_DEFAULT_ENV.timezone
)
_viewport_width_var: contextvars.ContextVar[int] = contextvars.ContextVar(
    "regpilot_viewport_width", default=_DEFAULT_ENV.viewport_width
)
_viewport_height_var: contextvars.ContextVar[int] = contextvars.ContextVar(
    "regpilot_viewport_height", default=_DEFAULT_ENV.viewport_height
)


def get_user_agent() -> str:
    return _user_agent_var.get()


def get_sec_ch_ua() -> str:
    return _sec_ch_ua_var.get()


def get_sec_ch_ua_full_version_list() -> str:
    return _sec_ch_ua_full_version_list_var.get()


def get_accept_language() -> str:
    return _accept_language_var.get()


def get_timezone() -> str:
    return _timezone_var.get()


def get_viewport_width() -> int:
    return _viewport_width_var.get()


def get_viewport_height() -> int:
    return _viewport_height_var.get()


def get_common_headers() -> dict[str, str]:
    return _build_common_headers()


def get_navigate_headers() -> dict[str, str]:
    return _build_navigate_headers()


def __getattr__(name: str) -> Any:
    if name == "user_agent":
        return _user_agent_var.get()
    if name == "sec_ch_ua":
        return _sec_ch_ua_var.get()
    if name == "sec_ch_ua_full_version_list":
        return _sec_ch_ua_full_version_list_var.get()
    if name == "current_accept_language":
        return _accept_language_var.get()
    if name == "current_timezone":
        return _timezone_var.get()
    if name == "current_viewport_width":
        return _viewport_width_var.get()
    if name == "current_viewport_height":
        return _viewport_height_var.get()
    if name == "common_headers":
        return _build_common_headers()
    if name == "navigate_headers":
        return _build_navigate_headers()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


@dataclass
class RegistrationResult:
    ok: bool
    email: str = ""
    password: str = ""
    access_token: str = ""
    refresh_token: str = ""
    id_token: str = ""
    mailbox: dict[str, Any] | None = None
    callback_url: str = ""
    error: str = ""


def _make_trace_headers() -> dict[str, str]:
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    return {
        "traceparent": f"00-{uuid.uuid4().hex}-{format(int(parent_id), '016x')}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


def _generate_pkce() -> tuple[str, str]:
    code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode("ascii")
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def _random_password(length: int = 16) -> str:
    chars = string.ascii_letters + string.digits + "!@#$%"
    value = list(
        secrets.choice(string.ascii_uppercase)
        + secrets.choice(string.ascii_lowercase)
        + secrets.choice(string.digits)
        + secrets.choice("!@#$%")
        + "".join(secrets.choice(chars) for _ in range(max(0, length - 4)))
    )
    random.shuffle(value)
    return "".join(value)


def _random_name() -> tuple[str, str]:
    first_names = [
        "James", "Robert", "John", "Michael", "David", "William", "Richard", "Thomas", "Daniel", "Matthew",
        "Mary", "Emma", "Olivia", "Sophia", "Emily", "Grace", "Lily", "Anna", "Chloe", "Nora",
    ]
    last_names = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Moore",
        "Taylor", "Anderson", "Thomas", "Martin", "Lee", "Walker", "Hall", "Allen", "Young", "King",
    ]
    return random.choice(first_names), random.choice(last_names)


def _random_birthdate() -> str:
    # Keep accounts clearly adult while avoiding a too-narrow repeated date distribution.
    return f"{random.randint(1985, 2004):04d}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"


def _age_from_birthdate(birthdate: str, today: date | None = None) -> int:
    current = today or date.today()
    try:
        year_text, month_text, day_text = str(birthdate or "").split("-", 2)
        born = date(int(year_text), int(month_text), int(day_text))
        age = current.year - born.year - ((current.month, current.day) < (born.month, born.day))
        return max(18, min(80, age))
    except Exception:
        return 21


def _about_you_page_shape(page_context: str = "") -> dict[str, Any]:
    raw = str(page_context or "")
    lowered = raw.lower()
    shape: dict[str, Any] = {
        "visible_age": False,
        "hidden_age": False,
        "visible_birthday": False,
        "hidden_birthday": False,
        "visible_birthdate": False,
        "hidden_birthdate": False,
        "age_cue": bool(re.search(r"\bage\b|how old are you|年龄|几岁", lowered)),
        "birthday_cue": bool(re.search(r"birth(?:day|date)|date of birth|生日|出生", lowered)),
        "preferred": "unknown",
        "birthday_fields": ["birthdate", "birthday"],
    }
    for input_match in re.finditer(r"<input\b([^>]*)>", raw, re.I | re.S):
        attrs = input_match.group(1) or ""
        name = _extract_attr(attrs, "name").strip().lower()
        if name not in {"age", "birthday", "birthdate"}:
            continue
        input_type = _extract_attr(attrs, "type").strip().lower()
        hidden_attr = bool(re.search(r"(?:^|\s)hidden(?:\s|=|$)", attrs, re.I))
        style = _extract_attr(attrs, "style").lower()
        is_hidden = input_type == "hidden" or hidden_attr or "display:none" in style or "display: none" in style
        key = f"{'hidden' if is_hidden else 'visible'}_{name}"
        shape[key] = True

    if shape["visible_birthdate"]:
        shape["birthday_fields"] = ["birthdate", "birthday"]
    elif shape["visible_birthday"]:
        shape["birthday_fields"] = ["birthday", "birthdate"]
    elif "name=\"birthday\"" in lowered or "name='birthday'" in lowered:
        shape["birthday_fields"] = ["birthday", "birthdate"]

    has_visible_birthday = bool(shape["visible_birthdate"] or shape["visible_birthday"])
    if shape["visible_age"] and not has_visible_birthday:
        shape["preferred"] = "age"
    elif has_visible_birthday:
        shape["preferred"] = "birthday"
    elif shape["age_cue"] and not shape["birthday_cue"]:
        shape["preferred"] = "age"
    elif shape["birthday_cue"]:
        shape["preferred"] = "birthday"
    return shape


def _about_you_shape_log_summary(page_context: str = "") -> str:
    shape = _about_you_page_shape(page_context)
    visible = []
    hidden = []
    for key, label in (("age", "年龄"), ("birthdate", "出生日期"), ("birthday", "生日")):
        if shape.get(f"visible_{key}"):
            visible.append(label)
        if shape.get(f"hidden_{key}"):
            hidden.append(label)
    cues = []
    if shape.get("age_cue"):
        cues.append("年龄")
    if shape.get("birthday_cue"):
        cues.append("生日")
    consent_fields = _about_you_consent_fields(page_context)
    preferred_map = {"age": "年龄", "birthdate": "出生日期", "birthday": "生日", "unknown": "未识别"}
    return (
        f"优先填写={preferred_map.get(str(shape.get('preferred') or 'unknown'), str(shape.get('preferred') or '未识别'))} "
        f"可见字段={'+'.join(visible) or '-'} "
        f"隐藏字段={'+'.join(hidden) or '-'} "
        f"提示词={'+'.join(cues) or '-'} "
        f"同意字段={'+'.join(consent_fields.keys()) or '-'}"
    )


def _about_you_consent_fields(page_context: str = "") -> dict[str, str]:
    raw = str(page_context or "")
    fields: dict[str, str] = {}
    has_explicit_marker = bool(re.search(r"isExplicitConsentRequired", raw, re.I))

    def is_required(attrs: str) -> bool:
        return bool(re.search(r"(?:^|\s)required(?:\s|=|$)", attrs, re.I))

    def is_consent_like(field_name: str, attrs: str) -> bool:
        haystack = f"{field_name} {attrs}".lower()
        return bool(
            field_name == "isexplicitconsentrequired"
            or re.search(r"consent|agree|terms|privacy|policy|checkbox|accept", haystack)
        )

    for input_match in re.finditer(r"<input\b([^>]*)>", raw, re.I | re.S):
        attrs = input_match.group(1) or ""
        name = _extract_attr(attrs, "name").strip()
        if not name:
            continue
        normalized_name = name.lower()
        if normalized_name in {"name", "age", "birthday", "birthdate"}:
            continue
        input_type = (_extract_attr(attrs, "type") or "text").strip().lower()
        value = _extract_attr(attrs, "value")
        if input_type == "hidden" and is_consent_like(normalized_name, attrs):
            fields[name] = value if value != "" else "true"
        elif input_type in {"checkbox", "radio"}:
            checked = bool(re.search(r"(?:^|\s)checked(?:\s|=|$)", attrs, re.I))
            if checked or is_required(attrs) or is_consent_like(normalized_name, attrs) or has_explicit_marker:
                fields[name] = value if value != "" else "on"

    if "isExplicitConsentRequired" not in fields:
        marker = re.search(r'\\*["\']isExplicitConsentRequired\\*["\']\s*:\s*(true|false)', raw, re.I)
        if marker:
            fields["isExplicitConsentRequired"] = marker.group(1).lower()
    return fields


def _about_you_create_account_payloads(name: str, birthdate: str, page_context: str = "", email: str = "") -> list[dict[str, Any]]:
    age = str(_age_from_birthdate(birthdate))
    shape = _about_you_page_shape(page_context)
    preferred = str(shape.get("preferred") or "unknown")
    birthday_fields = list(shape.get("birthday_fields") or ["birthdate", "birthday"])
    clean_email = str(email or "").strip()
    ordered: list[dict[str, Any]] = []

    def add(payload: dict[str, Any]) -> None:
        normalized = {key: value for key, value in payload.items() if value not in (None, "")}
        if normalized and normalized not in ordered:
            ordered.append(normalized)

    def add_candidate(payload: dict[str, str]) -> None:
        if clean_email:
            add({**payload, "email": clean_email})
        add(payload)

    if preferred == "age":
        add_candidate({"name": name, "age": age})
        for field in birthday_fields:
            add_candidate({"name": name, field: birthdate})
    elif preferred == "birthday":
        for field in birthday_fields:
            add_candidate({"name": name, field: birthdate})
        add_candidate({"name": name, "age": age})
    else:
        add_candidate({"name": name, "birthdate": birthdate})
        add_candidate({"name": name, "birthday": birthdate})
    add_candidate({"name": name, "age": age})
    return ordered


def _response_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _accounts_error_code(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    error = body.get("error") if isinstance(body.get("error"), dict) else {}
    for value in (error.get("code"), body.get("code"), error.get("type"), body.get("type")):
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _decode_jwt_payload(token: str) -> dict:
    try:
        payload = token.split(".")[1]
        padding = 4 - len(payload) % 4
        if padding != 4:
            payload += "=" * padding
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def _merge_url_query(url: str, **params: str) -> str:
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in params.items():
        if value is None:
            continue
        query[key] = [str(value)]
    merged = urlencode(query, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, merged, parsed.fragment))


def _safe_cookie_get(session: Any, name: str, *preferred_domains: str) -> str:
    jar = getattr(session, "cookies", None)
    if jar is None:
        return ""
    for domain in preferred_domains:
        try:
            value = jar.get(name, domain=domain)
        except Exception:
            value = None
        if value:
            return str(value)
    try:
        value = jar.get(name)
    except Exception:
        value = None
    if value:
        return str(value)
    try:
        for cookie in jar:
            if getattr(cookie, "name", "") != name:
                continue
            domain = str(getattr(cookie, "domain", "") or "")
            if preferred_domains and domain not in preferred_domains:
                continue
            return str(getattr(cookie, "value", "") or "")
        for cookie in jar:
            if getattr(cookie, "name", "") == name:
                return str(getattr(cookie, "value", "") or "")
    except Exception:
        return ""
    return ""


def _cookie_snapshot(session: Any) -> dict[str, str]:
    wanted = [
        "oai-did",
        "oai-client-auth-session",
        "oai-auth-token",
        "__cf_bm",
        "cf_clearance",
        "_cfuvid",
        "did",
        "did_compat",
        "auth_session",
    ]
    values: dict[str, str] = {}
    for name in wanted:
        val = _safe_cookie_get(session, name, ".auth.openai.com", "auth.openai.com")
        if val:
            values[name] = val
    return values


def _summarize_cookie_snapshot(snapshot: dict[str, str]) -> dict[str, Any]:
    summary: dict[str, Any] = {"present": sorted(snapshot.keys())}
    raw = str(snapshot.get("oai-client-auth-session") or "").strip()
    if raw:
        try:
            first_part = raw.split(".")[0]
            padding = 4 - len(first_part) % 4
            if padding != 4:
                first_part += "=" * padding
            payload = json.loads(base64.urlsafe_b64decode(first_part))
            summary["client_auth_session"] = {
                "keys": sorted(payload.keys()) if isinstance(payload, dict) else [],
                "has_workspaces": bool((payload or {}).get("workspaces")) if isinstance(payload, dict) else False,
                "has_session_id": bool((payload or {}).get("session_id")) if isinstance(payload, dict) else False,
            }
        except Exception as exc:
            summary["client_auth_session_decode_error"] = str(exc)
    return summary


def _extract_workspace_id_from_client_auth_session(raw: str) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    try:
        first_part = value.split(".")[0]
        padding = 4 - len(first_part) % 4
        if padding != 4:
            first_part += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(first_part))
        workspaces = payload.get("workspaces") if isinstance(payload, dict) else None
        if isinstance(workspaces, list) and workspaces:
            return str((workspaces[0] or {}).get("id") or "").strip()
    except Exception:
        return ""
    return ""


def _decode_client_auth_session_value(raw: Any) -> dict[str, Any]:
    value = str(raw or "").strip()
    if not value:
        return {}
    try:
        first_part = value.split(".")[0]
        padding = 4 - len(first_part) % 4
        if padding != 4:
            first_part += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(first_part))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}


def _get_session_workspace_id(session: Any) -> str:
    raw = _safe_cookie_get(session, "oai-client-auth-session", ".auth.openai.com", "auth.openai.com")
    return _extract_workspace_id_from_client_auth_session(raw)


def create_mailbox(config: RegisterConfig, username: str | None = None) -> dict:
    return mail_provider.create_mailbox(asdict(config.mail), username)


def wait_for_code(config: RegisterConfig, mailbox: dict) -> str | None:
    return mail_provider.wait_for_code(asdict(config.mail), mailbox)


class SentinelTokenGenerator:
    MAX_ATTEMPTS = 500000
    ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

    def __init__(
        self,
        device_id: str,
        ua: str,
        *,
        accept_language: str = "",
        timezone_name: str = "",
        viewport_width: int = 1920,
        viewport_height: int = 1080,
    ):
        self.device_id = device_id
        self.user_agent = ua
        self.accept_language = str(accept_language or "en-US").split(",", 1)[0].strip() or "en-US"
        self.timezone_name = str(timezone_name or "UTC").strip() or "UTC"
        self.viewport_width = int(viewport_width or 1920)
        self.viewport_height = int(viewport_height or 1080)
        self.sid = str(uuid.uuid4())

    @staticmethod
    def _fnv1a_32(text: str) -> str:
        h = 2166136261
        for ch in text:
            h ^= ord(ch)
            h = (h * 16777619) & 0xFFFFFFFF
        h ^= h >> 16
        h = (h * 2246822507) & 0xFFFFFFFF
        h ^= h >> 13
        h = (h * 3266489909) & 0xFFFFFFFF
        h ^= h >> 16
        return format(h & 0xFFFFFFFF, "08x")

    def _get_config(self) -> list:
        perf_now = random.uniform(1000, 50000)
        tz_name = self.timezone_name
        dt_value: datetime
        try:
            dt_value = datetime.now(ZoneInfo(tz_name))
        except Exception:
            tz_name = "UTC"
            dt_value = datetime.now(ZoneInfo("UTC"))
        tz_abbr = dt_value.tzname() or tz_name
        offset = dt_value.utcoffset()
        total_minutes = int(offset.total_seconds() // 60) if offset else 0
        sign = "+" if total_minutes >= 0 else "-"
        abs_minutes = abs(total_minutes)
        tz_label = f"GMT{sign}{abs_minutes // 60:02d}{abs_minutes % 60:02d} ({tz_abbr})"
        return [
            f"{self.viewport_width}x{self.viewport_height}",
            dt_value.strftime(f"%a %b %d %Y %H:%M:%S {tz_label}"),
            4294705152,
            random.random(),
            self.user_agent,
            "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js",
            None,
            None,
            self.accept_language,
            random.random(),
            random.choice(["vendorSub-undefined", "plugins-undefined", "mimeTypes-undefined", "hardwareConcurrency-undefined"]),
            random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
            random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
            perf_now,
            self.sid,
            "",
            random.choice([4, 8, 12, 16]),
            time.time() * 1000 - perf_now,
        ]

    @staticmethod
    def _b64(data) -> str:
        return base64.b64encode(json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).decode("ascii")

    def generate_requirements_token(self) -> str:
        data = self._get_config()
        data[3] = 1
        data[9] = round(random.uniform(5, 50))
        return "gAAAAAC" + self._b64(data)

    def generate_token(self, seed: str, difficulty: str) -> str:
        start = time.time()
        data = self._get_config()
        difficulty = str(difficulty or "0")
        for i in range(self.MAX_ATTEMPTS):
            data[3] = i
            data[9] = round((time.time() - start) * 1000)
            payload = self._b64(data)
            if self._fnv1a_32(seed + payload)[: len(difficulty)] <= difficulty:
                return "gAAAAAB" + payload + "~S"
        return "gAAAAAB" + self.ERROR_PREFIX + self._b64(str(None))


def build_sentinel_token(session: requests.Session, device_id: str, flow: str) -> str:
    generator = SentinelTokenGenerator(
        device_id,
        get_user_agent(),
        accept_language=get_accept_language(),
        timezone_name=get_timezone(),
        viewport_width=get_viewport_width(),
        viewport_height=get_viewport_height(),
    )
    resp = session.post(
        "https://sentinel.openai.com/backend-api/sentinel/req",
        data=json.dumps({"p": generator.generate_requirements_token(), "id": device_id, "flow": flow}),
        headers={
            "Content-Type": "text/plain;charset=UTF-8",
            "Referer": "https://sentinel.openai.com/backend-api/sentinel/frame.html",
            "Origin": "https://sentinel.openai.com",
            "User-Agent": get_user_agent(),
            "sec-ch-ua": get_sec_ch_ua(),
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        timeout=20,
        verify=False,
    )
    data = _response_json(resp)
    token = str(data.get("token") or "").strip()
    if resp.status_code != 200 or not token:
        raise RuntimeError(f"sentinel_req_failed_{resp.status_code}")
    pow_data = data.get("proofofwork") or {}
    p_value = (
        generator.generate_token(str(pow_data.get("seed") or ""), str(pow_data.get("difficulty") or "0"))
        if pow_data.get("required") and pow_data.get("seed")
        else generator.generate_requirements_token()
    )
    return json.dumps({"p": p_value, "t": "", "c": token, "id": device_id, "flow": flow}, separators=(",", ":"))


def _is_socks_proxy(proxy: str) -> bool:
    candidate = str(proxy or "").strip().lower()
    return candidate.startswith("socks5://") or candidate.startswith("socks5h://")


def create_session(proxy: str = "") -> Any:
    if str(proxy or "").strip():
        return curl_requests.Session(impersonate="chrome", verify=False, proxy=proxy)
    session = requests.Session()
    retry = Retry(total=2, connect=2, read=2, backoff_factor=0.5, status_forcelist=(429, 500, 502, 503, 504))
    adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    return session


def request_with_local_retry(session: requests.Session, method: str, url: str, retry_attempts: int = 3, **kwargs):
    last_error = ""
    timeout = kwargs.pop("timeout", default_timeout)
    attempts = max(1, retry_attempts)
    for index in range(attempts):
        try:
            return session.request(method.upper(), url, timeout=timeout, **kwargs), ""
        except Exception as error:
            last_error = str(error)
            if index < attempts - 1:
                time.sleep(1)
    return None, last_error


def validate_otp(session: requests.Session, device_id: str, code: str):
    headers = get_common_headers()
    headers["referer"] = f"{auth_base}/create-account/email-verification"
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    try:
        headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, "authorize_continue")
    except Exception:
        pass
    resp, error = request_with_local_retry(
        session,
        "post",
        f"{auth_base}/api/accounts/email-otp/validate",
        json={"code": str(code).strip()},
        headers=headers,
        verify=False,
    )
    return resp, error


def extract_oauth_callback_params_from_url(url: str) -> dict[str, str] | None:
    if not url:
        return None
    try:
        params = parse_qs(urlparse(url).query)
    except Exception:
        return None
    code = str((params.get("code") or [""])[0]).strip()
    if not code:
        return None
    return {"code": code, "state": str((params.get("state") or [""])[0]).strip(), "scope": str((params.get("scope") or [""])[0]).strip()}


def _extract_oauth_callback_params_from_text(text: str) -> dict[str, str] | None:
    raw = str(text or "")
    if not raw:
        return None
    variants = [raw]
    if "\\/" in raw:
        variants.append(raw.replace("\\/", "/"))
    for variant in variants:
        for match in re.finditer(r"https?://[^\"'\s<>\\]+", variant, re.I):
            callback_params = extract_oauth_callback_params_from_url(str(match.group(0) or "").strip())
            if callback_params:
                return callback_params
        for match in re.finditer(r"/(?:auth/callback)\?[^\"'\s<>\\]+", variant, re.I):
            callback_params = extract_oauth_callback_params_from_url(f"{platform_base}{str(match.group(0) or '').strip()}")
            if callback_params:
                return callback_params
    return None


def _extract_oauth_callback_params_from_response(response: requests.Response | None) -> dict[str, str] | None:
    if response is None:
        return None
    callback_params = extract_oauth_callback_params_from_url(str(getattr(response, "url", "") or ""))
    if callback_params:
        return callback_params
    callback_params = extract_oauth_callback_params_from_url(str(getattr(response, "headers", {}).get("Location") or "").strip())
    if callback_params:
        return callback_params
    try:
        body = response.json()
    except Exception:
        body = None
    if isinstance(body, (dict, list)):
        callback_params = _extract_oauth_callback_params_from_text(json.dumps(body, ensure_ascii=False))
        if callback_params:
            return callback_params
    try:
        text = str(getattr(response, "text", "") or "")
    except Exception:
        text = ""
    return _extract_oauth_callback_params_from_text(text)


def _find_workspace_id_from_auth_session_node(node: Any) -> str:
    if isinstance(node, dict):
        decoded = _decode_client_auth_session_value(node.get("client_auth_session"))
        if decoded:
            found = _find_workspace_id_from_auth_session_node(decoded)
            if found:
                return found
        for key in ("workspace_id", "workspaceId"):
            value = str(node.get(key) or "").strip()
            if value:
                return value
        for key in ("workspaces", "workspace"):
            value = node.get(key)
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        item_id = str(item.get("id") or "").strip()
                        if item_id:
                            return item_id
            if isinstance(value, dict):
                item_id = str(value.get("id") or "").strip()
                if item_id:
                    return item_id
            found = _find_workspace_id_from_auth_session_node(value)
            if found:
                return found
        node_type = str(node.get("type") or node.get("kind") or "").lower()
        node_id = str(node.get("id") or "").strip()
        if node_id and "workspace" in node_type:
            return node_id
        for value in node.values():
            found = _find_workspace_id_from_auth_session_node(value)
            if found:
                return found
    if isinstance(node, (list, tuple)):
        for item in node:
            found = _find_workspace_id_from_auth_session_node(item)
            if found:
                return found
    return ""


def _find_org_project_from_auth_session_node(node: Any) -> tuple[str, str]:
    if isinstance(node, dict):
        decoded = _decode_client_auth_session_value(node.get("client_auth_session"))
        if decoded:
            found = _find_org_project_from_auth_session_node(decoded)
            if found[0]:
                return found
        for key in ("orgs", "organizations"):
            value = node.get(key)
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    org_id = str(item.get("id") or item.get("organization_id") or item.get("org_id") or "").strip()
                    projects = item.get("projects") if isinstance(item.get("projects"), list) else []
                    project_id = ""
                    for project in projects:
                        if isinstance(project, dict):
                            project_id = str(project.get("id") or project.get("project_id") or "").strip()
                            if project_id:
                                break
                    if org_id and project_id:
                        return org_id, project_id
                    if org_id:
                        return org_id, ""
        node_type = str(node.get("type") or node.get("kind") or "").lower()
        node_id = str(node.get("id") or node.get("organization_id") or node.get("org_id") or "").strip()
        if node_id and ("org" in node_type or "organization" in node_type):
            projects = node.get("projects") if isinstance(node.get("projects"), list) else []
            project_id = ""
            for project in projects:
                if isinstance(project, dict):
                    project_id = str(project.get("id") or project.get("project_id") or "").strip()
                    if project_id:
                        break
            return node_id, project_id
        for value in node.values():
            found = _find_org_project_from_auth_session_node(value)
            if found[0]:
                return found
    if isinstance(node, (list, tuple)):
        for item in node:
            found = _find_org_project_from_auth_session_node(item)
            if found[0]:
                return found
    return "", ""


def _submit_organization_select_for_consent(
    session: requests.Session,
    org_id: str,
    project_id: str,
    headers: dict[str, str],
    referer: str,
    debug_steps: list[dict[str, Any]] | None,
    source: str,
) -> dict[str, str] | None:
    org_id = str(org_id or "").strip()
    project_id = str(project_id or "").strip()
    if not org_id:
        return None
    org_headers = dict(headers)
    org_headers["accept"] = "application/json"
    org_headers["content-type"] = "application/json"
    org_headers["referer"] = referer or f"{auth_base}/sign-in-with-chatgpt/codex/organization"
    bodies = [{"org_id": org_id}]
    if project_id:
        bodies.insert(0, {"org_id": org_id, "project_id": project_id})
    for body in bodies:
        org_resp = session.post(
            f"{auth_base}/api/accounts/organization/select",
            json=body,
            headers=org_headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        org_summary = _consent_response_summary(org_resp, method="post", target=f"{auth_base}/api/accounts/organization/select", source=source)
        org_summary["payload_keys"] = sorted(body.keys())
        _append_consent_debug(debug_steps, **org_summary)
        callback_params = _extract_oauth_callback_params_from_response(org_resp)
        if callback_params:
            return callback_params
    return None


def _workspace_id_from_client_auth_session_cookie(session: Any) -> str:
    raw = _safe_cookie_get(session, "oai-client-auth-session", ".auth.openai.com", "auth.openai.com")
    if not raw:
        return ""
    try:
        first_part = raw.split(".")[0]
        padding = 4 - len(first_part) % 4
        if padding != 4:
            first_part += "=" * padding
        payload = json.loads(base64.urlsafe_b64decode(first_part))
        return _find_workspace_id_from_auth_session_node(payload)
    except Exception:
        return ""


def _workspace_id_from_consent_html(text: str) -> str:
    raw = str(text or "")
    if not raw:
        return ""
    variants = [raw]
    unescaped = html.unescape(raw)
    if unescaped != raw:
        variants.append(unescaped)
    slash_unescaped = raw.replace('\\"', '"').replace("\\'", "'")
    if slash_unescaped not in variants:
        variants.append(slash_unescaped)
    for value in variants:
        patterns = [
            r"name\s*=\s*[\"']workspace_id[\"'][^>]*value\s*=\s*[\"']([^\"']+)",
            r"value\s*=\s*[\"']([^\"']+)[\"'][^>]*name\s*=\s*[\"']workspace_id[\"']",
            r"[\\]?[\"']current_workspace_id[\\]?[\"']\s*:\s*[\\]?[\"']([^\\\"']+)",
            r"[\\]?[\"']workspace_id[\\]?[\"']\s*:\s*[\\]?[\"']([^\\\"']+)",
            r"[\\]?[\"']workspaceId[\\]?[\"']\s*:\s*[\\]?[\"']([^\\\"']+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, value, re.I | re.S)
            if match:
                workspace_id = str(match.group(1) or "").strip()
                if workspace_id:
                    return workspace_id
    return ""


def _org_project_from_consent_html(text: str) -> tuple[str, str]:
    raw = str(text or "")
    if not raw:
        return "", ""
    variants = [raw]
    unescaped = html.unescape(raw)
    if unescaped != raw:
        variants.append(unescaped)
    slash_unescaped = raw.replace('\\"', '"').replace("\\'", "'")
    if slash_unescaped not in variants:
        variants.append(slash_unescaped)
    for value in variants:
        normalized = value.replace('\\"', '"').replace('\\/', '/').replace('\\n', ' ')
        orgs_index = normalized.find('"orgs"')
        if orgs_index < 0:
            orgs_index = normalized.find('organizations')
        if orgs_index < 0:
            continue
        window = normalized[orgs_index:orgs_index + 20000]
        org_match = re.search(r'"id"\s*:\s*"([0-9a-fA-F-]{20,})"', window)
        if not org_match:
            continue
        org_id = org_match.group(1).strip()
        project_id = ""
        projects_index = window.find('"projects"')
        if projects_index >= 0:
            project_window = window[projects_index:projects_index + 6000]
            project_match = re.search(r'"id"\s*:\s*"([0-9a-fA-F-]{20,})"', project_window)
            if project_match:
                project_id = project_match.group(1).strip()
        return org_id, project_id
    return "", ""


def _extract_attr(attrs: str, name: str) -> str:
    text = str(attrs or "")
    match = re.search(rf'{re.escape(name)}\s*=\s*["\']([^"\']*)["\']', text, re.I | re.S)
    if not match:
        match = re.search(rf'{re.escape(name)}\s*=\s*([^\s"\'<>`]+)', text, re.I | re.S)
    return html.unescape(str(match.group(1) or "").strip()) if match else ""


def _strip_html_tags(value: str) -> str:
    return re.sub(r"<[^>]+>", " ", str(value or ""))


def _extract_consent_form_inputs(html_text: str) -> tuple[str, dict[str, str]]:
    text = str(html_text or "")
    form_matches = list(re.finditer(r"<form\b([^>]*)>(.*?)</form>", text, re.I | re.S))
    if not form_matches:
        return "", {}

    def _score_form(match: re.Match[str]) -> tuple[int, int]:
        attrs = match.group(1) or ""
        body = match.group(2) or ""
        haystack = f"{attrs}\n{_strip_html_tags(body)}".lower()
        score = 0
        for token, weight in [
            ("codex", 30),
            ("consent", 24),
            ("authorize", 24),
            ("allow", 18),
            ("approve", 18),
            ("continue", 10),
            ("confirm", 10),
            ("state", 4),
        ]:
            if token in haystack:
                score += weight
        if re.search(r"<button\b|type\s*=\s*[\"']submit[\"']", body, re.I):
            score += 8
        return score, len(body)

    form_match = max(form_matches, key=_score_form)
    form_attrs = form_match.group(1) or ""
    form_body = form_match.group(2) or ""
    action = _extract_attr(form_attrs, "action")
    payload: dict[str, str] = {}
    submit_choice: tuple[int, str, str, str] | None = None

    def _submit_score(label: str, input_type: str) -> int:
        haystack = f"{label} {input_type}".lower()
        score = 0
        for token, weight in [
            ("codex", 40),
            ("authorize", 35),
            ("allow", 30),
            ("approve", 30),
            ("consent", 24),
            ("confirm", 16),
            ("continue", 12),
            ("submit", 6),
        ]:
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
                payload[name] = value
        if input_type in ("submit", "button", "image"):
            candidate = (_submit_score(f"{name} {value}", input_type), name, value, _extract_attr(attrs, "formaction"))
            if submit_choice is None or candidate[0] > submit_choice[0]:
                submit_choice = candidate

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
        if submit_choice[1] and submit_choice[1] not in payload:
            payload[submit_choice[1]] = submit_choice[2]
        if submit_choice[3]:
            action = submit_choice[3]
    return action, payload


def _append_consent_debug(debug_steps: list[dict[str, Any]] | None, **step: Any) -> None:
    if debug_steps is not None:
        debug_steps.append(step)


def _build_authorize_continue_headers(session: requests.Session, device_id: str, referer: str) -> dict[str, str]:
    headers = get_common_headers()
    headers["referer"] = referer
    headers["oai-device-id"] = device_id
    headers.update(_make_trace_headers())
    try:
        headers["openai-sentinel-token"] = build_sentinel_token(session, device_id, "authorize_continue")
    except Exception as exc:
        headers["x-openai-sentinel-error"] = str(exc)
    return headers


def _consent_data_payloads(workspace_id: str, state: str) -> list[dict[str, str]]:
    payloads: list[dict[str, str]] = []

    def _add(payload: dict[str, str]) -> None:
        normalized = {key: value for key, value in payload.items() if value}
        if normalized and normalized not in payloads:
            payloads.append(normalized)

    _add({"workspace_id": workspace_id, "state": state})
    _add({"workspaceId": workspace_id, "state": state})
    _add({"workspace_id": workspace_id, "action": "authorize", "state": state})
    _add({"workspace_id": workspace_id, "action": "approve", "state": state})
    _add({"workspace_id": workspace_id, "intent": "authorize", "state": state})
    _add({"workspace_id": workspace_id, "_action": "authorize", "state": state})
    return payloads


def _submit_workspace_select_from_consent_form(
    session: requests.Session,
    workspace_id: str,
    headers: dict[str, str],
    consent_url: str,
    debug_steps: list[dict[str, Any]] | None,
    source: str,
) -> dict[str, str] | None:
    payload = {"workspace_id": str(workspace_id or "").strip()}
    if not payload["workspace_id"]:
        return None
    browser_fetch_headers = {
        "accept": "application/json",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "origin": auth_base,
        "priority": "u=1, i",
        "referer": consent_url,
        "user-agent": get_user_agent(),
        "sec-ch-ua": '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    browser_fetch_headers.update(_make_trace_headers())
    enriched_headers = dict(headers)
    enriched_headers["accept"] = "application/json"
    enriched_headers["content-type"] = "application/json"
    enriched_headers["referer"] = consent_url
    for index, ws_headers in enumerate([browser_fetch_headers, enriched_headers], start=1):
        ws_resp = session.post(
            f"{auth_base}/api/accounts/workspace/select",
            json=payload,
            headers=ws_headers,
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        ws_summary = _consent_response_summary(ws_resp, method="post", target=f"{auth_base}/api/accounts/workspace/select", source=source)
        ws_summary["payload_keys"] = sorted(payload.keys())
        ws_summary["header_profile"] = "browser_fetch" if index == 1 else "enriched"
        _append_consent_debug(debug_steps, **ws_summary)
        callback_params = _extract_oauth_callback_params_from_response(ws_resp)
        if callback_params:
            return callback_params
        ws_body = _response_json(ws_resp)
        orgs = ((ws_body.get("data") or {}).get("orgs") or []) if isinstance(ws_body, dict) else []
        if orgs:
            org_id = str((orgs[0] or {}).get("id") or "").strip()
            project_id = str(((orgs[0] or {}).get("projects") or [{}])[0].get("id") or "").strip()
            if org_id:
                callback_params = _submit_organization_select_for_consent(
                    session,
                    org_id,
                    project_id,
                    ws_headers,
                    str(ws_body.get("continue_url") or consent_url),
                    debug_steps,
                    f"{source}_organization_select",
                )
                if callback_params:
                    return callback_params
        follow_url = ""
        if isinstance(ws_body, dict):
            follow_url = str(ws_body.get("continue_url") or ws_body.get("redirect_url") or ws_body.get("url") or "").strip()
        if follow_url:
            try:
                current_follow = follow_url
                seen_follow_urls: set[str] = set()
                for _ in range(6):
                    if current_follow in seen_follow_urls:
                        break
                    seen_follow_urls.add(current_follow)
                    follow_resp = session.get(
                        current_follow,
                        headers=_har_like_browser_fetch_headers(consent_url, accept="application/json, text/html, */*", content_type=""),
                        verify=False,
                        timeout=30,
                        allow_redirects=False,
                    )
                    _append_consent_debug(debug_steps, **_consent_response_summary(follow_resp, method="get", target=current_follow, source=f"{source}_continue"))
                    callback_params = _extract_oauth_callback_params_from_response(follow_resp)
                    if callback_params:
                        return callback_params
                    follow_body = _response_json(follow_resp)
                    if isinstance(follow_body, dict):
                        json_follow = str(follow_body.get("continue_url") or follow_body.get("redirect_url") or follow_body.get("url") or "").strip()
                        if json_follow and json_follow not in seen_follow_urls:
                            current_follow = urljoin(current_follow, json_follow)
                            continue
                    location = str(getattr(follow_resp, "headers", {}).get("Location") or "").strip()
                    if int(getattr(follow_resp, "status_code", 0) or 0) not in (301, 302, 303, 307, 308) or not location:
                        break
                    current_follow = urljoin(current_follow, location)
            except Exception as exc:
                _append_consent_debug(debug_steps, method="get", source=f"{source}_continue", target_prefix=follow_url[:180], error=str(exc))
        if 200 <= int(getattr(ws_resp, "status_code", 0) or 0) < 300:
            return None
    return None


def _har_like_browser_fetch_headers(referer: str, *, accept: str = "application/json", content_type: str = "application/json") -> dict[str, str]:
    headers = get_common_headers()
    headers["accept"] = accept
    headers["accept-language"] = "zh-CN,zh;q=0.9"
    headers["referer"] = referer if referer.startswith("http") else f"{auth_base}{referer}"
    headers["sec-ch-ua"] = '"Chromium";v="148", "Google Chrome";v="148", "Not/A)Brand";v="99"'
    headers.update(_make_trace_headers())
    if content_type:
        headers["content-type"] = content_type
    else:
        headers.pop("content-type", None)
    return headers


def _consent_response_summary(response: Any, *, method: str, target: str, source: str = "") -> dict[str, Any]:
    body = _response_json(response)
    text = str(getattr(response, "text", "") or "")
    content_type = str(getattr(response, "headers", {}).get("Content-Type") or getattr(response, "headers", {}).get("content-type") or "")
    summary = {
        "method": method,
        "source": source,
        "target_prefix": str(target or "")[:180],
        "status": int(getattr(response, "status_code", 0) or 0),
        "content_type_prefix": content_type[:120],
        "location_prefix": str(getattr(response, "headers", {}).get("Location") or "")[:180],
        "final_url_prefix": str(getattr(response, "url", target) or target)[:180],
        "json_keys": sorted(body.keys())[:20] if isinstance(body, dict) else [],
        "text_markers": {
            "has_code": "code=" in text or '"code"' in text,
            "has_continue": "continue" in text.lower(),
            "has_callback": "/auth/callback" in text or "localhost:1455" in text,
            "has_consent": "consent" in text.lower(),
            "has_workspace_id": "workspace_id" in text or "workspaceId" in text,
        },
    }
    workspace_id = _find_workspace_id_from_auth_session_node(body) if isinstance(body, dict) else ""
    if not workspace_id:
        workspace_id = _workspace_id_from_consent_html(text)
    summary["workspace_id_present"] = bool(workspace_id)
    if workspace_id:
        summary["workspace_id_prefix"] = workspace_id[:16]
    org_id, project_id = _find_org_project_from_auth_session_node(body) if isinstance(body, dict) else ("", "")
    if not org_id:
        org_id, project_id = _org_project_from_consent_html(text)
    summary["org_id_present"] = bool(org_id)
    summary["project_id_present"] = bool(project_id)
    if org_id:
        summary["org_id_prefix"] = org_id[:16]
    if project_id:
        summary["project_id_prefix"] = project_id[:16]
    detail = ""
    if isinstance(body, dict):
        for key in ("error", "message", "detail", "reason"):
            value = body.get(key)
            if value:
                detail = json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value)
                break
    if detail:
        summary["error_prefix"] = detail[:240]
    snippets: dict[str, str] = {}
    for token in ("workspace_id", "workspaceId", "continue", "authorize", "_data", "_routes", "routeId", "SIGN_IN_WITH_CHATGPT_CODEX_CONSENT"):
        index = text.find(token)
        if index < 0:
            continue
        start = max(0, index - 90)
        end = min(len(text), index + 180)
        snippet = re.sub(r"\s+", " ", text[start:end])
        snippets[token] = snippet[:280]
    if snippets:
        summary["snippets"] = snippets
    route_candidates = sorted(dict.fromkeys(re.findall(r"(?:routes/[A-Za-z0-9_./$+-]+|SIGN_IN_WITH_CHATGPT_CODEX_CONSENT)", text)))[:20]
    if route_candidates:
        summary["route_candidates"] = route_candidates
    if source in ("consent_page", "consent_data", "consent_data_submit") or int(getattr(response, "status_code", 0) or 0) >= 400:
        prefix = re.sub(r"\s+", " ", text[:1200]).strip()
        if prefix:
            summary["text_prefix"] = prefix[:1200]
    return summary


def extract_oauth_callback_params_from_consent_session(session: requests.Session, consent_url: str, device_id: str, state: str = "", debug_steps: list[dict[str, Any]] | None = None) -> dict[str, str] | None:
    if consent_url.startswith("/"):
        consent_url = f"{auth_base}{consent_url}"
    har_like_headers = _har_like_browser_fetch_headers(f"{auth_base}/email-verification", accept="application/json", content_type="")
    workspace_id = ""
    try:
        dump_resp = session.get(
            f"{auth_base}/api/accounts/client_auth_session_dump",
            headers={**har_like_headers, "accept": "application/json"},
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        _append_consent_debug(debug_steps, **_consent_response_summary(dump_resp, method="get", target=f"{auth_base}/api/accounts/client_auth_session_dump", source="client_auth_session_dump_har_like"))
        callback_params = _extract_oauth_callback_params_from_response(dump_resp)
        if callback_params:
            return callback_params
        dump_body = _response_json(dump_resp)
        org_id, project_id = _find_org_project_from_auth_session_node(dump_body)
        if org_id:
            callback_params = _submit_organization_select_for_consent(
                session,
                org_id,
                project_id,
                har_like_headers,
                f"{auth_base}/sign-in-with-chatgpt/codex/organization",
                debug_steps,
                "organization_select_from_session_dump_har_like",
            )
            if callback_params:
                return callback_params
        workspace_id = _find_workspace_id_from_auth_session_node(dump_body)
    except Exception:
        workspace_id = ""

    try:
        data_url = _merge_url_query(
            f"{auth_base}/sign-in-with-chatgpt/codex/consent.data",
            _routes="SIGN_IN_WITH_CHATGPT_CODEX_CONSENT",
        )
        data_resp = session.get(
            data_url,
            headers=_har_like_browser_fetch_headers(f"{auth_base}/email-verification", accept="*/*", content_type=""),
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        _append_consent_debug(debug_steps, **_consent_response_summary(data_resp, method="get", target=data_url, source="consent_data_har_like"))
        callback_params = _extract_oauth_callback_params_from_response(data_resp)
        if callback_params:
            return callback_params
        if not workspace_id:
            workspace_id = _find_workspace_id_from_auth_session_node(_response_json(data_resp))
        if not workspace_id:
            workspace_id = _workspace_id_from_consent_html(str(getattr(data_resp, "text", "") or ""))
        org_id, project_id = _find_org_project_from_auth_session_node(_response_json(data_resp))
        if not org_id:
            org_id, project_id = _org_project_from_consent_html(str(getattr(data_resp, "text", "") or ""))
        if org_id:
            callback_params = _submit_organization_select_for_consent(
                session,
                org_id,
                project_id,
                headers,
                f"{auth_base}/sign-in-with-chatgpt/codex/organization",
                debug_steps,
                "organization_select_from_consent_data",
            )
            if callback_params:
                return callback_params
        org_id, project_id = _find_org_project_from_auth_session_node(_response_json(data_resp))
        if not org_id:
            org_id, project_id = _org_project_from_consent_html(str(getattr(data_resp, "text", "") or ""))
        if org_id:
            callback_params = _submit_organization_select_for_consent(
                session,
                org_id,
                project_id,
                har_like_headers,
                f"{auth_base}/sign-in-with-chatgpt/codex/organization",
                debug_steps,
                "organization_select_from_consent_data_har_like",
            )
            if callback_params:
                return callback_params
    except Exception:
        pass

    if workspace_id:
        try:
            callback_params = _submit_workspace_select_from_consent_form(
                session,
                workspace_id,
                har_like_headers,
                consent_url,
                debug_steps,
                "workspace_select_har_like",
            )
            if callback_params:
                return callback_params
        except Exception as exc:
            _append_consent_debug(debug_steps, method="post", source="workspace_select_har_like", target_prefix=f"{auth_base}/api/accounts/workspace/select", payload_keys=["workspace_id"], error=str(exc))

    current_url = consent_url
    consent_page_text = ""
    for _ in range(10):
        response = session.get(current_url, headers=get_navigate_headers(), verify=False, timeout=30, allow_redirects=False)
        _append_consent_debug(debug_steps, **_consent_response_summary(response, method="get", target=current_url, source="consent_page"))
        if not consent_page_text:
            consent_page_text = str(getattr(response, "text", "") or "")
        callback_params = _extract_oauth_callback_params_from_response(response)
        if callback_params:
            return callback_params
        page_org_id, page_project_id = _org_project_from_consent_html(str(getattr(response, "text", "") or ""))
        if page_org_id:
            callback_params = _submit_organization_select_for_consent(
                session,
                page_org_id,
                page_project_id,
                har_like_headers,
                f"{auth_base}/sign-in-with-chatgpt/codex/organization",
                debug_steps,
                "organization_select_from_consent_page_html",
            )
            if callback_params:
                return callback_params
        location = str(response.headers.get("Location") or "").strip()
        if response.status_code not in (301, 302, 303, 307, 308) or not location:
            break
        current_url = f"{auth_base}{location}" if location.startswith("/") else location

    headers = _build_authorize_continue_headers(session, device_id, consent_url)

    action, form_payload = _extract_consent_form_inputs(consent_page_text)
    form_workspace_id = str((form_payload or {}).get("workspace_id") or (form_payload or {}).get("workspaceId") or "").strip()
    form_action_url = urljoin(consent_url, action or consent_url)
    page_workspace_id = _workspace_id_from_consent_html(consent_page_text)
    if page_workspace_id and page_workspace_id != form_workspace_id:
        try:
            callback_params = _submit_workspace_select_from_consent_form(
                session,
                page_workspace_id,
                headers,
                consent_url,
                debug_steps,
                "workspace_select_from_consent_page",
            )
            if callback_params:
                return callback_params
        except Exception as exc:
            _append_consent_debug(debug_steps, method="post", source="workspace_select_from_consent_page", target_prefix=f"{auth_base}/api/accounts/workspace/select", payload_keys=["workspace_id"], error=str(exc))

    if form_workspace_id and (not action or "/sign-in-with-chatgpt/codex/consent" in form_action_url):
        try:
            callback_params = _submit_workspace_select_from_consent_form(
                session,
                form_workspace_id,
                headers,
                consent_url,
                debug_steps,
                "workspace_select_from_consent_form",
            )
            if callback_params:
                return callback_params
        except Exception as exc:
            _append_consent_debug(debug_steps, method="post", source="workspace_select_from_consent_form", target_prefix=f"{auth_base}/api/accounts/workspace/select", payload_keys=["workspace_id"], error=str(exc))

    if action:
        form_url = form_action_url
        form_headers = dict(headers)
        form_headers["content-type"] = "application/x-www-form-urlencoded"
        form_headers["referer"] = consent_url
        try:
            form_resp = session.post(
                form_url,
                data=form_payload,
                headers=form_headers,
                verify=False,
                timeout=30,
                allow_redirects=False,
            )
            form_summary = _consent_response_summary(form_resp, method="post", target=form_url, source="consent_form")
            form_summary["payload_keys"] = sorted(form_payload.keys())[:20]
            _append_consent_debug(debug_steps, **form_summary)
            callback_params = _extract_oauth_callback_params_from_response(form_resp)
            if callback_params:
                return callback_params
            follow = str(getattr(form_resp, "headers", {}).get("Location") or getattr(form_resp, "url", "") or "").strip()
            if follow:
                follow_url = urljoin(form_url, follow)
                follow_resp = session.get(
                    follow_url,
                    headers={**headers, "referer": form_url},
                    verify=False,
                    timeout=30,
                    allow_redirects=True,
                )
                _append_consent_debug(debug_steps, **_consent_response_summary(follow_resp, method="get", target=follow_url, source="consent_form_follow"))
                callback_params = _extract_oauth_callback_params_from_response(follow_resp)
                if callback_params:
                    return callback_params
        except Exception as exc:
            _append_consent_debug(debug_steps, method="post", source="consent_form", target_prefix=form_url[:180], error=str(exc))

    workspace_id = _workspace_id_from_consent_html(consent_page_text)
    try:
        dump_resp = session.get(
            f"{auth_base}/api/accounts/client_auth_session_dump",
            headers={**headers, "accept": "application/json", "content-type": "application/json"},
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        _append_consent_debug(debug_steps, **_consent_response_summary(dump_resp, method="get", target=f"{auth_base}/api/accounts/client_auth_session_dump", source="client_auth_session_dump"))
        callback_params = _extract_oauth_callback_params_from_response(dump_resp)
        if callback_params:
            return callback_params
        dump_body = _response_json(dump_resp)
        org_id, project_id = _find_org_project_from_auth_session_node(dump_body)
        if org_id:
            callback_params = _submit_organization_select_for_consent(
                session,
                org_id,
                project_id,
                headers,
                f"{auth_base}/sign-in-with-chatgpt/codex/organization",
                debug_steps,
                "organization_select_from_session_dump",
            )
            if callback_params:
                return callback_params
        if not workspace_id:
            workspace_id = _find_workspace_id_from_auth_session_node(dump_body)
    except Exception:
        if not workspace_id:
            workspace_id = ""

    try:
        data_url = _merge_url_query(
            f"{auth_base}/sign-in-with-chatgpt/codex/consent.data",
            _routes="SIGN_IN_WITH_CHATGPT_CODEX_CONSENT",
        )
        data_resp = session.get(
            data_url,
            headers={**headers, "accept": "*/*"},
            verify=False,
            timeout=30,
            allow_redirects=False,
        )
        _append_consent_debug(debug_steps, **_consent_response_summary(data_resp, method="get", target=data_url, source="consent_data"))
        callback_params = _extract_oauth_callback_params_from_response(data_resp)
        if callback_params:
            return callback_params
        if not workspace_id:
            workspace_id = _find_workspace_id_from_auth_session_node(_response_json(data_resp))
        if not workspace_id:
            workspace_id = _workspace_id_from_consent_html(str(getattr(data_resp, "text", "") or ""))
    except Exception:
        pass

    if not workspace_id:
        workspace_id = _workspace_id_from_client_auth_session_cookie(session)
    if not workspace_id:
        return None

    for payload in _consent_data_payloads(workspace_id, state):
        for submit_url in [
            _merge_url_query(
                f"{auth_base}/sign-in-with-chatgpt/codex/consent.data",
                _routes="SIGN_IN_WITH_CHATGPT_CODEX_CONSENT",
            ),
            f"{auth_base}/sign-in-with-chatgpt/codex/consent",
        ]:
            form_headers = dict(headers)
            form_headers["accept"] = "application/json, text/x-script, */*"
            form_headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
            form_headers["referer"] = consent_url
            try:
                submit_resp = session.post(
                    submit_url,
                    data=payload,
                    headers=form_headers,
                    verify=False,
                    timeout=30,
                    allow_redirects=False,
                )
                submit_summary = _consent_response_summary(submit_resp, method="post", target=submit_url, source="consent_data_submit")
                submit_summary["payload_keys"] = sorted(payload.keys())[:20]
                _append_consent_debug(debug_steps, **submit_summary)
                callback_params = _extract_oauth_callback_params_from_response(submit_resp)
                if callback_params:
                    return callback_params
                if int(getattr(submit_resp, "status_code", 0) or 0) in (301, 302, 303, 307, 308):
                    follow = str(getattr(submit_resp, "headers", {}).get("Location") or "").strip()
                    if follow:
                        follow_url = urljoin(submit_url, follow)
                        follow_resp = session.get(
                            follow_url,
                            headers={**headers, "referer": submit_url},
                            verify=False,
                            timeout=30,
                            allow_redirects=True,
                        )
                        _append_consent_debug(debug_steps, **_consent_response_summary(follow_resp, method="get", target=follow_url, source="consent_data_submit_follow"))
                        callback_params = _extract_oauth_callback_params_from_response(follow_resp)
                        if callback_params:
                            return callback_params
                submit_body = _response_json(submit_resp)
                submit_text = str(getattr(submit_resp, "text", "") or "")
                if "invalid_state" in json.dumps(submit_body, ensure_ascii=False) or "invalid_state" in submit_text:
                    return None
            except Exception as exc:
                _append_consent_debug(debug_steps, method="post", source="consent_data_submit", target_prefix=submit_url[:180], payload_keys=sorted(payload.keys())[:20], error=str(exc))

    ws_payload = {"workspace_id": workspace_id}
    ws_resp = session.post(f"{auth_base}/api/accounts/workspace/select", json=ws_payload, headers=headers, verify=False, timeout=30, allow_redirects=False)
    _append_consent_debug(debug_steps, **_consent_response_summary(ws_resp, method="post", target=f"{auth_base}/api/accounts/workspace/select", source="workspace_select"))
    callback_params = _extract_oauth_callback_params_from_response(ws_resp)
    if callback_params:
        return callback_params
    ws_data = _response_json(ws_resp)
    orgs = ((ws_data.get("data") or {}).get("orgs") or []) if isinstance(ws_data, dict) else []
    if not orgs:
        return None
    org_id = str((orgs[0] or {}).get("id") or "").strip()
    project_id = str(((orgs[0] or {}).get("projects") or [{}])[0].get("id") or "").strip()
    if not org_id:
        return None
    org_headers = get_common_headers()
    org_headers["referer"] = str(ws_data.get("continue_url") or consent_url)
    org_headers["oai-device-id"] = device_id
    org_headers.update(_make_trace_headers())
    body = {"org_id": org_id}
    if project_id:
        body["project_id"] = project_id
    org_resp = session.post(f"{auth_base}/api/accounts/organization/select", json=body, headers=org_headers, verify=False, timeout=30, allow_redirects=False)
    _append_consent_debug(debug_steps, **_consent_response_summary(org_resp, method="post", target=f"{auth_base}/api/accounts/organization/select", source="organization_select"))
    return _extract_oauth_callback_params_from_response(org_resp)


def exchange_platform_tokens(session: requests.Session, device_id: str, code_verifier: str, consent_url: str, proxy: str = "") -> RegistrationResult:
    callback_params = extract_oauth_callback_params_from_consent_session(session, consent_url, device_id)
    if not callback_params:
        try:
            r = session.get(consent_url, headers=get_navigate_headers(), allow_redirects=True, verify=False, timeout=30)
            callback_params = _extract_oauth_callback_params_from_response(r)
            if not callback_params:
                for hist in getattr(r, "history", []) or []:
                    callback_params = _extract_oauth_callback_params_from_response(hist)
                    if callback_params:
                        break
        except Exception as exc:
            return RegistrationResult(ok=False, error=f"consent_redirect_failed:{exc}")
    if not callback_params:
        return RegistrationResult(ok=False, error="missing_oauth_callback")
    code = str(callback_params.get("code") or "").strip()
    resp = create_session(proxy).post(
        f"{auth_base}/oauth/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": platform_oauth_redirect_uri,
            "client_id": platform_oauth_client_id,
            "code_verifier": code_verifier,
        },
        verify=False,
        timeout=60,
    )
    data = _response_json(resp)
    if resp.status_code != 200:
        return RegistrationResult(ok=False, callback_url=consent_url, error=f"oauth_token_http_{resp.status_code}")
    access_token = str(data.get("access_token") or "").strip()
    refresh_token = str(data.get("refresh_token") or "").strip()
    id_token = str(data.get("id_token") or "").strip()
    if not access_token or not refresh_token or not id_token:
        return RegistrationResult(ok=False, callback_url=consent_url, error="missing_tokens")
    payload = _decode_jwt_payload(id_token) or _decode_jwt_payload(access_token)
    return RegistrationResult(
        ok=True,
        email=str(payload.get("email") or "").strip(),
        access_token=access_token,
        refresh_token=refresh_token,
        id_token=id_token,
        callback_url=consent_url,
    )


def save_result(result: RegistrationResult) -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    path = DATA_DIR / "last_result.json"
    path.write_text(json.dumps(asdict(result), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _save_about_you_failure_artifacts(
    *,
    state: dict[str, Any] | None,
    create_info: dict[str, Any] | None,
    page_snapshot: dict[str, Any] | None,
    page_context: str = "",
) -> dict[str, str]:
    debug_dir = DATA_DIR / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"about_you_failure_{stamp}"
    json_path = debug_dir / f"{stem}.json"
    html_path = debug_dir / f"{stem}.html"

    state_raw = state.get("raw") if isinstance(state, dict) else {}
    state_url = str((state or {}).get("url") or "").strip()
    html_text = str((page_snapshot or {}).get("text") or "").strip()
    if not html_text:
        html_text = str((state_raw or {}).get("text") or "").strip()
    if not html_text:
        html_text = str((create_info or {}).get("text") or "").strip()

    payload = {
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "state_url": state_url,
        "page_context": page_context[:4000],
        "state": state or {},
        "create_info": create_info or {},
        "page_snapshot": page_snapshot or {},
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if html_text:
        html_path.write_text(html_text, encoding="utf-8")
    return {
        "json_path": str(json_path),
        "html_path": str(html_path) if html_text else "",
    }


def _save_about_you_presubmit_artifacts(
    *,
    state: dict[str, Any] | None,
    page_snapshot: dict[str, Any] | None,
    page_context: str = "",
) -> dict[str, str]:
    debug_dir = DATA_DIR / "debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = f"about_you_presubmit_{stamp}"
    json_path = debug_dir / f"{stem}.json"
    html_path = debug_dir / f"{stem}.html"

    state_raw = state.get("raw") if isinstance(state, dict) else {}
    state_url = str((state or {}).get("url") or "").strip()
    html_text = str((page_snapshot or {}).get("text") or "").strip()
    if not html_text:
        html_text = str((state_raw or {}).get("text") or "").strip()

    payload = {
        "captured_at": datetime.now().isoformat(timespec="seconds"),
        "state_url": state_url,
        "page_context": page_context[:4000],
        "state": state or {},
        "page_snapshot": page_snapshot or {},
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if html_text:
        html_path.write_text(html_text, encoding="utf-8")
    return {
        "json_path": str(json_path),
        "html_path": str(html_path) if html_text else "",
    }


def _response_error_summary(prefix: str, info: dict[str, Any]) -> str:
    status = info.get("status")
    body = info.get("json") or {}
    code = str(body.get("code") or body.get("error_code") or "").strip()
    message = str(body.get("message") or body.get("error") or "").strip()
    pieces = [f"{prefix}_{status}"]
    if code:
        pieces.append(code)
    if message:
        pieces.append(message[:160])
    return ": ".join(pieces)


def _failed_registration_result(
    *,
    email: str,
    password: str,
    mailbox: dict[str, Any],
    callback_url: str,
    error: str,
) -> RegistrationResult:
    result = RegistrationResult(
        ok=False,
        email=email,
        password=password,
        mailbox=mailbox,
        callback_url=callback_url,
        error=error,
    )
    save_result(result)
    return result


class PlatformRegistrar:
    def __init__(self, proxy: str = "") -> None:
        self.session = create_session(proxy)
        self.device_id = str(uuid.uuid4())
        self.proxy = proxy
        self.last_authorize: dict[str, Any] = {}
        self.sentinel_tokens: dict[str, str] = {}

    def close(self) -> None:
        self.session.close()

    def get_workspace_id(self) -> str:
        return _get_session_workspace_id(self.session)

    def start_phone_signup(self, phone_number: str = "") -> dict[str, str]:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        phone_hint = re.sub(r"\s+", "", str(phone_number or "").strip())
        if phone_hint:
            state = secrets.token_urlsafe(32)
            params = {
                "client_id": chatgpt_signup_client_id,
                "scope": chatgpt_signup_scope,
                "response_type": "code",
                "redirect_uri": chatgpt_signup_redirect_uri,
                "audience": platform_oauth_audience,
                "state": state,
                "device_id": self.device_id,
                "ext-oai-did": self.device_id,
                "screen_hint": "login_or_signup",
                "prompt": "login",
                "auth_session_logging_id": str(uuid.uuid4()),
                "login_hint": phone_hint,
            }
            url = f"{auth_base}/api/accounts/authorize?" + urlencode(params)
        else:
            state = ""
            url = f"{auth_base}/u/signup/identifier"
        headers = get_navigate_headers()
        if phone_hint:
            headers["referer"] = "https://chatgpt.com/"
            headers["sec-fetch-site"] = "cross-site"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token("signup")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        response, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            raise RuntimeError(error or "phone_signup_start_failed")
        cookie_snapshot = _cookie_snapshot(self.session)
        self.last_authorize = {
            "email": "",
            "state": state,
            "nonce": "",
            "code_verifier": "",
            "code_challenge": "",
            "external_authorize": False,
            "flow_kind": "phone_signup",
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_snapshot": cookie_snapshot,
            "cookie_summary": _summarize_cookie_snapshot(cookie_snapshot),
        }
        return {
            "code_verifier": "",
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_summary": self.last_authorize.get("cookie_summary") or {},
        }

    def start_email_signup(self, email: str) -> dict[str, str]:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        email_hint = str(email or "").strip()
        if not email_hint:
            raise ValueError("email_required")
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": chatgpt_signup_client_id,
            "scope": chatgpt_signup_scope,
            "response_type": "code",
            "redirect_uri": chatgpt_signup_redirect_uri,
            "audience": platform_oauth_audience,
            "state": state,
            "device_id": self.device_id,
            "ext-oai-did": self.device_id,
            "screen_hint": "login_or_signup",
            "prompt": "login",
            "auth_session_logging_id": str(uuid.uuid4()),
            "login_hint": email_hint,
        }
        url = f"{auth_base}/api/accounts/authorize?" + urlencode(params)
        headers = get_navigate_headers()
        headers["referer"] = "https://chatgpt.com/"
        headers["sec-fetch-site"] = "cross-site"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token("signup")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        response, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            raise RuntimeError(error or "email_signup_start_failed")
        cookie_snapshot = _cookie_snapshot(self.session)
        self.last_authorize = {
            "email": email_hint,
            "state": state,
            "nonce": "",
            "code_verifier": "",
            "code_challenge": "",
            "external_authorize": False,
            "flow_kind": "email_signup",
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_snapshot": cookie_snapshot,
            "cookie_summary": _summarize_cookie_snapshot(cookie_snapshot),
        }
        return {
            "code_verifier": "",
            "final_url": str(response.url),
            "status": str(response.status_code),
            "state": state,
            "cookie_summary": self.last_authorize.get("cookie_summary") or {},
        }

    def start_authorize(self, email: str, authorize_url: str = "", screen_hint: str = "login_or_signup") -> dict[str, str]:
        self.session.cookies.set("oai-did", self.device_id, domain=".auth.openai.com")
        self.session.cookies.set("oai-did", self.device_id, domain="auth.openai.com")
        code_verifier = ""
        requested_screen_hint = str(screen_hint or "login_or_signup")
        if authorize_url:
            parsed = urlparse(authorize_url)
            params = {key: values[-1] for key, values in parse_qs(parsed.query, keep_blank_values=True).items()}
            params["login_hint"] = email
            params["screen_hint"] = requested_screen_hint
            params.setdefault("device_id", self.device_id)
            state = str(params.get("state") or "")
            nonce = str(params.get("nonce") or "")
            url = urlunparse(parsed._replace(query=urlencode(params)))
        else:
            code_verifier, code_challenge = _generate_pkce()
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            params = {
                "issuer": auth_base,
                "client_id": platform_oauth_client_id,
                "audience": platform_oauth_audience,
                "redirect_uri": platform_oauth_redirect_uri,
                "device_id": self.device_id,
                "screen_hint": requested_screen_hint,
                "max_age": "0",
                "login_hint": email,
                "scope": "openid profile email offline_access",
                "response_type": "code",
                "response_mode": "query",
                "state": state,
                "nonce": nonce,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "auth0Client": "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9",
            }
            url = f"{auth_base}/api/accounts/authorize?" + "&".join(f"{k}={requests.utils.quote(str(v), safe='')}" for k, v in params.items())
        response, error = request_with_local_retry(
            self.session,
            "get",
            url,
            headers=get_navigate_headers(),
            allow_redirects=True,
            verify=False,
        )
        if response is None:
            raise RuntimeError(error or "authorize_request_failed")
        cookie_snapshot = _cookie_snapshot(self.session)
        self.last_authorize = {
            "email": email,
            "state": state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "code_challenge": str(params.get("code_challenge") or ""),
            "external_authorize": bool(authorize_url),
            "screen_hint": requested_screen_hint,
            "flow_kind": "login" if requested_screen_hint == "login" else "signup" if requested_screen_hint == "signup" else "login_or_signup",
            "final_url": str(response.url),
            "status": str(response.status_code),
            "cookie_snapshot": cookie_snapshot,
            "cookie_summary": _summarize_cookie_snapshot(cookie_snapshot),
        }
        return {
            "code_verifier": code_verifier,
            "final_url": str(response.url),
            "status": str(response.status_code),
            "state": state,
            "cookie_summary": self.last_authorize.get("cookie_summary") or {},
        }

    def _ensure_sentinel_token(self, flow: str) -> str:
        cached = str(self.sentinel_tokens.get(flow) or "").strip()
        if cached:
            return cached
        token = build_sentinel_token(self.session, self.device_id, flow)
        self.sentinel_tokens[flow] = token
        return token

    def _build_accounts_headers(self, referer_path: str, flow: str) -> dict[str, str]:
        headers = get_common_headers()
        headers["referer"] = f"{auth_base}{referer_path}"
        headers["oai-device-id"] = self.device_id
        headers["accept"] = "application/json"
        headers["x-requested-with"] = "XMLHttpRequest"
        headers["sec-fetch-site"] = "same-origin"
        headers["sec-fetch-mode"] = "cors"
        headers["sec-fetch-dest"] = "empty"
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token(flow)
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        return headers

    def _post_accounts_payload(self, payload: dict[str, Any], referer_path: str, candidates: list[tuple[str, str]] | None = None) -> dict[str, Any]:
        origin_page_type = str(payload.get("origin_page_type") or "")
        flow_kind = str(self.last_authorize.get("flow_kind") or "").strip()
        flow = "auth" if origin_page_type.startswith("login") or (origin_page_type.startswith("email_otp") and flow_kind == "login") else "signup"
        headers = self._build_accounts_headers(referer_path, flow)
        state = str(self.last_authorize.get("state") or "").strip()
        referer_url = f"{auth_base}{referer_path}"
        default_candidates = [
            (f"{auth_base}/api/accounts", "json"),
            (referer_url, "json"),
            (referer_url, "form"),
            (_merge_url_query(referer_url, _data="routes/u/signup/identifier"), "json"),
            (_merge_url_query(referer_url, _data="routes/u/signup/identifier"), "form"),
            (_merge_url_query(referer_url, _data="routes/u/signup/password"), "json"),
            (_merge_url_query(referer_url, _data="routes/u/signup/password"), "form"),
            (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "json"),
            (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "form"),
            (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "json"),
            (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "form"),
        ]
        if state:
            default_candidates.extend(
                [
                    (_merge_url_query(f"{auth_base}/u/signup/identifier", state=state, _data="routes/u/signup/identifier"), "json"),
                    (_merge_url_query(f"{auth_base}/u/signup/identifier", state=state, _data="routes/u/signup/identifier"), "form"),
                    (_merge_url_query(f"{auth_base}/u/signup/password", state=state, _data="routes/u/signup/password"), "json"),
                    (_merge_url_query(f"{auth_base}/u/signup/password", state=state, _data="routes/u/signup/password"), "form"),
                ]
            )
        attempts: list[dict[str, Any]] = []
        cookie_snapshot = _cookie_snapshot(self.session)
        cookie_summary = _summarize_cookie_snapshot(cookie_snapshot)
        for url, body_mode in (candidates or default_candidates):
            try_headers = dict(headers)
            kwargs: dict[str, Any] = {"headers": try_headers, "verify": False}
            if body_mode == "form":
                try_headers["content-type"] = "application/x-www-form-urlencoded;charset=UTF-8"
                kwargs["data"] = {
                    "payload": json.dumps(payload, separators=(",", ":"), ensure_ascii=False),
                    "state": state,
                    "origin_page_type": str(payload.get("origin_page_type") or ""),
                }
            else:
                kwargs["json"] = payload
            resp, error = request_with_local_retry(
                self.session,
                "post",
                url,
                **kwargs,
            )
            body = {}
            text = ""
            status = 0
            final_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_url = str(getattr(resp, "url", url) or url)
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            attempt = {
                "url": url,
                "body_mode": body_mode,
                "ok": resp is not None and 200 <= status < 300,
                "status": status,
                "json": body,
                "text": text,
                "error": error,
                "final_url": final_url,
                "cookie_summary": cookie_summary,
                "referer": headers.get("referer") or "",
                "state": state,
                "sentinel_token_present": bool(try_headers.get("OpenAI-Sentinel-Token")),
                "sentinel_error": try_headers.get("x-openai-sentinel-error") or "",
            }
            attempts.append(attempt)
            if attempt["ok"] or status in (401, 403, 405, 422):
                return {**attempt, "payload": payload, "attempts": attempts, "authorize": self.last_authorize}
        last = attempts[-1] if attempts else {"ok": False, "status": 0, "json": {}, "text": "", "error": "no_attempts", "url": "", "final_url": "", "body_mode": "json", "cookie_summary": cookie_summary, "referer": headers.get("referer") or "", "state": state}
        return {**last, "payload": payload, "attempts": attempts, "authorize": self.last_authorize}

    def establish_signup_session(self) -> dict[str, Any]:
        state = str(self.last_authorize.get("state") or "").strip()
        final_url = str(self.last_authorize.get("final_url") or "").strip() or f"{auth_base}/u/signup"
        requested_flow = str(self.last_authorize.get("flow_kind") or "").strip()
        is_login_flow = requested_flow == "login" or any(token in final_url for token in ("/log-in", "screen_hint=login", "login_or_signup"))
        base_page = "/log-in/password" if is_login_flow else "/u/signup/password"
        headers = get_navigate_headers()
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["OpenAI-Sentinel-Token"] = self._ensure_sentinel_token("auth" if is_login_flow else "signup")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        probes: list[dict[str, Any]] = []
        if is_login_flow:
            nav_candidates = [
                final_url,
                f"{auth_base}/log-in/password?state={state}" if state else f"{auth_base}/log-in/password",
                f"{auth_base}/api/auth/session",
                f"{auth_base}/api/auth/session?state={state}" if state else f"{auth_base}/api/auth/session",
                f"{auth_base}/api/client_auth_session_dump",
                f"{auth_base}/api/client_auth_session_dump?state={state}" if state else f"{auth_base}/api/client_auth_session_dump",
            ]
        else:
            nav_candidates = [
                final_url,
                f"{auth_base}/u/signup",
                f"{auth_base}/u/signup?state={state}" if state else f"{auth_base}/u/signup",
                f"{auth_base}/u/signup/identifier?state={state}" if state else f"{auth_base}/u/signup/identifier",
                f"{auth_base}/u/signup/password?state={state}" if state else f"{auth_base}/u/signup/password",
                f"{auth_base}/log-in/password?state={state}" if state else f"{auth_base}/log-in/password",
                f"{auth_base}/api/auth/session",
                f"{auth_base}/api/auth/session?state={state}" if state else f"{auth_base}/api/auth/session",
                f"{auth_base}/api/client_auth_session_dump",
                f"{auth_base}/api/client_auth_session_dump?state={state}" if state else f"{auth_base}/api/client_auth_session_dump",
            ]
        xhr_headers = self._build_accounts_headers(f"{base_page}?state={state}" if state else base_page, "auth" if is_login_flow else "signup")
        xhr_headers["accept"] = "application/json"
        if is_login_flow:
            xhr_candidates = [
                (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "get"),
                (f"{auth_base}/api/auth/session", "get"),
                (f"{auth_base}/api/client_auth_session_dump", "get"),
            ]
        else:
            xhr_candidates = [
                (_merge_url_query(f"{auth_base}/u/signup", _data="routes/u/signup", state=state) if state else _merge_url_query(f"{auth_base}/u/signup", _data="routes/u/signup"), "get"),
                (_merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier", state=state) if state else _merge_url_query(f"{auth_base}/u/signup/identifier", _data="routes/u/signup/identifier"), "get"),
                (_merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password", state=state) if state else _merge_url_query(f"{auth_base}/u/signup/password", _data="routes/u/signup/password"), "get"),
                (_merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password", state=state) if state else _merge_url_query(f"{auth_base}/log-in/password", _data="routes/log-in/password"), "get"),
                (f"{auth_base}/api/auth/session", "get"),
                (f"{auth_base}/api/client_auth_session_dump", "get"),
            ]
        for url in nav_candidates:
            resp, error = request_with_local_retry(
                self.session,
                "get",
                url,
                headers=headers,
                verify=False,
                allow_redirects=False,
            )
            body = {}
            text = ""
            status = 0
            content_type = ""
            location = ""
            final_probe_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_probe_url = str(getattr(resp, "url", url) or url)
                content_type = str(getattr(resp, "headers", {}).get("Content-Type") or "")
                location = str(getattr(resp, "headers", {}).get("Location") or "")
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            probes.append(
                {
                    "probe_type": "navigate",
                    "url": url,
                    "status": status,
                    "content_type": content_type,
                    "location": location,
                    "json": body,
                    "text": text,
                    "error": error,
                    "final_url": final_probe_url,
                    "is_html_shell": "<html" in text.lower() or "auth-cdn.oaistatic.com/assets/" in text,
                }
            )
        for url, method in xhr_candidates:
            resp, error = request_with_local_retry(
                self.session,
                method,
                url,
                headers=xhr_headers,
                verify=False,
                allow_redirects=False,
            )
            body = {}
            text = ""
            status = 0
            content_type = ""
            location = ""
            final_probe_url = url
            if resp is not None:
                status = int(getattr(resp, "status_code", 0) or 0)
                body = _response_json(resp)
                final_probe_url = str(getattr(resp, "url", url) or url)
                content_type = str(getattr(resp, "headers", {}).get("Content-Type") or "")
                location = str(getattr(resp, "headers", {}).get("Location") or "")
                try:
                    text = resp.text[:2000]
                except Exception:
                    text = ""
            probes.append(
                {
                    "probe_type": "xhr",
                    "url": url,
                    "method": method,
                    "status": status,
                    "content_type": content_type,
                    "location": location,
                    "json": body,
                    "text": text,
                    "error": error,
                    "final_url": final_probe_url,
                    "is_html_shell": "<html" in text.lower() or "auth-cdn.oaistatic.com/assets/" in text,
                }
            )
        cookie_snapshot = _cookie_snapshot(self.session)
        cookie_summary = _summarize_cookie_snapshot(cookie_snapshot)
        result = {
            "ok": bool(cookie_snapshot.get("oai-client-auth-session") or cookie_snapshot.get("auth_session") or cookie_snapshot.get("oai-auth-token")),
            "state": state,
            "flow_kind": "login" if is_login_flow else "signup",
            "input_final_url": final_url,
            "cookie_summary": cookie_summary,
            "cookie_snapshot": cookie_snapshot,
            "sentinel_token_present": bool(headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
            "probes": probes,
        }
        self.last_authorize["session_establishment"] = result
        return result

    def create_account_start(self, email: str) -> dict[str, Any]:
        identifier = str(email or "").strip()
        identifier_kind = "phone" if re.fullmatch(r"\+?[0-9]{6,20}", re.sub(r"\s+", "", identifier)) else "email"
        username_payload = {"value": identifier, "kind": identifier_kind}
        if identifier_kind == "phone":
            username_payload["phone_country_code"] = "AUTO"
        payload = {
            "origin_page_type": "create_account_start",
            "data": {
                "kind": "username",
                "username": username_payload,
            },
        }
        state = self.last_authorize.get("state") or ""
        return self._post_accounts_payload(payload, f"/u/signup/identifier?state={state}")

    def register_user(self, email: str, password: str) -> dict[str, Any]:
        headers = get_common_headers()
        headers["referer"] = f"{auth_base}/create-account/password"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = self._ensure_sentinel_token("username_password_create")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/user/register",
            json={"username": email, "password": password},
            headers=headers,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/user/register"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 300,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "payload": {"username": email, "password": password},
            "authorize": self.last_authorize,
            "sentinel_token_present": bool(headers.get("openai-sentinel-token") or headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
        }

    def send_otp(self) -> dict[str, Any]:
        headers = get_navigate_headers()
        headers["referer"] = f"{auth_base}/create-account/password"
        resp, error = request_with_local_retry(
            self.session,
            "get",
            f"{auth_base}/api/accounts/email-otp/send",
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/email-otp/send"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and status in (200, 302),
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def send_phone_otp(self) -> dict[str, Any]:
        headers = get_navigate_headers()
        headers["referer"] = f"{auth_base}/create-account/phone-verification"
        resp, error = request_with_local_retry(
            self.session,
            "get",
            f"{auth_base}/api/accounts/phone-otp/send",
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/phone-otp/send"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and status in (200, 302),
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def resend_phone_otp(self) -> dict[str, Any]:
        return self.send_phone_otp()

    def validate_signup_otp(self, code: str) -> dict[str, Any]:
        resp, error = validate_otp(self.session, self.device_id, code)
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/email-otp/validate"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 300,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def validate_phone_signup_otp(self, code: str) -> dict[str, Any]:
        headers = get_common_headers()
        headers["referer"] = f"{auth_base}/create-account/phone-verification"
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = self._ensure_sentinel_token("authorize_continue")
        except Exception:
            pass
        resp, error = request_with_local_retry(
            self.session,
            "post",
            f"{auth_base}/api/accounts/phone-otp/validate",
            json={"code": str(code).strip()},
            headers=headers,
            verify=False,
        )
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/phone-otp/validate"
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 300,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "authorize": self.last_authorize,
        }

    def create_account(self, name: str, birthdate: str, referer: str = "", page_context: str = "", email: str = "") -> dict[str, Any]:
        headers = get_common_headers()
        headers["referer"] = str(referer or f"{auth_base}/about-you")
        headers["oai-device-id"] = self.device_id
        headers.update(_make_trace_headers())
        try:
            headers["openai-sentinel-token"] = self._ensure_sentinel_token("oauth_create_account")
        except Exception as exc:
            headers["x-openai-sentinel-error"] = str(exc)
        payloads = _about_you_create_account_payloads(name, birthdate, page_context, email=email)
        attempts: list[dict[str, Any]] = []
        last_resp = None
        last_error = ""
        for payload in payloads:
            resp, error = request_with_local_retry(
                self.session,
                "post",
                f"{auth_base}/api/accounts/create_account",
                json=payload,
                headers=headers,
                verify=False,
                allow_redirects=False,
            )
            status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
            body = _response_json(resp) if resp is not None else {}
            attempt_error_code = _accounts_error_code({"json": body})
            attempts.append({"keys": list(payload.keys()), "status": status, "ok": resp is not None and 200 <= status < 400, "error_code": attempt_error_code})
            last_resp = resp
            last_error = error
            if resp is not None and 200 <= status < 400:
                break
            if attempt_error_code == "registration_disallowed":
                break
        resp = last_resp
        error = last_error
        status = int(getattr(resp, "status_code", 0) or 0) if resp is not None else 0
        body = _response_json(resp) if resp is not None else {}
        text = ""
        final_url = f"{auth_base}/api/accounts/create_account"
        location = ""
        if resp is not None:
            final_url = str(getattr(resp, "url", final_url) or final_url)
            location = str(getattr(resp, "headers", {}).get("Location") or "")
            try:
                text = resp.text[:2000]
            except Exception:
                text = ""
        return {
            "ok": resp is not None and 200 <= status < 400,
            "status": status,
            "json": body,
            "text": text,
            "error": error,
            "final_url": final_url,
            "location": location,
            "payload": payloads[min(len(attempts), len(payloads)) - 1] if attempts else {},
            "payload_attempts": attempts,
            "referer": headers.get("referer") or "",
            "authorize": self.last_authorize,
            "sentinel_token_present": bool(headers.get("openai-sentinel-token") or headers.get("OpenAI-Sentinel-Token")),
            "sentinel_error": headers.get("x-openai-sentinel-error") or "",
        }

    def exchange_platform_tokens(self, code_verifier: str, callback_url: str) -> RegistrationResult:
        return exchange_platform_tokens(self.session, self.device_id, code_verifier, callback_url, self.proxy)


def _registration_continue_url(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    return str(
        body.get("continue_url")
        or info.get("location")
        or info.get("final_url")
        or info.get("url")
        or ""
    ).strip()


def _registration_page_context(info: dict[str, Any]) -> str:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    parts = [body, info.get("text") or "", info.get("location") or "", info.get("final_url") or ""]
    return json.dumps(parts, ensure_ascii=False, default=str)


def _registration_state_from_info(info: dict[str, Any]) -> dict[str, str]:
    body = info.get("json") if isinstance(info.get("json"), dict) else {}
    page = body.get("page") if isinstance(body.get("page"), dict) else {}
    page_type = str(page.get("type") or body.get("page_type") or "").strip()
    url = _registration_continue_url(info)
    text = str(info.get("text") or "")
    location = str(info.get("location") or "")
    combined = " ".join([page_type, url, text[:2000], location]).lower()

    callback_url = ""
    for candidate in (url, location, str(info.get("final_url") or "")):
        if extract_oauth_callback_params_from_url(candidate):
            callback_url = candidate
            break
    if callback_url:
        return {"kind": "callback", "url": callback_url, "page_type": page_type}
    if "/error" in combined or "authorize_hydra_invalid_request" in combined:
        return {"kind": "error", "url": url, "page_type": page_type}
    if page_type == "add_email" or "/add-email" in combined:
        return {"kind": "add_email", "url": url or f"{auth_base}/add-email", "page_type": page_type}
    if page_type == "about_you" or "about-you" in combined or 'name="birthday"' in combined or 'name="age"' in combined:
        return {"kind": "about_you", "url": url or f"{auth_base}/about-you", "page_type": page_type}
    if page_type == "email_otp_verification" or "email-verification" in combined or "email-otp" in combined:
        return {"kind": "email_otp", "url": url or f"{auth_base}/email-verification", "page_type": page_type}
    if page_type in {"create_account_password", "login_password", "password"} or "create-account/password" in combined or "/u/signup/password" in combined or "log-in/password" in combined:
        return {"kind": "password", "url": url or f"{auth_base}/create-account/password", "page_type": page_type}
    if page_type or url:
        return {"kind": "continue", "url": url, "page_type": page_type}
    return {"kind": "unknown", "url": "", "page_type": ""}


def _load_registration_state(registrar: PlatformRegistrar, url: str) -> dict[str, Any]:
    target = str(url or "").strip()
    if not target:
        return {"kind": "unknown", "url": "", "page_type": "", "raw": {}}
    try:
        from .oauth_token_flow import _load_continue_page

        probe = _load_continue_page(registrar, target)
        if probe.get("callback_url"):
            return {"kind": "callback", "url": str(probe.get("callback_url") or ""), "page_type": str(probe.get("page_type") or ""), "raw": probe}
        info = {
            "json": probe.get("json") or {},
            "text": probe.get("text") or "",
            "final_url": probe.get("continue_url") or target,
            "location": probe.get("location") or "",
        }
        state = _registration_state_from_info(info)
        state["raw"] = probe
        return state
    except Exception as exc:
        return {"kind": "continue", "url": target, "page_type": "", "raw": {"error": str(exc)}}


def _registration_expected_state(registrar: PlatformRegistrar, start_info: dict[str, Any], create_info: dict[str, Any]) -> str:
    authorize = create_info.get("authorize") if isinstance(create_info.get("authorize"), dict) else {}
    for value in (
        start_info.get("state") if isinstance(start_info, dict) else "",
        authorize.get("state"),
        getattr(registrar, "last_authorize", {}).get("state") if isinstance(getattr(registrar, "last_authorize", {}), dict) else "",
    ):
        text = str(value or "").strip()
        if text:
            return text
    return ""


def _resolve_registration_post_create_url(
    registrar: PlatformRegistrar,
    *,
    start_info: dict[str, Any],
    create_info: dict[str, Any],
    fallback_url: str = "",
) -> str:
    candidate = _registration_continue_url(create_info) or str(fallback_url or "").strip()
    if extract_oauth_callback_params_from_url(candidate):
        return candidate
    state = _registration_expected_state(registrar, start_info, create_info)
    try:
        from .oauth_token_flow import _resolve_oauth_callback

        resolved = _resolve_oauth_callback(registrar, candidate, state)
        if resolved:
            return resolved
    except Exception as exc:
        log(f"注册后 OAuth 回调预解析异常：{exc}")
    return candidate


def _wait_email_otp_with_resend(config: RegisterConfig, registrar: PlatformRegistrar, mailbox: dict, *, resend_on_miss: bool = True) -> str:
    code = wait_for_code(config, mailbox)
    if code or not resend_on_miss:
        return str(code or "").strip()
    mailbox["_code_after_ts"] = int(time.time() * 1000)
    otp_info = registrar.send_otp()
    log(f"邮箱验证码重发结果：status={otp_info.get('status')} ok={otp_info.get('ok')} final_url={otp_info.get('final_url')}")
    if not otp_info.get("ok"):
        error = _response_error_summary("send_otp", otp_info)
        log(f"邮箱验证码重发失败：{error}")
        return ""
    return str(wait_for_code(config, mailbox) or "").strip()


def _brief_flow_url(url: str) -> str:
    raw = str(url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw)
        query = parse_qs(parsed.query, keep_blank_values=True)
        suffix = ""
        if query.get("errorCode"):
            suffix = f"?errorCode={query['errorCode'][-1]}"
        elif query.get("code"):
            suffix = "?code=***"
        elif query.get("state"):
            suffix = "?state=***"
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}{suffix}"[:180]
    except Exception:
        return raw[:180]


def _follow_chatgpt_signup_callback(registrar: PlatformRegistrar, callback_url: str) -> dict[str, Any]:
    target = str(callback_url or "").strip()
    if not target.startswith(chatgpt_signup_redirect_uri):
        return {"followed": False, "final_url": target, "status": 0}
    session = getattr(registrar, "session", None)
    if session is None:
        return {"followed": False, "final_url": target, "status": 0, "error": "session_missing"}
    headers = get_navigate_headers()
    headers["referer"] = f"{auth_base}/about-you"
    headers["sec-fetch-site"] = "cross-site"
    try:
        response, error = request_with_local_retry(
            session,
            "get",
            target,
            headers=headers,
            allow_redirects=True,
            verify=False,
        )
    except Exception as exc:
        return {"followed": True, "final_url": target, "status": 0, "error": str(exc)}
    if response is None:
        return {"followed": True, "final_url": target, "status": 0, "error": error}
    return {
        "followed": True,
        "final_url": str(getattr(response, "url", "") or target),
        "status": int(getattr(response, "status_code", 0) or 0),
    }


def _exchange_registered_account_tokens(
    *,
    config: RegisterConfig,
    registrar: PlatformRegistrar,
    email: str,
    password: str,
    mailbox: dict[str, Any],
    code_verifier: str,
    callback_url: str,
) -> RegistrationResult:
    candidate_callback = str(callback_url or "").strip()
    candidate_verifier = str(code_verifier or "").strip()
    if candidate_callback.startswith(chatgpt_signup_redirect_uri):
        follow_info = _follow_chatgpt_signup_callback(registrar, candidate_callback)
        if follow_info.get("followed"):
            log(
                "注册后 ChatGPT 回调已跟随："
                f"status={follow_info.get('status')} final_url={_brief_flow_url(str(follow_info.get('final_url') or ''))}"
            )

    if candidate_callback and not candidate_callback.startswith(chatgpt_signup_redirect_uri):
        token_result = registrar.exchange_platform_tokens(candidate_verifier, candidate_callback)
        if token_result.ok:
            token_result.password = password
            token_result.mailbox = mailbox
            return token_result
        log(f"注册回调换 token 未成功，准备用当前登录会话重新打开 OAuth：{token_result.error}")
        if not hasattr(registrar, "start_authorize"):
            return token_result

    if parse_bool(getattr(config, "codex2api_auto_import", False), key="codex2api_auto_import") and str(config.codex2api_url or "").strip() and str(config.codex2api_admin_key or "").strip():
        try:
            from .oauth_token_flow import _continue_with_optional_add_email, _resolve_oauth_callback
            from .reauthorize import (
                _attempt_password_login,
                _build_reauthorize_sms_config,
                _continue_with_optional_phone_verification,
                _resolve_callback_step,
                _start_cpa_oauth,
                _step_requires_phone_verification,
                _submit_callback_to_cpa,
            )

            cpa_oauth = _start_cpa_oauth(
                cpa_url=config.codex2api_url,
                cpa_management_key=config.codex2api_admin_key,
                email=email,
                proxy_url=str(config.codex2api_proxy_url or "").strip(),
            )
            log("注册后 CPA OAuth 授权参数已获取")
            oauth_info = registrar.start_authorize(
                email=email,
                authorize_url=str(cpa_oauth.get("authorize_url") or ""),
                screen_hint="login",
            )
            log(
                "注册后 CPA OAuth 授权入口已打开："
                f"status={oauth_info.get('status')} final_url={_brief_flow_url(str(oauth_info.get('final_url') or ''))}"
            )
            expected_state = str(cpa_oauth.get("state") or oauth_info.get("state") or "").strip()
            resolved_callback = ""
            phone_info: dict[str, Any] = {}
            phone_debug: dict[str, Any] = {}
            add_email_attempt_count = 0

            def _mail_config_for_add_email() -> dict[str, Any]:
                try:
                    return asdict(config.mail)
                except Exception:
                    return {}

            def _continue_add_email_if_needed(continue_url: str, *, source: str) -> str:
                nonlocal resolved_callback, add_email_attempt_count
                target = str(continue_url or "").strip()
                if not target:
                    return ""
                if add_email_attempt_count >= 2:
                    log("注册后 CPA OAuth 绑定邮箱已连续处理 2 次仍未完成，本次停止重复提交")
                    return target
                add_email_attempt_count += 1
                log(f"注册后 CPA OAuth 需要绑定邮箱，开始处理：source={source} attempt={add_email_attempt_count}/2 url={_brief_flow_url(target)}")
                verified_url, resolved_bind_email = _continue_with_optional_add_email(
                    registrar,
                    continue_url=target,
                    bind_email=str(mailbox.get("bind_email") or ""),
                    bind_email_code=str(mailbox.get("bind_email_code") or ""),
                    bind_mail_config=_mail_config_for_add_email(),
                )
                verified_url = str(verified_url or "").strip()
                pending_bind_email = str(resolved_bind_email or "").strip()
                if pending_bind_email:
                    mailbox["bind_email_pending"] = pending_bind_email
                    log(f"注册后 CPA OAuth 绑定邮箱验证码已提交，等待确认最终绑定：{pending_bind_email}")
                if extract_oauth_callback_params_from_url(verified_url):
                    resolved_callback = verified_url
                if not resolved_callback:
                    resolved_callback = _resolve_oauth_callback(registrar, verified_url, expected_state)
                if not resolved_callback:
                    resolved_callback = _resolve_callback_step(
                        registrar,
                        {"status": 200, "ok": True, "json": {}, "text": "", "location": "", "final_url": verified_url},
                        expected_state,
                        allow_state_resume=True,
                    )
                if not resolved_callback:
                    log("注册后 CPA OAuth 绑定邮箱已通过但未返回回调，重新打开授权入口继续获取回调")
                    try:
                        reopened_info = registrar.start_authorize(
                            email=email,
                            authorize_url=str(cpa_oauth.get("authorize_url") or ""),
                            screen_hint="login",
                        )
                    except Exception as exc:
                        reopened_info = {"ok": False, "status": 0, "final_url": "", "error": str(exc)}
                    log(
                        "注册后 CPA OAuth 绑定后重开授权入口："
                        f"status={reopened_info.get('status')} final_url={_brief_flow_url(str(reopened_info.get('final_url') or ''))}"
                    )
                    resolved_callback = _resolve_callback_step(
                        registrar,
                        reopened_info,
                        expected_state,
                        allow_state_resume=True,
                    )
                    if not resolved_callback:
                        reopened_state = _registration_state_from_info({"final_url": str(reopened_info.get("final_url") or ""), "json": reopened_info.get("json") if isinstance(reopened_info.get("json"), dict) else {}, "text": str(reopened_info.get("text") or "")})
                        log(f"注册后 CPA OAuth 绑定后仍未拿到回调：当前页面类型={reopened_state.get('kind') or '-'}")
                        if str(reopened_state.get("kind") or "") == "add_email" and add_email_attempt_count < 2:
                            log("注册后 CPA OAuth 重开后仍停在绑定邮箱页，继续提交绑定验证码流程")
                            return _continue_add_email_if_needed(str(reopened_state.get("url") or reopened_info.get("final_url") or ""), source="reopen")
                if resolved_callback and pending_bind_email:
                    mailbox["bind_email"] = pending_bind_email
                    mailbox.pop("bind_email_pending", None)
                    log(f"注册后 CPA OAuth 已确认绑定邮箱并拿到回调：{pending_bind_email}")
                log(f"注册后 CPA OAuth 绑定邮箱后回调：{'ready' if resolved_callback else 'missing'}")
                return verified_url

            start_state = _registration_state_from_info({"final_url": str(oauth_info.get("final_url") or ""), "json": {}, "text": ""})
            log(f"注册后 CPA OAuth 当前页面：kind={start_state.get('kind') or '-'} url={_brief_flow_url(str(start_state.get('url') or oauth_info.get('final_url') or ''))}")
            if str(start_state.get("kind") or "") == "add_email":
                _continue_add_email_if_needed(str(start_state.get("url") or oauth_info.get("final_url") or ""), source="start")
            if not resolved_callback and str(start_state.get("kind") or "") == "password":
                if hasattr(registrar, "establish_signup_session"):
                    establish_info = registrar.establish_signup_session()
                    log(f"注册后 CPA OAuth 登录会话建立：ok={establish_info.get('ok')} kind={establish_info.get('flow_kind') or '-'}")
                    if not establish_info.get("ok"):
                        return RegistrationResult(
                            ok=False,
                            email=email,
                            password=password,
                            mailbox=mailbox,
                            callback_url=str(oauth_info.get("final_url") or ""),
                            error="cpa_login_session_establishment_failed",
                        )
                log("注册后 CPA OAuth 密码页已打开，提交刚创建账号的密码")
                password_info = _attempt_password_login(registrar, email, password)
                log(f"注册后 CPA OAuth 密码登录结果：status={password_info.get('status')} ok={password_info.get('ok')}")
                if not password_info.get("ok"):
                    return RegistrationResult(
                        ok=False,
                        email=email,
                        password=password,
                        mailbox=mailbox,
                        callback_url=str(oauth_info.get("final_url") or ""),
                        error=f"cpa_login_password_{password_info.get('status') or 0}",
                    )
                if _step_requires_phone_verification(password_info):
                    try:
                        sms_config = _build_reauthorize_sms_config(
                            sms_provider=str(getattr(config, "sms_provider", "") or "hero_sms"),
                            sms_api_key=str(getattr(config, "sms_api_key", "") or ""),
                            hero_sms_api_key=str(getattr(config, "hero_sms_api_key", "") or ""),
                            smsbower_api_key=str(getattr(config, "smsbower_api_key", "") or ""),
                            hero_sms_base_url=str(getattr(config, "hero_sms_base_url", "") or ""),
                            smsbower_base_url=str(getattr(config, "smsbower_base_url", "") or ""),
                            hero_sms_country=str(getattr(config, "hero_sms_country", "") or "16"),
                            hero_sms_service=str(getattr(config, "hero_sms_service") or "dr"),
                            hero_sms_max_price=getattr(config, "hero_sms_max_price", 0.0),
                            hero_sms_wait_timeout=int(getattr(config, "hero_sms_wait_timeout", 180) or 180),
                            hero_sms_wait_interval=int(getattr(config, "hero_sms_wait_interval", 5) or 5),
                            hero_sms_auto_retry=parse_bool(getattr(config, "hero_sms_auto_retry", False), key="hero_sms_auto_retry"),
                        )
                        retry_count = max(1, int(getattr(config, "hero_sms_retry_count", 3) or 3)) if sms_config.auto_retry else 1
                        resolved_callback, phone_info, phone_debug = _continue_with_optional_phone_verification(
                            registrar,
                            password_info,
                            expected_state,
                            sms_config=sms_config,
                            retry_count=retry_count,
                            email=email,
                        )
                        log(
                            "注册后 CPA OAuth 密码后手机验证处理："
                            f"provider={sms_config.provider} callback={'ready' if resolved_callback else 'missing'}"
                        )
                    except Exception as exc:
                        log(f"注册后 CPA OAuth 密码后手机验证失败：{exc}")
                        raise
                if not resolved_callback:
                    password_state = _registration_state_from_info(password_info)
                    if str(password_state.get("kind") or "") == "add_email":
                        _continue_add_email_if_needed(str(password_state.get("url") or ""), source="password")
                if not resolved_callback:
                    resolved_callback = _resolve_callback_step(registrar, password_info, expected_state, allow_state_resume=False)
                    log(f"注册后 CPA OAuth 密码登录后回调：{'ready' if resolved_callback else 'missing'}")
            try:
                if not resolved_callback:
                    sms_config = _build_reauthorize_sms_config(
                        sms_provider=str(getattr(config, "sms_provider", "") or "hero_sms"),
                        sms_api_key=str(getattr(config, "sms_api_key", "") or ""),
                        hero_sms_api_key=str(getattr(config, "hero_sms_api_key", "") or ""),
                        smsbower_api_key=str(getattr(config, "smsbower_api_key", "") or ""),
                        hero_sms_base_url=str(getattr(config, "hero_sms_base_url", "") or ""),
                        smsbower_base_url=str(getattr(config, "smsbower_base_url", "") or ""),
                        hero_sms_country=str(getattr(config, "hero_sms_country", "") or "16"),
                        hero_sms_service=str(getattr(config, "hero_sms_service", "") or "dr"),
                        hero_sms_max_price=getattr(config, "hero_sms_max_price", 0.0),
                        hero_sms_wait_timeout=int(getattr(config, "hero_sms_wait_timeout", 180) or 180),
                        hero_sms_wait_interval=int(getattr(config, "hero_sms_wait_interval", 5) or 5),
                        hero_sms_auto_retry=parse_bool(getattr(config, "hero_sms_auto_retry", False), key="hero_sms_auto_retry"),
                    )
                    retry_count = max(1, int(getattr(config, "hero_sms_retry_count", 3) or 3)) if sms_config.auto_retry else 1
                    resolved_callback, phone_info, phone_debug = _continue_with_optional_phone_verification(
                        registrar,
                        oauth_info,
                        expected_state,
                        sms_config=sms_config,
                        retry_count=retry_count,
                        email=email,
                    )
                    if phone_debug.get("required"):
                        log(
                            "注册后 CPA OAuth 手机验证处理："
                            f"provider={sms_config.provider} callback={'ready' if resolved_callback else 'missing'}"
                        )
            except Exception as exc:
                log(f"注册后 CPA OAuth 手机验证失败：{exc}")
                raise
            if not resolved_callback:
                callback_source_info = phone_info or oauth_info
                callback_state = _registration_state_from_info(callback_source_info)
                if str(callback_state.get("kind") or "") == "add_email":
                    _continue_add_email_if_needed(str(callback_state.get("url") or ""), source="phone")
            if not resolved_callback:
                resolved_callback = _resolve_oauth_callback(registrar, str((phone_info or oauth_info).get("final_url") or oauth_info.get("final_url") or ""), expected_state)
            if not resolved_callback:
                return RegistrationResult(
                    ok=False,
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str(oauth_info.get("final_url") or ""),
                    error="cpa_callback_not_reached",
                )
            cpa_result = _submit_callback_to_cpa(
                resolved_callback,
                cpa_url=config.codex2api_url,
                cpa_management_key=config.codex2api_admin_key,
                expected_state=expected_state,
            )
            mailbox["_callback_url"] = resolved_callback
            mailbox["_cpa_submit_ok"] = bool(cpa_result.get("ok"))
            mailbox["_cpa_submit_message"] = str(cpa_result.get("message") or "")
            log(f"CPA 回调提交结果：ok={mailbox['_cpa_submit_ok']} message={mailbox['_cpa_submit_message']}")
            return RegistrationResult(
                ok=bool(cpa_result.get("ok")),
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=resolved_callback,
                error="" if bool(cpa_result.get("ok")) else str(cpa_result.get("message") or "cpa_callback_submit_failed"),
            )
        except Exception as exc:
            log(f"注册后 CPA OAuth 回调提交失败：{exc}")
            return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=candidate_callback, error=str(exc or "cpa_callback_submit_failed"))

    try:
        oauth_info = registrar.start_authorize(email=email, screen_hint="login")
    except TypeError as exc:
        if "screen_hint" not in str(exc) and "unexpected keyword" not in str(exc):
            raise
        oauth_info = registrar.start_authorize(email=email)
    log(f"注册后 OAuth 授权入口已打开：status={oauth_info.get('status')} final_url={_brief_flow_url(str(oauth_info.get('final_url') or ''))}")
    resolved_callback = ""
    try:
        from .oauth_token_flow import _resolve_oauth_callback

        resolved_callback = _resolve_oauth_callback(registrar, str(oauth_info.get("final_url") or ""), str(oauth_info.get("state") or ""))
    except Exception as exc:
        log(f"注册后 OAuth 回调解析异常：{exc}")
    if not resolved_callback:
        return RegistrationResult(ok=False, email=email, password=password, mailbox=mailbox, callback_url=str(oauth_info.get("final_url") or ""), error="oauth_callback_not_reached")
    token_result = registrar.exchange_platform_tokens(str(oauth_info.get("code_verifier") or ""), resolved_callback)
    token_result.password = password
    token_result.mailbox = mailbox
    return token_result


def _finalize_registration_result(config: RegisterConfig, registrar: PlatformRegistrar, result: RegistrationResult, email: str, mailbox: dict[str, Any]) -> RegistrationResult:
    workspace_id = registrar.get_workspace_id() if hasattr(registrar, "get_workspace_id") else ""
    if workspace_id:
        mailbox["account_id"] = workspace_id
        log(f"workspace/account id captured: {workspace_id}")
    result.mailbox = mailbox
    if result.ok and not mailbox.get("_cpa_submit_ok") and parse_bool(getattr(config, "codex2api_auto_import", False), key="codex2api_auto_import") and str(config.codex2api_url or "").strip() and str(config.codex2api_admin_key or "").strip():
        try:
            from .oauth_token_flow import import_result_to_codex2api

            codex2api_result = import_result_to_codex2api(
                result,
                codex2api_url=config.codex2api_url,
                admin_key=config.codex2api_admin_key,
                account_name=result.email or email,
                proxy_url=str(config.codex2api_proxy_url or ""),
            )
            mailbox["_codex2api_submit_ok"] = bool(codex2api_result.get("ok"))
            mailbox["_codex2api_submit_message"] = str(codex2api_result.get("message") or "")
            log(f"Codex2API auto import completed: {mailbox['_codex2api_submit_message']}")
        except Exception as exc:
            mailbox["_codex2api_submit_ok"] = False
            mailbox["_codex2api_submit_message"] = str(exc)
            log(f"Codex2API auto import failed: {exc}")
    save_result(result)
    try:
        from .accounts_store import save_registration_result_to_account

        save_registration_result_to_account(result, source="register")
    except Exception:
        pass
    return result


def _run_email_registration_state_machine(
    *,
    config: RegisterConfig,
    registrar: PlatformRegistrar,
    mailbox: dict[str, Any],
    email: str,
    password: str,
    full_name: str,
    birthdate: str,
    start_info: dict[str, Any],
) -> RegistrationResult:
    state = _registration_state_from_info(start_info)
    register_info: dict[str, Any] = {}
    validate_info: dict[str, Any] = {}
    create_start_done = False
    register_submitted = False
    otp_verified = False
    seen: dict[tuple[str, str], int] = {}

    for step in range(1, 14):
        signature = (str(state.get("kind") or ""), str(state.get("url") or ""))
        seen[signature] = seen.get(signature, 0) + 1
        log(f"注册状态机：step={step} kind={state.get('kind') or '-'} page={state.get('page_type') or '-'} url={state.get('url') or '-'}")
        if seen[signature] > 3:
            return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=str(state.get("url") or ""), error=f"registration_state_stuck:{state.get('kind') or 'unknown'}")

        kind = str(state.get("kind") or "")
        if kind == "error":
            url = str(state.get("url") or "")
            error = "authorize_hydra_invalid_request" if "authorize_hydra_invalid_request" in url else "authorize_failed"
            return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=url, error=error)

        if kind == "password":
            if register_submitted:
                return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=str(state.get("url") or ""), error="password_stage_repeated")
            register_info = registrar.register_user(email=email, password=password)
            register_submitted = True
            log(f"注册提交结果：status={register_info.get('status')} ok={register_info.get('ok')}")
            if not register_info.get("ok"):
                error = _response_error_summary("register_user", register_info)
                log(f"注册提交失败：{error}")
                return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=_registration_continue_url(register_info) or str(state.get("url") or ""), error=error)
            mailbox["_code_after_ts"] = int(time.time() * 1000)
            otp_info = registrar.send_otp()
            log(f"邮箱验证码发送结果：status={otp_info.get('status')} ok={otp_info.get('ok')} final_url={otp_info.get('final_url')}")
            state = {"kind": "email_otp", "url": _registration_continue_url(otp_info) or f"{auth_base}/email-verification", "page_type": "email_otp_verification"}
            continue

        if kind == "email_otp":
            log("已进入邮箱验证页，等待邮箱验证码")
            code = _wait_email_otp_with_resend(config, registrar, mailbox, resend_on_miss=True)
            if not code:
                return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=str(state.get("url") or ""), error="wait_for_code_timeout")
            log(f"已收到邮箱验证码：{code}")
            code_meta = mailbox.get("_last_code_meta") or {}
            if code_meta:
                log(
                    "verification code metadata: "
                    f"provider={code_meta.get('provider') or ''} "
                    f"message_id={code_meta.get('message_id') or ''} "
                    f"received_at_ms={code_meta.get('received_at_ms') or 0}"
                )
            validate_info = registrar.validate_signup_otp(code)
            otp_verified = bool(validate_info.get("ok"))
            log(f"邮箱验证码校验结果：status={validate_info.get('status')} ok={validate_info.get('ok')} continue_url={((validate_info.get('json') or {}).get('continue_url') or '')}")
            if not validate_info.get("ok"):
                validate_text = str(validate_info.get("text") or "").strip()
                validate_json = validate_info.get("json") or {}
                log(f"validate_signup_otp failure body: {validate_text[:500] or validate_json}")
                return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=_registration_continue_url(validate_info), error=f"validate_signup_otp_{validate_info.get('status')}")
            state = _registration_state_from_info(validate_info)
            if state.get("kind") == "continue" and state.get("url"):
                state = _load_registration_state(registrar, str(state.get("url") or ""))
            continue

        if kind == "about_you":
            page_context = _registration_page_context((state.get("raw") or {}) if isinstance(state.get("raw"), dict) else validate_info)
            pre_submit_snapshot: dict[str, Any] = {}
            try:
                pre_submit_state = _load_registration_state(registrar, str(state.get("url") or f"{auth_base}/about-you"))
                pre_submit_snapshot = pre_submit_state.get("raw") if isinstance(pre_submit_state, dict) else {}
            except Exception as exc:
                pre_submit_snapshot = {"error": str(exc)}
            pre_submit_html = str(pre_submit_snapshot.get("text") or "").strip()
            if pre_submit_html:
                page_context = f"{page_context}\n{pre_submit_html}"
            log(f"about-you 页面识别：{_about_you_shape_log_summary(page_context)}")
            try:
                pre_artifacts = _save_about_you_presubmit_artifacts(
                    state=state,
                    page_snapshot=pre_submit_snapshot,
                    page_context=page_context,
                )
                log(f"about-you 提交前页面：json={pre_artifacts.get('json_path') or ''} html={pre_artifacts.get('html_path') or ''}")
            except Exception as exc:
                log(f"about-you 提交前页面保存失败：{exc}")
            try:
                create_info = registrar.create_account(full_name, birthdate, referer=str(state.get("url") or ""), page_context=page_context)
            except TypeError as exc:
                if "page_context" not in str(exc) and "unexpected keyword" not in str(exc):
                    raise
                create_info = registrar.create_account(full_name, birthdate, referer=str(state.get("url") or ""))
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
                log(f"姓名年龄/生日提交尝试：{attempt_summary}")
            log(f"姓名年龄/生日提交结果：status={create_info.get('status')} ok={create_info.get('ok')} location={create_info.get('location')} final_url={create_info.get('final_url')}")
            callback_url = _registration_continue_url(create_info) or str(state.get("url") or "")
            if not create_info.get("ok"):
                error_code = _accounts_error_code(create_info)
                if error_code == "registration_disallowed":
                    log("姓名年龄/生日接口失败响应：registration_disallowed（上游拒绝创建账号）")
                else:
                    failure_body = str(create_info.get("text") or create_info.get("json") or create_info.get("error") or "").strip()
                    if failure_body:
                        log(f"姓名年龄/生日接口失败响应：{failure_body[:500]}")
                try:
                    artifacts = _save_about_you_failure_artifacts(
                        state=state,
                        create_info=create_info,
                        page_snapshot=pre_submit_snapshot,
                        page_context=page_context,
                    )
                    log(f"about-you 失败调试文件：json={artifacts.get('json_path') or ''} html={artifacts.get('html_path') or ''}")
                except Exception as exc:
                    log(f"about-you 失败调试文件保存失败：{exc}")
                if error_code == "registration_disallowed":
                    log("上游拒绝创建账号：registration_disallowed，通常是当前代理/环境/邮箱风险导致，已停止无效表单兜底")
                    return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=callback_url, error="registration_disallowed")
                try:
                    from .oauth_token_flow import _submit_about_you_form

                    submitted_url, _ = _submit_about_you_form(
                        registrar,
                        page_url=str(state.get("url") or callback_url or f"{auth_base}/about-you"),
                        page_html=pre_submit_html or str(create_info.get("text") or ""),
                        full_name=full_name,
                        birthdate=birthdate,
                    )
                    callback_url = str(submitted_url or callback_url).strip()
                    log(f"姓名年龄/生日页面表单提交结果：final_url={callback_url}")
                    if callback_url and "/about-you" not in callback_url:
                        create_info = {**create_info, "ok": True, "location": callback_url}
                except Exception as exc:
                    log(f"姓名年龄/生日页面表单提交失败：{exc}")
            if not create_info.get("ok"):
                return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=callback_url, error=f"create_account_{create_info.get('status')}")
            resolved_post_create_url = _resolve_registration_post_create_url(
                registrar,
                start_info=start_info,
                create_info=create_info,
                fallback_url=callback_url,
            )
            if resolved_post_create_url and resolved_post_create_url != callback_url:
                log(f"about-you 后续回调/继续地址已解析：{_brief_flow_url(resolved_post_create_url)}")
            callback_url = resolved_post_create_url or callback_url
            if extract_oauth_callback_params_from_url(callback_url):
                state = {"kind": "callback", "url": callback_url, "page_type": ""}
            else:
                state = _registration_state_from_info({**create_info, "final_url": callback_url})
            if state.get("kind") == "continue" and state.get("url"):
                state = _load_registration_state(registrar, str(state.get("url") or ""))
            if state.get("kind") != "callback":
                state = {"kind": "callback", "url": str(state.get("url") or callback_url), "page_type": str(state.get("page_type") or "")}
            continue

        if kind == "callback":
            token_result = _exchange_registered_account_tokens(
                config=config,
                registrar=registrar,
                email=email,
                password=password,
                mailbox=mailbox,
                code_verifier=str(start_info.get("code_verifier") or ""),
                callback_url=str(state.get("url") or ""),
            )
            return _finalize_registration_result(config, registrar, token_result, email, mailbox)

        if kind in {"continue", "unknown"}:
            current_url = str(state.get("url") or "")
            if current_url:
                next_state = _load_registration_state(registrar, current_url)
                if next_state.get("kind") != "continue" or next_state.get("url") != current_url:
                    state = next_state
                    continue
            if not create_start_done:
                create_start_done = True
                create_start = registrar.create_account_start(email)
                log(f"邮箱注册入口初始化结果：status={create_start.get('status')} ok={create_start.get('ok')} final_url={create_start.get('final_url')}")
                if not create_start.get("ok") and int(create_start.get("status") or 0) not in (400, 409, 422):
                    error = _response_error_summary("create_account_start", create_start)
                    log(f"邮箱注册入口初始化失败：{error}")
                    return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=_registration_continue_url(create_start) or current_url, error=error)
                state = _registration_state_from_info(create_start)
                if state.get("kind") == "continue" and state.get("url"):
                    state = _load_registration_state(registrar, str(state.get("url") or ""))
                continue
            if not register_submitted and not otp_verified:
                state = {"kind": "password", "url": f"{auth_base}/create-account/password", "page_type": "create_account_password"}
                continue

        return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=str(state.get("url") or ""), error=f"unsupported_registration_state:{kind or 'unknown'}")

    return _failed_registration_result(email=email, password=password, mailbox=mailbox, callback_url=_registration_continue_url(validate_info or register_info or start_info), error="registration_state_machine_exhausted")


def run_placeholder(config: RegisterConfig) -> RegistrationResult:
    env_profile = prepare_environment_profile_from_config(config)
    effective_proxy = str(env_profile.proxy or config.proxy or "").strip()
    mailbox = create_mailbox(config)
    email = str(mailbox.get("email") or "").strip()
    password = str(getattr(config, "default_password", "") or "").strip() or _random_password()
    first_name, last_name = _random_name()
    birthdate = _random_birthdate()
    full_name = f"{first_name} {last_name}"
    log(f"已创建邮箱：{email}")
    log(f"已生成注册资料：密码已生成，姓名={full_name}，生日={birthdate}")
    log(f"本次账号密码：{password}")
    registrar: PlatformRegistrar | None = None
    env_lock_acquired = False
    env_snapshot: dict[str, Any] = {}
    try:
        _ENV_LOCK.acquire()
        env_lock_acquired = True
        env_snapshot = _snapshot_environment_state()
        _apply_environment_state(env_profile)
        log(f"环境模块：{summarize_environment_profile(env_profile)}")
        registrar = PlatformRegistrar(proxy=effective_proxy)
        mailbox["_runtime_proxy"] = effective_proxy
        mailbox["_code_after_ts"] = int(time.time() * 1000)
        info = registrar.start_email_signup(email=email)
        authorize_final_url = str(info.get("final_url") or "")
        email_verification_first = "email-verification" in authorize_final_url
        log(f"邮箱注册入口已打开：status={info.get('status')} final_url={authorize_final_url}")
        if "/error" in authorize_final_url or "authorize_hydra_invalid_request" in authorize_final_url:
            error = "authorize_hydra_invalid_request" if "authorize_hydra_invalid_request" in authorize_final_url else "authorize_failed"
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=authorize_final_url,
                error=error,
            )
        if "/password" not in authorize_final_url and "email-verification" not in authorize_final_url:
            create_start = registrar.create_account_start(email)
            log(f"邮箱注册入口初始化结果：status={create_start.get('status')} ok={create_start.get('ok')} final_url={create_start.get('final_url')}")
            if not create_start.get("ok"):
                error = _response_error_summary("create_account_start", create_start)
                log(f"邮箱注册入口初始化失败：{error}")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str(create_start.get("final_url") or authorize_final_url),
                    error=error,
                )
        establish_info = registrar.establish_signup_session()
        log(f"注册会话建立结果：ok={establish_info.get('ok')} cookies={((establish_info.get('cookie_summary') or {}).get('present') or [])}")
        if not establish_info.get("ok"):
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(info.get("final_url") or ""),
                error="session_establishment_failed",
            )
        return _run_email_registration_state_machine(
            config=config,
            registrar=registrar,
            mailbox=mailbox,
            email=email,
            password=password,
            full_name=full_name,
            birthdate=birthdate,
            start_info=info,
        )
        register_info: dict[str, Any] = {}
        otp_info: dict[str, Any] = {}
        if email_verification_first:
            log("已进入邮箱验证页，等待邮箱验证码")
        else:
            register_info = registrar.register_user(email=email, password=password)
            log(f"注册提交结果：status={register_info.get('status')} ok={register_info.get('ok')}")
            if not register_info.get("ok"):
                error = _response_error_summary("register_user", register_info)
                log(f"注册提交失败：{error}")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str((register_info.get("json") or {}).get("continue_url") or info.get("final_url") or ""),
                    error=error,
                )
            mailbox["_code_after_ts"] = int(time.time() * 1000)
            otp_info = registrar.send_otp()
            log(f"邮箱验证码发送结果：status={otp_info.get('status')} ok={otp_info.get('ok')} final_url={otp_info.get('final_url')}")
            if not otp_info.get("ok"):
                error = _response_error_summary("send_otp", otp_info)
                log(f"邮箱验证码发送失败：{error}")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str(otp_info.get("final_url") or info.get("final_url") or ""),
                    error=error,
                )
        code = wait_for_code(config, mailbox)
        if not code and email_verification_first:
            mailbox["_code_after_ts"] = int(time.time() * 1000)
            otp_info = registrar.send_otp()
            log(f"邮箱验证码重发结果：status={otp_info.get('status')} ok={otp_info.get('ok')} final_url={otp_info.get('final_url')}")
            if not otp_info.get("ok"):
                error = _response_error_summary("send_otp", otp_info)
                log(f"邮箱验证码重发失败：{error}")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str(otp_info.get("final_url") or info.get("final_url") or ""),
                    error=error,
                )
            code = wait_for_code(config, mailbox)
        if not code:
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(register_info.get("json", {}).get("continue_url") or info.get("final_url") or ""),
                error="wait_for_code_timeout",
            )
        log(f"已收到邮箱验证码：{code}")
        code_meta = mailbox.get("_last_code_meta") or {}
        if code_meta:
            log(
                "verification code metadata: "
                f"provider={code_meta.get('provider') or ''} "
                f"message_id={code_meta.get('message_id') or ''} "
                f"received_at_ms={code_meta.get('received_at_ms') or 0}"
            )
        validate_info = registrar.validate_signup_otp(code)
        log(f"邮箱验证码校验结果：status={validate_info.get('status')} ok={validate_info.get('ok')} continue_url={((validate_info.get('json') or {}).get('continue_url') or '')}")
        if not validate_info.get("ok"):
            validate_text = str(validate_info.get("text") or "").strip()
            validate_json = validate_info.get("json") or {}
            log(f"validate_signup_otp failure body: {validate_text[:500] or validate_json}")
        if not validate_info.get("ok"):
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=str(((validate_info.get("json") or {}).get("continue_url") or info.get("final_url") or "")),
                error=f"validate_signup_otp_{validate_info.get('status')}",
            )
        validate_continue_url = str((validate_info.get("json") or {}).get("continue_url") or validate_info.get("final_url") or "")
        if email_verification_first and "password" in validate_continue_url:
            register_info = registrar.register_user(email=email, password=password)
            log(f"注册提交结果：status={register_info.get('status')} ok={register_info.get('ok')}")
            if not register_info.get("ok"):
                error = _response_error_summary("register_user", register_info)
                log(f"注册提交失败：{error}")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=str((register_info.get("json") or {}).get("continue_url") or (validate_info.get("json") or {}).get("continue_url") or info.get("final_url") or ""),
                    error=error,
                )
        elif email_verification_first and "about-you" in validate_continue_url:
            log(f"邮箱验证后已进入姓名生日页：{validate_continue_url}")
        elif email_verification_first:
            error = f"unexpected_email_signup_continue:{validate_continue_url or '-'}"
            log(f"邮箱验证后遇到未知页面：{validate_continue_url or '-'}")
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=validate_continue_url or str(info.get("final_url") or ""),
                error=error,
            )
        page_context = json.dumps(validate_info.get("json") or {}, ensure_ascii=False)
        pre_submit_snapshot: dict[str, Any] = {}
        try:
            pre_submit_state = _load_registration_state(registrar, str(validate_continue_url or f"{auth_base}/about-you"))
            pre_submit_snapshot = pre_submit_state.get("raw") if isinstance(pre_submit_state, dict) else {}
        except Exception as exc:
            pre_submit_snapshot = {"error": str(exc)}
        pre_submit_html = str(pre_submit_snapshot.get("text") or "").strip()
        if pre_submit_html:
            page_context = f"{page_context}\n{pre_submit_html}"
        try:
            pre_artifacts = _save_about_you_presubmit_artifacts(
                state={"url": validate_continue_url, "raw": validate_info},
                page_snapshot=pre_submit_snapshot,
                page_context=page_context,
            )
            log(f"about-you 提交前页面：json={pre_artifacts.get('json_path') or ''} html={pre_artifacts.get('html_path') or ''}")
        except Exception as exc:
            log(f"about-you 提交前页面保存失败：{exc}")
        try:
            create_info = registrar.create_account(full_name, birthdate, referer=validate_continue_url or "", page_context=page_context)
        except TypeError as exc:
            if "page_context" not in str(exc) and "unexpected keyword" not in str(exc):
                raise
            create_info = registrar.create_account(full_name, birthdate, referer=validate_continue_url or "")
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
            log(f"姓名年龄/生日提交尝试：{attempt_summary}")
        log(f"姓名年龄/生日提交结果：status={create_info.get('status')} ok={create_info.get('ok')} location={create_info.get('location')} final_url={create_info.get('final_url')}")
        callback_url = str(((create_info.get("json") or {}).get("continue_url") or create_info.get("location") or validate_info.get("json", {}).get("continue_url") or info.get("final_url") or ""))
        if not create_info.get("ok"):
            error_code = _accounts_error_code(create_info)
            if error_code == "registration_disallowed":
                log("姓名年龄/生日接口失败响应：registration_disallowed（上游拒绝创建账号）")
            else:
                failure_body = str(create_info.get("text") or create_info.get("json") or create_info.get("error") or "").strip()
                if failure_body:
                    log(f"姓名年龄/生日接口失败响应：{failure_body[:500]}")
            try:
                artifacts = _save_about_you_failure_artifacts(
                    state={"url": validate_continue_url, "raw": validate_info},
                    create_info=create_info,
                    page_snapshot=pre_submit_snapshot,
                    page_context=page_context,
                )
                log(f"about-you 失败调试文件：json={artifacts.get('json_path') or ''} html={artifacts.get('html_path') or ''}")
            except Exception as exc:
                log(f"about-you 失败调试文件保存失败：{exc}")
            if error_code == "registration_disallowed":
                log("上游拒绝创建账号：registration_disallowed，通常是当前代理/环境/邮箱风险导致，已停止无效表单兜底")
                return _failed_registration_result(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    callback_url=callback_url,
                    error="registration_disallowed",
                )
            try:
                from .oauth_token_flow import _submit_about_you_form

                submitted_url, _ = _submit_about_you_form(
                    registrar,
                    page_url=validate_continue_url or callback_url or str(info.get("final_url") or ""),
                    page_html=pre_submit_html or str(create_info.get("text") or ""),
                    full_name=full_name,
                    birthdate=birthdate,
                )
                callback_url = str(submitted_url or callback_url).strip()
                log(f"姓名年龄/生日页面表单提交结果：final_url={callback_url}")
                if callback_url and "/about-you" not in callback_url:
                    create_info = {**create_info, "ok": True, "location": callback_url}
            except Exception as exc:
                log(f"姓名年龄/生日页面表单提交失败：{exc}")
        if not create_info.get("ok"):
            return _failed_registration_result(
                email=email,
                password=password,
                mailbox=mailbox,
                callback_url=callback_url,
                error=f"create_account_{create_info.get('status')}",
            )
        if create_info.get("ok") and callback_url:
            resolved_post_create_url = _resolve_registration_post_create_url(
                registrar,
                start_info=info,
                create_info=create_info,
                fallback_url=callback_url,
            )
            if resolved_post_create_url and resolved_post_create_url != callback_url:
                log(f"about-you 后续回调/继续地址已解析：{_brief_flow_url(resolved_post_create_url)}")
                callback_url = resolved_post_create_url
            token_result = registrar.exchange_platform_tokens(str(info.get("code_verifier") or ""), callback_url)
            if token_result.ok:
                token_result.password = password
                workspace_id = registrar.get_workspace_id()
                if workspace_id:
                    mailbox["account_id"] = workspace_id
                    log(f"workspace/account id captured: {workspace_id}")
                token_result.mailbox = mailbox
                if parse_bool(getattr(config, "codex2api_auto_import", False), key="codex2api_auto_import") and str(config.codex2api_url or "").strip() and str(config.codex2api_admin_key or "").strip():
                    try:
                        from .oauth_token_flow import import_result_to_codex2api

                        codex2api_result = import_result_to_codex2api(
                            token_result,
                            codex2api_url=config.codex2api_url,
                            admin_key=config.codex2api_admin_key,
                            account_name=token_result.email or email,
                            proxy_url=str(config.codex2api_proxy_url or ""),
                        )
                        mailbox["_codex2api_submit_ok"] = bool(codex2api_result.get("ok"))
                        mailbox["_codex2api_submit_message"] = str(codex2api_result.get("message") or "")
                        log(f"Codex2API auto import completed: {mailbox['_codex2api_submit_message']}")
                    except Exception as exc:
                        mailbox["_codex2api_submit_ok"] = False
                        mailbox["_codex2api_submit_message"] = str(exc)
                        log(f"Codex2API auto import failed: {exc}")
                save_result(token_result)
                try:
                    from .accounts_store import save_registration_result_to_account
                    save_registration_result_to_account(token_result, source="register")
                except Exception:
                    pass
                return token_result
            save_result(token_result)
            try:
                from .accounts_store import save_registration_result_to_account
                save_registration_result_to_account(token_result, source="register")
            except Exception:
                pass
            return token_result
        error = f"register_{register_info.get('status')}_otp_{otp_info.get('status')}_validate_{validate_info.get('status')}_create_{create_info.get('status')}"
        result = RegistrationResult(
            ok=False,
            email=email,
            password=password,
            mailbox=mailbox,
            callback_url=callback_url,
            error=error,
        )
        save_result(result)
        return result
    finally:
        if env_lock_acquired:
            _restore_environment_state(env_snapshot)
            _ENV_LOCK.release()
        if registrar is not None:
            registrar.close()
