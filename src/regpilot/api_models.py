from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


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
