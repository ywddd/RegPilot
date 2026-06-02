from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from .account_inspection import (
    AccountInspectionDeps,
    AccountInspectionCpaActionRequest,
    AccountInspectionRequest,
    configure_account_inspection,
    _run_account_inspection,
    _run_cpa_auth_action,
)
from .api_accounts import _refresh_account_tokens
from .api_config_values import (
    _prefer_codex2api_admin_key,
    _prefer_codex2api_proxy_url,
    _prefer_codex2api_url,
    _prefer_proxy,
    _prefer_reauthorize_sms_values,
)
from .api_presenters import _zh_job_message
from .api_tasks import _run_job


router = APIRouter()

configure_account_inspection(
    AccountInspectionDeps(
        prefer_proxy=_prefer_proxy,
        prefer_codex2api_url=_prefer_codex2api_url,
        prefer_codex2api_admin_key=_prefer_codex2api_admin_key,
        prefer_codex2api_proxy_url=_prefer_codex2api_proxy_url,
        refresh_account_tokens=_refresh_account_tokens,
        zh_job_message=_zh_job_message,
    )
)


@router.post("/api/accounts/inspection/job")
def api_account_inspection_job(payload: AccountInspectionRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)

    def run() -> dict[str, Any]:
        return _run_account_inspection(payload, sms_values)

    return _run_job("account_inspection", run)


@router.post("/api/accounts/inspection/cpa-action")
def api_account_inspection_cpa_action(payload: AccountInspectionCpaActionRequest) -> dict[str, Any]:
    return _run_cpa_auth_action(payload)
