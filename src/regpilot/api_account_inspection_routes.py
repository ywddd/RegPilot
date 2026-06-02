from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from .account_inspection import (
    AccountInspectionCpaActionRequest,
    AccountInspectionRequest,
    _run_account_inspection,
    _run_cpa_auth_action,
)
from .api_config_values import _prefer_reauthorize_sms_values
from .api_tasks import _run_job


router = APIRouter()


@router.post("/api/accounts/inspection/job")
def api_account_inspection_job(payload: AccountInspectionRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)

    def run() -> dict[str, Any]:
        return _run_account_inspection(payload, sms_values)

    return _run_job("account_inspection", run)


@router.post("/api/accounts/inspection/cpa-action")
def api_account_inspection_cpa_action(payload: AccountInspectionCpaActionRequest) -> dict[str, Any]:
    return _run_cpa_auth_action(payload)
