from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from . import microsoft_mail_pool
from .api_models import MicrosoftMailAccountRequest, MicrosoftMailImportRequest


router = APIRouter()


def _safe_microsoft_mail_account(item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    if out.get("password"):
        out["password"] = "***"
    if out.get("refresh_token"):
        out["refresh_token"] = "***"
    return out


@router.get("/api/microsoft-mail/accounts")
def api_list_microsoft_mail_accounts() -> dict[str, Any]:
    items = microsoft_mail_pool.list_accounts()
    return {"ok": True, "items": [_safe_microsoft_mail_account(item) for item in items], "total": len(items)}


@router.post("/api/microsoft-mail/accounts")
def api_upsert_microsoft_mail_account(payload: MicrosoftMailAccountRequest) -> dict[str, Any]:
    item = microsoft_mail_pool.upsert_account(payload.model_dump())
    return {"ok": True, "item": _safe_microsoft_mail_account(item)}


@router.post("/api/microsoft-mail/import")
def api_import_microsoft_mail_accounts(payload: MicrosoftMailImportRequest) -> dict[str, Any]:
    return {"ok": True, **microsoft_mail_pool.import_accounts(payload.text)}


@router.post("/api/microsoft-mail/clear-used")
def api_clear_used_microsoft_mail_accounts() -> dict[str, Any]:
    return {"ok": True, "count": microsoft_mail_pool.clear_used()}


@router.delete("/api/microsoft-mail/accounts/{account_id}")
def api_delete_microsoft_mail_account(account_id: str) -> dict[str, Any]:
    ok = microsoft_mail_pool.delete_account(account_id)
    if not ok:
        raise HTTPException(status_code=404, detail="microsoft_mail_account_not_found")
    return {"ok": True, "id": account_id}
