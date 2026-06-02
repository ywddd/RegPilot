from __future__ import annotations

import argparse
import re
import requests
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .accounts_store import count_accounts, delete_account, delete_accounts, get_account, init_db, list_accounts, upsert_account
from .config import DATA_DIR
from . import microsoft_mail_pool
from .register_core import _decode_jwt_payload, auth_base, platform_oauth_client_id
from .reauthorize import auto_reauthorize_account_with_email_otp, finish_account_reauthorize, start_account_reauthorize
from .api_tasks import (
    JOBS,
    _hero_country_lookup,
    _hero_phone_bind,
    _hero_price_lookup,
    _phone_direct,
    _run_job,
    _run_register,
)
from .webui_html import FASTAPI_INDEX_HTML
from .api_models import (
    AccountDeleteRequest,
    AccountUpsertRequest,
    ConfigSaveRequest,
    MicrosoftMailAccountRequest,
    MicrosoftMailImportRequest,
    ReauthorizeAutoRequest,
    ReauthorizeFinishRequest,
    ReauthorizeRequest,
    TaskRunRequest,
)
from .api_presenters import _safe_job, _zh_job_message
from .account_status import _account_phone_status, _safe_account_with_status
from .api_config_values import (
    _load_webui_config,
    _merge_task_values,
    _preflight_hero_phone_bind,
    _preflight_phone_direct,
    _preflight_register,
    _preflight_sms_lookup,
    _prefer_codex2api_admin_key,
    _prefer_codex2api_proxy_url,
    _prefer_codex2api_url,
    _prefer_proxy,
    _prefer_reauthorize_sms_values,
    _save_webui_config,
)
from .account_inspection import (
    AccountInspectionCpaActionRequest,
    AccountInspectionDeps,
    AccountInspectionRequest,
    configure_account_inspection,
    _run_account_inspection,
    _run_cpa_auth_action,
)
app = FastAPI(title="RegPilot API", version="0.1.0")


def main() -> None:
    parser = argparse.ArgumentParser(prog="regpilot-api", description="Run the RegPilot FastAPI server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8766)
    args = parser.parse_args()
    import uvicorn

    uvicorn.run("regpilot.api:app", host=args.host, port=args.port)




@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return FASTAPI_INDEX_HTML


@app.get("/api/config")
def api_config() -> dict[str, Any]:
    return {"ok": True, "path": str(DATA_DIR / "webui_config.json"), "config": _load_webui_config()}


@app.post("/api/config")
def api_save_config(payload: ConfigSaveRequest) -> dict[str, Any]:
    requested_section = str(payload.section or "register").strip() or "register"
    if requested_section not in {"register", "phone_direct", "hero_phone_bind", "logs"}:
        raise HTTPException(status_code=400, detail="invalid_config_section")
    section = "hero_phone_bind" if requested_section == "phone_direct" else requested_section
    data = _load_webui_config()
    current = data.get(section) if isinstance(data.get(section), dict) else {}
    merged = dict(current)
    for key, value in (payload.values or {}).items():
        merged[str(key)] = value
    data[section] = merged
    try:
        saved = _save_webui_config(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "path": str(DATA_DIR / "webui_config.json"), "section": requested_section, "storage_section": section, "config": saved}


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "RegPilot API"}


def _safe_microsoft_mail_account(item: dict[str, Any]) -> dict[str, Any]:
    out = dict(item)
    if out.get("password"):
        out["password"] = "***"
    if out.get("refresh_token"):
        out["refresh_token"] = "***"
    return out


@app.get("/api/microsoft-mail/accounts")
def api_list_microsoft_mail_accounts() -> dict[str, Any]:
    items = microsoft_mail_pool.list_accounts()
    return {"ok": True, "items": [_safe_microsoft_mail_account(item) for item in items], "total": len(items)}


@app.post("/api/microsoft-mail/accounts")
def api_upsert_microsoft_mail_account(payload: MicrosoftMailAccountRequest) -> dict[str, Any]:
    item = microsoft_mail_pool.upsert_account(payload.model_dump())
    return {"ok": True, "item": _safe_microsoft_mail_account(item)}


@app.post("/api/microsoft-mail/import")
def api_import_microsoft_mail_accounts(payload: MicrosoftMailImportRequest) -> dict[str, Any]:
    return {"ok": True, **microsoft_mail_pool.import_accounts(payload.text)}


@app.post("/api/microsoft-mail/clear-used")
def api_clear_used_microsoft_mail_accounts() -> dict[str, Any]:
    return {"ok": True, "count": microsoft_mail_pool.clear_used()}


@app.delete("/api/microsoft-mail/accounts/{account_id}")
def api_delete_microsoft_mail_account(account_id: str) -> dict[str, Any]:
    ok = microsoft_mail_pool.delete_account(account_id)
    if not ok:
        raise HTTPException(status_code=404, detail="microsoft_mail_account_not_found")
    return {"ok": True, "id": account_id}


@app.get("/api/accounts")
def api_list_accounts(limit: int = 200, offset: int = 0, q: str = "") -> dict[str, Any]:
    limit = min(500, max(1, int(limit)))
    offset = max(0, int(offset))
    search = str(q or "").strip()
    return {
        "ok": True,
        "items": [_safe_account_with_status(item) for item in list_accounts(limit=limit, offset=offset, search=search)],
        "limit": limit,
        "offset": offset,
        "total": count_accounts(search=search),
        "q": search,
    }


@app.get("/api/accounts/{account_id}")
def api_get_account(account_id: str) -> dict[str, Any]:
    item = get_account(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="account_not_found")
    return {"ok": True, "item": _safe_account_with_status(item)}


def _iso_from_jwt_exp(value: Any) -> str:
    try:
        import datetime as _dt

        exp = int(value or 0)
        if exp <= 0:
            return ""
        return _dt.datetime.fromtimestamp(exp, _dt.timezone(_dt.timedelta(hours=8))).replace(microsecond=0).isoformat()
    except Exception:
        return ""


def _refresh_account_tokens(item: dict[str, Any]) -> dict[str, Any]:
    refresh_token = str(item.get("refresh_token") or "").strip()
    if not refresh_token:
        raise HTTPException(status_code=400, detail="account_has_no_refresh_token")
    proxy = _prefer_proxy("")
    proxies = {"http": proxy, "https": proxy} if proxy else None
    try:
        response = requests.post(
            f"{auth_base}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": platform_oauth_client_id,
            },
            timeout=60,
            verify=False,
            proxies=proxies,
        )
    except requests.RequestException as exc:
        failed = dict(item)
        failed["status"] = "auth_failed"
        failed["last_error"] = "refresh_token_failed:request_failed"
        try:
            upsert_account(failed)
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=failed["last_error"]) from exc
    try:
        data = response.json()
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    if response.status_code != 200:
        message = ""
        error = data.get("error") if isinstance(data.get("error"), dict) else {}
        if isinstance(error, dict):
            message = str(error.get("code") or error.get("message") or "").strip()
        failed = dict(item)
        failed["status"] = "auth_failed"
        failed["last_error"] = f"refresh_token_failed:{message or response.status_code}"
        try:
            upsert_account(failed)
        except Exception:
            pass
        raise HTTPException(status_code=400, detail=failed["last_error"])
    access_token = str(data.get("access_token") or "").strip()
    new_refresh_token = str(data.get("refresh_token") or refresh_token).strip()
    id_token = str(data.get("id_token") or item.get("id_token") or "").strip()
    if not access_token or not new_refresh_token:
        raise HTTPException(status_code=400, detail="refresh_token_missing_tokens")
    updated = dict(item)
    updated["access_token"] = access_token
    updated["refresh_token"] = new_refresh_token
    updated["id_token"] = id_token
    updated["status"] = "authorized"
    updated["last_error"] = ""
    saved = upsert_account(updated)
    return saved or updated



@app.get("/api/accounts/{account_id}/export-json")
def api_export_account_json(account_id: str) -> dict[str, Any]:
    item = get_account(account_id)
    if not item:
        raise HTTPException(status_code=404, detail="account_not_found")
    if not str(item.get("access_token") or "").strip() or not str(item.get("refresh_token") or "").strip():
        raise HTTPException(status_code=400, detail="account_has_no_local_token")
    item = _refresh_account_tokens(item)
    phone_status = _account_phone_status(item)
    if phone_status.get("phone_status") not in {"verified", "bound_recorded", "authorized_assumed"}:
        raise HTTPException(status_code=400, detail="phone_not_verified_reauthorize_after_binding_required")
    access_token = str(item.get("access_token") or "")
    id_token = str(item.get("id_token") or "")
    access_payload = _decode_jwt_payload(access_token) or {}
    id_payload = _decode_jwt_payload(id_token) or {}
    profile = access_payload.get("https://api.openai.com/profile") if isinstance(access_payload.get("https://api.openai.com/profile"), dict) else {}
    auth_claim = id_payload.get("https://api.openai.com/auth") if isinstance(id_payload.get("https://api.openai.com/auth"), dict) else {}
    orgs = auth_claim.get("organizations") if isinstance(auth_claim.get("organizations"), list) else []
    default_org = next((org for org in orgs if isinstance(org, dict) and org.get("is_default")), orgs[0] if orgs else {})
    email = str(item.get("email") or profile.get("email") or id_payload.get("email") or "")
    expired = _iso_from_jwt_exp(access_payload.get("exp"))
    payload = {
        "access_token": access_token,
        "account_id": str((item.get("mailbox") or {}).get("account_id") or default_org.get("id") or "") if isinstance(item.get("mailbox"), dict) or isinstance(default_org, dict) else "",
        "disabled": False,
        "email": email,
        "expired": expired,
        "id_token": id_token,
        "last_refresh": str(item.get("last_auth_at") or item.get("updated_at") or ""),
        "plan_type": "free",
        "refresh_token": str(item.get("refresh_token") or ""),
        "type": "codex",
    }
    safe_email = re.sub(r"[^a-zA-Z0-9_.-]+", "_", str(item.get("email") or account_id)).strip("_") or account_id
    return {"ok": True, "filename": f"cpa-{safe_email}.json", "payload": payload}


@app.post("/api/accounts")
def api_upsert_account(payload: AccountUpsertRequest) -> dict[str, Any]:
    item = upsert_account(payload.model_dump())
    return {"ok": True, "item": _safe_account_with_status(item)}


@app.post("/api/accounts/delete")
def api_delete_accounts(payload: AccountDeleteRequest) -> dict[str, Any]:
    result = delete_accounts(payload.ids)
    return {"ok": True, **result}


@app.delete("/api/accounts/{account_id}")
def api_delete_account(account_id: str) -> dict[str, Any]:
    ok = delete_account(account_id)
    if not ok:
        raise HTTPException(status_code=404, detail="account_not_found")
    return {"ok": True, "id": account_id}


@app.post("/api/accounts/inspection/job")
def api_account_inspection_job(payload: AccountInspectionRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)

    def run() -> dict[str, Any]:
        return _run_account_inspection(payload, sms_values)

    return _run_job("account_inspection", run)


@app.post("/api/accounts/inspection/cpa-action")
def api_account_inspection_cpa_action(payload: AccountInspectionCpaActionRequest) -> dict[str, Any]:
    return _run_cpa_auth_action(payload)


@app.post("/api/tasks/register")
def api_task_register(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("register", payload.values or {})
    _preflight_register(merged)
    return _run_job("register", _run_register, merged)


@app.post("/api/tasks/hero/phone-bind")
def api_task_hero_phone_bind(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_hero_phone_bind(merged)
    return _run_job("phone_direct", _phone_direct, merged)


@app.post("/api/tasks/phone-direct")
def api_task_phone_direct(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("phone_direct", payload.values or {})
    _preflight_phone_direct(merged)
    return _run_job("phone_direct", _phone_direct, merged)


@app.post("/api/hero/countries")
def api_hero_countries(payload: TaskRunRequest) -> dict[str, Any]:
    return api_sms_countries(payload)


@app.post("/api/sms/countries")
def api_sms_countries(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_sms_lookup(merged)
    try:
        return _hero_country_lookup(merged)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/sms/price")
def api_sms_price(payload: TaskRunRequest) -> dict[str, Any]:
    merged = _merge_task_values("hero_phone_bind", payload.values or {})
    _preflight_sms_lookup(merged)
    try:
        return _hero_price_lookup(merged)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))



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


@app.get("/api/jobs")
def api_jobs() -> dict[str, Any]:
    return {"ok": True, "items": [_safe_job(job) for job in JOBS.list()]}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str) -> dict[str, Any]:
    for job in JOBS.list():
        if job.get("id") == job_id:
            return {"ok": True, "item": _safe_job(job)}
    raise HTTPException(status_code=404, detail="job_not_found")


@app.post("/api/jobs/{job_id}/stop")
def api_job_stop(job_id: str) -> dict[str, Any]:
    try:
        result = JOBS.request_stop(job_id)
    except ValueError as exc:
        if str(exc) == "job_not_found":
            raise HTTPException(status_code=404, detail="job_not_found")
        raise
    return {"ok": True, **result}


@app.post("/api/accounts/reauthorize")
def api_reauthorize(payload: ReauthorizeRequest) -> dict[str, Any]:
    outcome = start_account_reauthorize(payload.account_id, proxy=_prefer_proxy(payload.proxy))
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "authorize_url": outcome.authorize_url,
        "state": outcome.state,
        "nonce": outcome.nonce,
        "redirect_uri": outcome.redirect_uri,
        "client_id": outcome.client_id,
        "code_verifier": outcome.code_verifier,
        "bind_email": outcome.bind_email,
    }


@app.post("/api/accounts/reauthorize/finish")
def api_reauthorize_finish(payload: ReauthorizeFinishRequest) -> dict[str, Any]:
    outcome = finish_account_reauthorize(
        payload.account_id,
        callback_or_code=payload.callback_or_code,
        code_verifier=payload.code_verifier,
        state=payload.state,
        redirect_uri=payload.redirect_uri,
        client_id=payload.client_id,
        codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
        codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
        codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
        proxy=_prefer_proxy(payload.proxy),
    )
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "callback_url": outcome.callback_url,
        "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
        "cpa_import_submit_message": outcome.codex2api_import_submit_message,
        "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
        "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
    }


def _reauthorize_account_log_line(account_id: str) -> str:
    account = get_account(account_id) or {}
    account_email = str(account.get("email") or "").strip()
    if account_email:
        return f"阶段：账号：{account_email}（ID：{account_id}）"
    return f"阶段：账号ID：{account_id}"


@app.post("/api/accounts/reauthorize/auto/job")
def api_reauthorize_auto_job(payload: ReauthorizeAutoRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)

    def run() -> dict[str, Any]:
        print("阶段：开始重新授权")
        print(_reauthorize_account_log_line(payload.account_id))
        print(f"阶段：CPA 地址：{_prefer_codex2api_url(payload.codex2api_url)}")
        outcome = auto_reauthorize_account_with_email_otp(
            payload.account_id,
            codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
            codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
            codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
            proxy=_prefer_proxy(payload.proxy),
            wait_timeout=payload.wait_timeout,
            wait_interval=payload.wait_interval,
            request_timeout=payload.request_timeout,
            allow_phone_verification=bool(payload.allow_phone_verification),
            **sms_values,
        )
        print(f"阶段：重新授权任务结束：{_zh_job_message(outcome.message)}")
        if outcome.debug:
            try:
                slim = {k: v for k, v in outcome.debug.items() if k in {"validate_otp_summary", "resume_probe", "callback_summary", "codex2api_oauth", "cpa_oauth", "consent_direct_summary", "phone_verification_after_password_summary", "phone_verification_after_email_otp_summary", "phone_verification_after_pre_password_email_otp_summary"}}
                if slim:
                    print("阶段：调试摘要已生成，敏感字段已隐藏")
            except Exception as exc:
                print(f"阶段：调试摘要生成失败：{exc}")
        return {
            "ok": outcome.ok,
            "message": outcome.message,
            "item": outcome.account,
            "callback_url": outcome.callback_url,
            "code": outcome.code,
            "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
            "cpa_import_submit_message": outcome.codex2api_import_submit_message,
            "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
            "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
        }
    return _run_job("reauthorize", run)


@app.post("/api/accounts/reauthorize/auto")
def api_reauthorize_auto(payload: ReauthorizeAutoRequest) -> dict[str, Any]:
    sms_values = _prefer_reauthorize_sms_values(payload)
    outcome = auto_reauthorize_account_with_email_otp(
        payload.account_id,
        codex2api_url=_prefer_codex2api_url(payload.codex2api_url),
        codex2api_admin_key=_prefer_codex2api_admin_key(payload.codex2api_admin_key),
        codex2api_proxy_url=_prefer_codex2api_proxy_url(payload.codex2api_proxy_url),
        proxy=_prefer_proxy(payload.proxy),
        wait_timeout=payload.wait_timeout,
        wait_interval=payload.wait_interval,
        request_timeout=payload.request_timeout,
        allow_phone_verification=bool(payload.allow_phone_verification),
        **sms_values,
    )
    if not outcome.ok and outcome.message == "account_not_found":
        raise HTTPException(status_code=404, detail="account_not_found")
    return {
        "ok": outcome.ok,
        "message": outcome.message,
        "item": outcome.account,
        "callback_url": outcome.callback_url,
        "code": outcome.code,
        "cpa_import_submit_ok": outcome.codex2api_import_submit_ok,
        "cpa_import_submit_message": outcome.codex2api_import_submit_message,
        "codex2api_import_submit_ok": outcome.codex2api_import_submit_ok,
        "codex2api_import_submit_message": outcome.codex2api_import_submit_message,
        "debug": outcome.debug,
    }


if __name__ == "__main__":
    main()
