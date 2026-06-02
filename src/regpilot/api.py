from __future__ import annotations

import argparse
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse

from .accounts_store import get_account, init_db
from . import microsoft_mail_pool
from .api_tasks import (
    _hero_phone_bind,
    _run_job,
    _run_register,
)
from .webui_html import FASTAPI_INDEX_HTML
from .api_models import (
    AccountDeleteRequest,
    AccountUpsertRequest,
    ConfigSaveRequest,
    ReauthorizeAutoRequest,
    ReauthorizeFinishRequest,
    ReauthorizeRequest,
    TaskRunRequest,
)
from .api_microsoft_mail import (
    router as microsoft_mail_router,
    _safe_microsoft_mail_account,
    api_clear_used_microsoft_mail_accounts,
    api_delete_microsoft_mail_account,
    api_import_microsoft_mail_accounts,
    api_list_microsoft_mail_accounts,
    api_upsert_microsoft_mail_account,
)
from .api_accounts import (
    router as accounts_router,
    _iso_from_jwt_exp,
    _refresh_account_tokens,
    api_delete_account,
    api_delete_accounts,
    api_export_account_json,
    api_get_account,
    api_list_accounts,
    api_upsert_account,
)
from .api_reauthorization import (
    router as reauthorization_router,
    _reauthorize_account_log_line,
    api_reauthorize,
    api_reauthorize_auto,
    api_reauthorize_auto_job,
    api_reauthorize_finish,
)
from .api_task_routes import (
    router as task_router,
    _hero_country_lookup,
    _hero_price_lookup,
    _phone_direct,
    api_hero_countries,
    api_sms_countries,
    api_sms_price,
    api_task_hero_phone_bind,
    api_task_phone_direct,
    api_task_register,
)
from .api_jobs import (
    router as jobs_router,
    api_job,
    api_job_stop,
    api_jobs,
)
from .api_config_routes import (
    router as config_router,
    api_config,
    api_save_config,
)
from .api_account_inspection_routes import (
    router as account_inspection_router,
    api_account_inspection_cpa_action,
    api_account_inspection_job,
)
from .api_presenters import _safe_job, _zh_job_message
from .account_status import _safe_account_with_status
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
    AccountInspectionRequest,
    _run_account_inspection,
    _run_cpa_auth_action,
)
app = FastAPI(title="RegPilot API", version="0.1.0")
app.include_router(config_router)
app.include_router(microsoft_mail_router)
app.include_router(task_router)
app.include_router(jobs_router)
app.include_router(account_inspection_router)


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


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "RegPilot API"}


app.include_router(reauthorization_router)
app.include_router(accounts_router)


if __name__ == "__main__":
    main()
