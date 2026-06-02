from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException

from .api_config_values import _load_webui_config, _save_webui_config
from .api_models import ConfigSaveRequest
from .config import DATA_DIR


router = APIRouter()


@router.get("/api/config")
def api_config() -> dict[str, Any]:
    return {"ok": True, "path": str(DATA_DIR / "webui_config.json"), "config": _load_webui_config()}


@router.post("/api/config")
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
