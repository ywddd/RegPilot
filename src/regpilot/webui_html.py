from __future__ import annotations

from importlib import resources


FASTAPI_INDEX_HTML = resources.files("regpilot").joinpath("templates/index.html").read_text(encoding="utf-8")
