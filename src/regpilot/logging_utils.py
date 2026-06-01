from __future__ import annotations

import contextvars
import re
import sys
import threading
from typing import Tuple


_task_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_log_task_id", default=""
)
_worker_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "regpilot_log_worker_id", default=""
)

_stdout_lock = threading.Lock()


def _zh_line(text: str) -> str:
    value = str(text or "").strip()
    if value.startswith("Flow stage:"):
        value = value.split("Flow stage:", 1)[1].strip()
    if value.startswith("阶段："):
        value = value.split("阶段：", 1)[1].strip()
    replacements = [
        (r"\bstatus=", "状态码="),
        (r"\bok=True\b", "成功=是"),
        (r"\bok=False\b", "成功=否"),
        (r"\bmatched=True\b", "匹配=是"),
        (r"\bmatched=False\b", "匹配=否"),
        (r"\bfinal_url=", "最终地址="),
        (r"\bcontinue_url=", "继续地址="),
        (r"\blocation=", "跳转地址="),
        (r"\bkind=", "类型="),
        (r"\bpage=", "页面="),
        (r"\bstep=", "步骤="),
        (r"\burl=", "地址="),
        (r"\bcookies=", "Cookie="),
        (r"\bprovider=", "接码服务="),
        (r"\bsource=", "来源="),
        (r"\bmessage=", "消息="),
        (r"\bcallback=ready\b", "OAuth 回调=已拿到"),
        (r"\bcallback=missing\b", "OAuth 回调=未拿到"),
        (r"\b类型=callback\b", "类型=OAuth 回调"),
        (r"：ready\b", "：已拿到"),
        (r"：missing\b", "：未拿到"),
        (r"\bregistration_disallowed\b", "上游拒绝创建账号"),
        (r"\bmissing_oauth_callback\b", "未拿到 OAuth 回调"),
        (r"\boauth_callback_not_reached\b", "未到达 OAuth 回调"),
        (r"\bcpa_callback_not_reached\b", "CPA 回调未到达"),
    ]
    for pattern, replacement in replacements:
        value = re.sub(pattern, replacement, value)
    value = re.sub(r"\bregister_user_(\d+)\b", r"注册提交失败（状态码=\1）", value)
    return value


def set_log_context(task_id: str = "", worker_id: str = "") -> Tuple[contextvars.Token, contextvars.Token]:
    return (
        _task_id_var.set(task_id or ""),
        _worker_id_var.set(worker_id or ""),
    )


def reset_log_context(tokens: Tuple[contextvars.Token, contextvars.Token]) -> None:
    try:
        _task_id_var.reset(tokens[0])
    except Exception:
        pass
    try:
        _worker_id_var.reset(tokens[1])
    except Exception:
        pass


def _format_tag() -> str:
    task_id = _task_id_var.get()
    worker_id = _worker_id_var.get()
    if not task_id and not worker_id:
        return ""
    parts = []
    if task_id:
        parts.append(f"task={task_id}")
    if worker_id:
        parts.append(f"worker={worker_id}")
    return f"[{','.join(parts)}] "


def _emit(line: str) -> None:
    text = _format_tag() + line
    with _stdout_lock:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()


def log(text: str) -> None:
    _emit(f"阶段：{_zh_line(text)}")


def log_raw(text: str) -> None:
    _emit(str(text or ""))
