from __future__ import annotations

import io
import threading
import traceback
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Callable, Type

from .logging_utils import reset_log_context, set_log_context


class JobOutputStream(io.TextIOBase):
    def __init__(self, jobs: Any, job_id: str) -> None:
        super().__init__()
        self._jobs = jobs
        self._job_id = job_id
        self._buffer = ""
        self._lock = threading.Lock()

    def write(self, s: str) -> int:
        self._jobs.raise_if_stop_requested(self._job_id)
        text = str(s or "")
        if not text:
            return 0
        with self._lock:
            self._buffer += text
            while "\n" in self._buffer:
                line, self._buffer = self._buffer.split("\n", 1)
                self._jobs.append_output(self._job_id, line + "\n")
                self._jobs.raise_if_stop_requested(self._job_id)
        return len(text)

    def flush(self) -> None:
        with self._lock:
            if self._buffer:
                self._jobs.append_output(self._job_id, self._buffer)
                self._buffer = ""


def run_job(
    jobs: Any,
    execution_lock: threading.Lock,
    kind: str,
    func: Callable[..., Any],
    *args: Any,
    error_translator: Callable[[Any], str],
    cancelled_error_type: Type[BaseException],
    **kwargs: Any,
) -> dict[str, str]:
    job_id = jobs.create(kind)

    def _job_output_text() -> str:
        for job in jobs.list():
            if job.get("id") == job_id:
                return str(job.get("output") or "")
        return ""

    def target() -> None:
        stdout = JobOutputStream(jobs, job_id)
        log_tokens = set_log_context(task_id=job_id)
        locked = False
        try:
            jobs.raise_if_stop_requested(job_id)
            # stdout/stderr redirection is process-global, and OAuth state can be
            # invalidated by concurrent CPA authorize flows. Run jobs one at a time.
            locked = execution_lock.acquire(blocking=False)
            if not locked:
                jobs.append_output(job_id, "阶段：任务已排队，等待前一个任务完成\n")
                while not locked:
                    jobs.raise_if_stop_requested(job_id)
                    locked = execution_lock.acquire(timeout=0.2)
            try:
                jobs.raise_if_stop_requested(job_id)
                jobs.mark_running(job_id)
                jobs.append_output(job_id, "阶段：任务开始执行\n")
                with redirect_stdout(stdout), redirect_stderr(stdout):
                    result = func(*args, **kwargs)
            finally:
                if locked:
                    execution_lock.release()
            stdout.flush()
            jobs.finish(job_id, result=result, output=_job_output_text())
        except cancelled_error_type as exc:
            stdout.flush()
            jobs.finish(
                job_id,
                result={"ok": False, "stopped": True, "message": str(exc)},
                error=None,
                output=_job_output_text(),
            )
            jobs.mark_stopped(job_id)
        except Exception as exc:
            jobs.append_output(job_id, f"阶段：任务失败：{error_translator(exc)}\n")
            stdout.flush()
            jobs.finish(
                job_id,
                error={"message": str(exc), "traceback": traceback.format_exc()},
                output=_job_output_text(),
            )
        finally:
            reset_log_context(log_tokens)

    threading.Thread(target=target, daemon=True).start()
    return {"ok": True, "job_id": job_id}
