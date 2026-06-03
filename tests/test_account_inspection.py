from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from threading import Lock
from types import SimpleNamespace
from unittest.mock import patch

from regpilot import accounts_store
from regpilot import account_inspection as inspection
from regpilot import api as fastapi_api


class AccountInspectionTests(unittest.TestCase):
    def test_unauthorized_account_runs_reauthorize_without_delete_mark(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], codex2api_url="http://cpa.test", codex2api_admin_key="key", use_cpa_test=False)
        account = {"id": "acc-1", "email": "user@example.test", "password": "pw", "mailbox": {"provider": "icloud"}}
        outcome = SimpleNamespace(ok=True, message="CPA callback submitted", account={**account, "status": "authorized"})

        with patch("regpilot.account_inspection._accounts_for_inspection", return_value=[account]), \
             patch("regpilot.account_inspection._codex_account_test", return_value={"ok": False, "account_id": "acc-1", "email": "user@example.test", "status_code": 401, "error": "unauthorized"}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", return_value=outcome) as mock_reauth, \
             patch("regpilot.account_inspection._mark_account_delete_pending", side_effect=AssertionError("should not mark delete")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["checked_count"], 1)
        self.assertEqual(result["unauthorized_count"], 1)
        self.assertEqual(result["reauthorized_count"], 1)
        self.assertEqual(result["delete_marked_count"], 0)
        self.assertEqual(result["items"][0]["action"], "reauthorized")
        mock_reauth.assert_called_once()

    def test_unauthorized_account_marks_delete_pending_only_for_phone_verification(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], codex2api_url="http://cpa.test", codex2api_admin_key="key", use_cpa_test=False)
        account = {
            "id": "acc-1",
            "email": "user@example.test",
            "password": "pw",
            "status": "authorized",
            "source": "manual",
            "mailbox": {"provider": "icloud"},
            "tags": [],
        }
        outcome = SimpleNamespace(ok=False, message="manual_phone_verification_required", account=account)

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, \
             patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"), \
             patch("regpilot.account_inspection._accounts_for_inspection", return_value=[account]), \
             patch("regpilot.account_inspection._codex_account_test", return_value={"ok": False, "account_id": "acc-1", "email": "user@example.test", "status_code": 401, "error": "unauthorized"}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", return_value=outcome):
            accounts_store.upsert_account(account)
            result = fastapi_api._run_account_inspection(payload, {})
            saved = accounts_store.get_account("acc-1")

        self.assertEqual(result["delete_marked_count"], 1)
        self.assertEqual(result["items"][0]["action"], "delete_pending")
        self.assertEqual((saved or {}).get("status"), "delete_pending")
        self.assertIn("待删除", (saved or {}).get("tags") or [])
        self.assertFalse((saved or {}).get("usable_for_reauth"))

    def test_non_unauthorized_failure_does_not_run_reauthorize(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], use_cpa_test=False)
        account = {"id": "acc-1", "email": "user@example.test"}

        with patch("regpilot.account_inspection._accounts_for_inspection", return_value=[account]), \
             patch("regpilot.account_inspection._codex_account_test", return_value={"ok": False, "account_id": "acc-1", "email": "user@example.test", "status_code": 429, "error": "usage limit"}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", side_effect=AssertionError("should not reauthorize")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["unauthorized_count"], 0)
        self.assertEqual(result["reauthorized_count"], 0)
        self.assertEqual(result["delete_marked_count"], 0)
        self.assertEqual(result["items"][0]["action"], "failed_no_reauthorize")

    def test_default_inspection_uses_cpa_auth_file_test(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], codex2api_url="http://cpa.test", codex2api_admin_key="key", threads=2)
        account = {"id": "acc-1", "email": "user@example.test"}
        auth_file = {"auth_index": "codex-1", "name": "user_example_test.json", "email": "user@example.test"}

        with patch("regpilot.account_inspection._accounts_for_inspection", return_value=[account]), \
             patch("regpilot.account_inspection._cpa_auth_files", return_value=[auth_file]) as mock_files, \
             patch("regpilot.account_inspection._cpa_auth_test", return_value={"ok": True, "account_id": "acc-1", "email": "user@example.test", "auth_index": "codex-1", "auth_name": "user_example_test.json", "status_code": 200, "text": "CPA_AUTH_TEST_OK"}), \
             patch("regpilot.account_inspection._codex_account_test", side_effect=AssertionError("should use CPA test")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertTrue(result["use_cpa_test"])
        self.assertEqual(result["threads"], 2)
        self.assertEqual(result["ok_count"], 1)
        self.assertEqual(result["items"][0]["auth_index"], "codex-1")
        mock_files.assert_called_once()

    def test_default_all_inspection_iterates_cpa_auth_files_not_account_pool(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "cpa-only.json", "email": "cpa-only@example.test"}

        with patch("regpilot.account_inspection._accounts_for_inspection", side_effect=AssertionError("all CPA inspection should not use account pool as target source")), \
             patch("regpilot.account_inspection._cpa_auth_files", return_value=[auth_file]), \
             patch("regpilot.account_inspection.count_accounts", return_value=0), \
             patch("regpilot.account_inspection.list_accounts", return_value=[]), \
             patch("regpilot.account_inspection._cpa_auth_test", return_value={"ok": True, "account_id": "", "email": "cpa-only@example.test", "auth_index": "codex-1", "auth_name": "cpa-only.json", "status_code": 200, "text": "CPA_AUTH_TEST_OK"}):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["target_source"], "cpa_auth_files")
        self.assertEqual(result["checked_count"], 1)
        self.assertEqual(result["items"][0]["auth_name"], "cpa-only.json")

    def test_cpa_auth_files_excludes_usage_stats_file(self):
        with patch(
            "regpilot.account_inspection._cpa_request",
            return_value={
                "files": [
                    {"name": "usage-stats.json"},
                    {"name": "/auth/usage-stats.json"},
                    {"name": "user.json", "auth_index": "codex-1"},
                ]
            },
        ):
            files = inspection._cpa_auth_files("http://cpa.test", "key")

        self.assertEqual(files, [{"name": "user.json", "auth_index": "codex-1"}])

    def test_disabled_cpa_auth_file_with_available_weekly_quota_suggests_enable(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "disabled.json", "email": "user@example.test", "disabled": True}
        account = {"id": "acc-1", "email": "user@example.test", "_cpa_auth_file": auth_file}

        with patch(
            "regpilot.account_inspection._cpa_codex_usage_probe",
            return_value={
                "has_status_code": True,
                "status_code": 200,
                "payload": {"rate_limit": {"secondary_window": {"limit_window_seconds": 604800, "used_percent": 42}}},
                "body_text": "",
                "error": "",
            },
        ):
            result = inspection._cpa_auth_test(account, payload, [auth_file])

        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "cpa_usage_available")
        self.assertEqual(result["usage_state"], "available")
        self.assertEqual(result["recommended_action"], "enable")
        self.assertTrue(result["auth_disabled"])

    def test_enabled_cpa_auth_file_with_available_weekly_quota_keeps_account(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "healthy.json", "email": "user@example.test"}
        account = {"id": "acc-1", "email": "user@example.test", "_cpa_auth_file": auth_file}

        with patch(
            "regpilot.account_inspection._cpa_codex_usage_probe",
            return_value={
                "has_status_code": True,
                "status_code": 200,
                "payload": {"rate_limit": {"secondary_window": {"limit_window_seconds": 604800, "used_percent": 42}}},
                "body_text": "",
                "error": "",
            },
        ):
            result = inspection._cpa_auth_test(account, payload, [auth_file])

        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "cpa_keep")
        self.assertEqual(result["recommended_action"], "")

    def test_weekly_quota_limit_suggests_disabling_enabled_cpa_auth_file(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "full.json", "email": "user@example.test"}
        account = {"id": "acc-1", "email": "user@example.test", "_cpa_auth_file": auth_file}

        with patch(
            "regpilot.account_inspection._cpa_codex_usage_probe",
            return_value={
                "has_status_code": True,
                "status_code": 200,
                "payload": {"rate_limit": {"secondary_window": {"limit_window_seconds": 604800, "used_percent": 100}}},
                "body_text": "",
                "error": "",
            },
        ):
            result = inspection._cpa_auth_test(account, payload, [auth_file])

        self.assertEqual(result["action"], "cpa_usage_limit_reached")
        self.assertEqual(result["usage_state"], "limit_reached")
        self.assertEqual(result["recommended_action"], "disable")

    def test_disabled_cpa_auth_file_with_full_weekly_quota_keeps_disabled_without_failure(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "disabled.json", "email": "cpa-only@example.test", "status": "disabled"}

        with patch("regpilot.account_inspection._cpa_auth_files", return_value=[auth_file]), \
             patch("regpilot.account_inspection.count_accounts", return_value=0), \
             patch("regpilot.account_inspection.list_accounts", return_value=[]), \
             patch("regpilot.account_inspection._cpa_codex_usage_probe", return_value={"has_status_code": True, "status_code": 200, "payload": {"rate_limit": {"secondary_window": {"limit_window_seconds": 604800, "used_percent": 100}}}, "body_text": "", "error": ""}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", side_effect=AssertionError("disabled auth should not reauthorize")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["checked_count"], 1)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(result["unauthorized_count"], 0)
        self.assertEqual(result["items"][0]["action"], "cpa_keep")
        self.assertEqual(result["items"][0]["recommended_action"], "")

    def test_cpa_only_unauthorized_does_not_reauthorize_without_local_account(self):
        payload = fastapi_api.AccountInspectionRequest(codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "cpa-only.json", "email": "cpa-only@example.test"}

        with patch("regpilot.account_inspection._cpa_auth_files", return_value=[auth_file]), \
             patch("regpilot.account_inspection.count_accounts", return_value=0), \
             patch("regpilot.account_inspection.list_accounts", return_value=[]), \
             patch("regpilot.account_inspection._cpa_auth_test", return_value={"ok": False, "account_id": "", "email": "cpa-only@example.test", "auth_index": "codex-1", "auth_name": "cpa-only.json", "status_code": 401, "error": "unauthorized", "action": "cpa_auth_invalid", "inspection_source": "cpa_quota"}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", side_effect=AssertionError("no local account should not reauthorize")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["unauthorized_count"], 1)
        self.assertEqual(result["reauthorized_count"], 0)
        self.assertEqual(result["items"][0]["action"], "cpa_unauthorized_no_local_account")
        self.assertEqual(result["items"][0]["recommended_action"], "")

    def test_cpa_quota_unauthorized_with_local_account_runs_reauthorize_before_delete(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], codex2api_url="http://cpa.test", codex2api_admin_key="key")
        auth_file = {"auth_index": "codex-1", "name": "user.json", "email": "user@example.test"}
        account = {"id": "acc-1", "email": "user@example.test", "_cpa_auth_file": auth_file}
        outcome = SimpleNamespace(ok=True, message="CPA callback submitted", account={**account, "status": "authorized"})

        with patch("regpilot.account_inspection._accounts_for_inspection", return_value=[account]), \
             patch("regpilot.account_inspection._cpa_auth_files", return_value=[auth_file]), \
             patch("regpilot.account_inspection._cpa_auth_test", return_value={"ok": False, "account_id": "acc-1", "email": "user@example.test", "auth_index": "codex-1", "auth_name": "user.json", "status_code": 401, "error": "unauthorized", "action": "cpa_auth_invalid", "inspection_source": "cpa_quota"}), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", return_value=outcome) as mock_reauth, \
             patch("regpilot.account_inspection._mark_account_delete_pending", side_effect=AssertionError("should not mark delete before phone verification")):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["items"][0]["action"], "reauthorized")
        self.assertEqual(result["reauthorized_count"], 1)
        mock_reauth.assert_called_once()

    def test_cpa_quota_unauthorized_reauthorize_runs_serially_to_reduce_risk(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1", "acc-2"], codex2api_url="http://cpa.test", codex2api_admin_key="key", threads=2)
        auth_files = [
            {"auth_index": "codex-1", "name": "one.json", "email": "one@example.test"},
            {"auth_index": "codex-2", "name": "two.json", "email": "two@example.test"},
        ]
        accounts = [
            {"id": "acc-1", "email": "one@example.test", "_cpa_auth_file": auth_files[0]},
            {"id": "acc-2", "email": "two@example.test", "_cpa_auth_file": auth_files[1]},
        ]
        counter_lock = Lock()
        active = 0
        max_active = 0

        def fake_test(account, payload, auth_files):
            return {"ok": False, "account_id": account["id"], "email": account["email"], "auth_index": account["_cpa_auth_file"]["auth_index"], "auth_name": account["_cpa_auth_file"]["name"], "status_code": 401, "error": "unauthorized", "action": "cpa_auth_invalid", "inspection_source": "cpa_quota"}

        def fake_reauthorize(account_id, **kwargs):
            nonlocal active, max_active
            with counter_lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with counter_lock:
                active -= 1
            account = next(item for item in accounts if item["id"] == account_id)
            return SimpleNamespace(ok=True, message="CPA callback submitted", account={**account, "status": "authorized"})

        with patch("regpilot.account_inspection._accounts_for_inspection", return_value=accounts), \
             patch("regpilot.account_inspection._cpa_auth_files", return_value=auth_files), \
             patch("regpilot.account_inspection._cpa_auth_test", side_effect=fake_test), \
             patch("regpilot.account_inspection.auto_reauthorize_account_with_email_otp", side_effect=fake_reauthorize):
            result = fastapi_api._run_account_inspection(payload, {})

        self.assertEqual(result["reauthorized_count"], 2)
        self.assertEqual(max_active, 1)

    def test_cpa_action_disable_calls_management_status_endpoint(self):
        payload = fastapi_api.AccountInspectionCpaActionRequest(action="disable", auth_index="codex-1", name="user.json", codex2api_url="http://cpa.test", codex2api_admin_key="key")
        calls = []

        def fake_request(method, base_url, admin_key, path, **kwargs):
            calls.append((method, base_url, admin_key, path, kwargs.get("json_body")))
            if method == "GET":
                return {"files": [{"auth_index": "codex-1", "name": "user.json"}]}
            return {"status": "ok", "disabled": True}

        with patch("regpilot.account_inspection._cpa_request", side_effect=fake_request):
            result = fastapi_api.api_account_inspection_cpa_action(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "disable")
        self.assertEqual(calls[-1][0], "PATCH")
        self.assertEqual(calls[-1][3], "/v0/management/auth-files/status")
        self.assertEqual(calls[-1][4], {"name": "user.json", "disabled": True})

    def test_cpa_action_delete_removes_matching_local_account_after_cpa_delete(self):
        payload = fastapi_api.AccountInspectionCpaActionRequest(action="delete", account_id="acc-1", auth_index="codex-1", name="user.json", codex2api_url="http://cpa.test", codex2api_admin_key="key")
        account = {"id": "acc-1", "email": "user@example.test", "status": "delete_pending"}
        calls = []

        def fake_request(method, base_url, admin_key, path, **kwargs):
            calls.append((method, base_url, admin_key, path))
            if method == "GET":
                return {"files": [{"auth_index": "codex-1", "name": "user.json"}]}
            return {"status": "ok"}

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, \
             patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"), \
             patch("regpilot.account_inspection._cpa_request", side_effect=fake_request):
            accounts_store.upsert_account(account)
            result = fastapi_api.api_account_inspection_cpa_action(payload)
            saved = accounts_store.get_account("acc-1")

        self.assertTrue(result["ok"])
        self.assertTrue(result["local_account_deleted"])
        self.assertIsNone(saved)
        self.assertEqual(calls[-1][0], "DELETE")
        self.assertEqual(calls[-1][3], "/v0/management/auth-files?name=user.json")

    def test_cpa_action_delete_without_local_account_still_deletes_cpa_auth_file(self):
        payload = fastapi_api.AccountInspectionCpaActionRequest(action="delete", account_id="missing", auth_index="codex-1", name="user.json", codex2api_url="http://cpa.test", codex2api_admin_key="key")

        def fake_request(method, base_url, admin_key, path, **kwargs):
            if method == "GET":
                return {"files": [{"auth_index": "codex-1", "name": "user.json"}]}
            return {"status": "ok"}

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, \
             patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"), \
             patch("regpilot.account_inspection._cpa_request", side_effect=fake_request):
            result = fastapi_api.api_account_inspection_cpa_action(payload)

        self.assertTrue(result["ok"])
        self.assertFalse(result["local_account_deleted"])

    def test_inspection_endpoint_starts_account_inspection_job(self):
        payload = fastapi_api.AccountInspectionRequest(account_ids=["acc-1"], sms_provider="hero_sms")

        with patch("regpilot.api_account_inspection_routes._prefer_reauthorize_sms_values", return_value={}), \
             patch("regpilot.api_account_inspection_routes._run_job", return_value={"ok": True, "job_id": "job-1"}) as mock_run:
            result = fastapi_api.api_account_inspection_job(payload)

        self.assertEqual(result["job_id"], "job-1")
        self.assertEqual(mock_run.call_args.args[0], "account_inspection")

    def test_webui_places_account_inspection_between_accounts_and_logs(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertLess(html.index("账号池</b>"), html.index("账户巡检</b>"))
        self.assertLess(html.index("账户巡检</b>"), html.index("统一日志</b>"))
        self.assertIn('id="page-inspection"', html)
        self.assertIn("/api/accounts/inspection/job", html)
        self.assertIn("/api/accounts/inspection/cpa-action", html)
        self.assertIn('id="inspection_threads"', html)
        self.assertIn("saveInspectionThreadConfig", html)
        self.assertIn("regpilot-inspection-threads", html)
        self.assertIn("inspection_threads:threads", html)
        self.assertNotIn('id="inspection_codex2api_url"', html)
        self.assertNotIn('id="inspection_codex2api_admin_key"', html)
        self.assertNotIn('id="inspection_codex2api_proxy_url"', html)
        self.assertNotIn('id="inspection_model"', html)
        self.assertNotIn('id="inspection_prompt"', html)
        self.assertNotIn('id="inspection_request_timeout"', html)
        self.assertNotIn('id="inspection_use_cpa_test"', html)
        self.assertNotIn("巡检勾选账号", html)
        self.assertNotIn("保存 CPA 配置", html)
        self.assertIn("delete_pending:'待删除'", html)
        self.assertIn("cpa_disabled:'CPA 禁用'", html)
        self.assertIn("account_inspection:'账户巡检'", html)
        self.assertIn("inspectionMessageText", html)
        self.assertIn("executeInspectionRecommendations()", html)
        self.assertNotIn("data-inspection-execute-all", html)
        self.assertIn("skipConfirm:true", html)
        self.assertIn("inspectionExecutedActionKeys", html)
        self.assertIn("regpilot-inspection-executed:${jobId}", html)
        self.assertIn("markInspectionActionExecuted", html)
        self.assertIn("useInspectionJobExecutionState(job.id)", html)
        self.assertIn("markExecuted:true", html)
        self.assertIn("建议操作执行结果", html)
        self.assertIn("执行：", html)
        self.assertIn("<th>执行建议</th><th>CPA 操作</th>", html)
        self.assertIn('colspan="9"', html)
        self.assertIn("name==='delete'&&recommended==='delete'", html)
        self.assertIn(".danger", html)


    def test_webui_inspection_table_filters_keep_rows(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("isInspectionVisibleAction", html)
        self.assertIn("暂无需要处理的账号", html)


if __name__ == "__main__":
    unittest.main()
