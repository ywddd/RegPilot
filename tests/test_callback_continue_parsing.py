from __future__ import annotations

import base64
import io
import json
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from datetime import datetime as real_datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from regpilot import register_core
from regpilot import oauth_token_flow as flow
from regpilot import api as fastapi_api
from regpilot import api_tasks
from regpilot import accounts_store
from regpilot import mail_provider
from regpilot import reauthorize as reauth
from regpilot import cli
from regpilot import microsoft_mail_pool
from regpilot.api_tasks import _hero_phone_bind


class CallbackContinueParsingTests(unittest.TestCase):
    def _response(self, *, url: str, text: str = "", headers: dict | None = None, status_code: int = 200):
        return SimpleNamespace(url=url, text=text, headers=headers or {}, status_code=status_code)

    def test_extract_form_inputs_prefers_authorize_button_formaction(self):
        html = '''
        <form action="/fallback-consent" method="post">
          <input type="hidden" name="state" value="abc">
          <button type="submit" formaction="/oauth/authorize?state=abc">Authorize</button>
        </form>
        '''

        action, fields, email_name, code_name = flow._extract_form_inputs(html)

        self.assertEqual(action, "/oauth/authorize?state=abc")
        self.assertEqual(fields.get("state"), "abc")
        self.assertEqual(email_name, "")
        self.assertEqual(code_name, "")

    def test_reauthorize_job_log_line_prefers_email_over_raw_id(self):
        with patch.object(fastapi_api, "get_account", return_value={"email": "user@example.com"}):
            line = fastapi_api._reauthorize_account_log_line("acct-1")

        self.assertEqual(line, "阶段：账号：user@example.com（ID：acct-1）")

    def test_compact_consent_debug_summary_drops_large_snippets(self):
        summary = {
            "url_prefix": "https://auth.openai.com/authorize",
            "attempts": [
                {
                    "method": "browser_like_consent_session",
                    "matched": False,
                    "snippets": {"html": "<html>" + ("x" * 2000)},
                    "text_prefix": "<!DOCTYPE html>" + ("x" * 2000),
                    "steps": [
                        {
                            "method": "get",
                            "source": "consent_page",
                            "status": 200,
                            "snippets": {"workspace_id": "secret"},
                            "text_prefix": "<!DOCTYPE html>",
                            "final_url_prefix": "https://auth.openai.com/log-in/password",
                            "text_markers": {"has_callback": False},
                        }
                    ],
                }
            ],
        }

        compact = reauth._compact_consent_debug_summary(summary)
        encoded = json.dumps(compact, ensure_ascii=False)

        self.assertIn("browser_like_consent_session", encoded)
        self.assertNotIn("snippets", encoded)
        self.assertNotIn("DOCTYPE", encoded)

    def test_extract_form_inputs_prefers_add_email_form_over_continue_form(self):
        html = '''
        <form action="/authorize/resume" method="post">
          <input type="hidden" name="state" value="abc">
          <button type="submit">Continue</button>
        </form>
        <form action="/add-email" method="post">
          <input type="hidden" name="state" value="abc">
          <input type="email" name="email">
          <button type="submit">Submit</button>
        </form>
        '''

        action, fields, email_name, code_name = flow._extract_form_inputs(html)

        self.assertEqual(action, "/add-email")
        self.assertEqual(fields.get("state"), "abc")
        self.assertEqual(email_name, "email")
        self.assertEqual(code_name, "")

    def test_add_email_refreshes_code_form_and_submits_hidden_fields(self):
        callback_url = "http://localhost:1455/auth/callback?code=cb123&state=oauth-state"
        email_form = '''
        <form action="/add-email" method="post">
          <input type="hidden" name="state" value="email-state">
          <input type="email" name="email">
        </form>
        '''
        code_form = '''
        <form action="/add-email/verify" method="post">
          <input type="hidden" name="state" value="form-state">
          <input name="otp_code">
        </form>
        '''
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(
            session=object(),
            device_id="dev-1",
            last_authorize={"state": "oauth-state"},
        )

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "get" and url.endswith("/add-email"):
                get_count = sum(1 for call in calls if call[0] == "get" and call[1].endswith("/add-email"))
                if get_count <= 2:
                    return FakeResponse(url, email_form), ""
                return FakeResponse(url, code_form), ""
            if method == "post" and url.endswith("/add-email"):
                return FakeResponse(url, email_form), ""
            if method == "post" and url.endswith("/api/accounts/add-email/send"):
                return FakeResponse(url, "{}", body={}), ""
            if method == "post" and url.endswith("/add-email/verify"):
                return FakeResponse(callback_url, ""), ""
            return FakeResponse(url, "", status_code=404), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"), \
             patch.object(flow.mail_provider, "wait_for_code", return_value="123456"):
            final_url, bind_email = flow._continue_with_optional_add_email(
                registrar,
                continue_url=f"{register_core.auth_base}/add-email",
                bind_email="bind@example.com",
                bind_mail_config={"providers": [{"type": "icloud"}]},
            )

        self.assertEqual(final_url, callback_url)
        self.assertEqual(bind_email, "bind@example.com")
        verify_call = next(call for call in calls if call[1].endswith("/add-email/verify"))
        self.assertEqual(verify_call[2]["data"]["state"], "form-state")
        self.assertEqual(verify_call[2]["data"]["otp_code"], "123456")
        self.assertFalse(any("/api/accounts/email-otp/validate" in call[1] for call in calls))

    def test_add_email_code_submit_prefers_code_form_when_email_form_is_also_present(self):
        callback_url = "http://localhost:1455/auth/callback?code=cb123&state=oauth-state"
        mixed_code_page = '''
        <form action="/add-email" method="post">
          <input type="hidden" name="state" value="email-state">
          <input type="email" name="email">
        </form>
        <form action="/email-verification" method="post">
          <input type="hidden" name="state" value="verify-state">
          <input name="verification_code">
        </form>
        '''
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(session=object(), device_id="dev-1", last_authorize={"state": "oauth-state"})

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "get" and url.endswith("/add-email"):
                get_count = sum(1 for call in calls if call[0] == "get" and call[1].endswith("/add-email"))
                if get_count <= 2:
                    return FakeResponse(url, '''
                    <form action="/add-email" method="post">
                      <input type="hidden" name="state" value="email-state">
                      <input type="email" name="email">
                    </form>
                    '''), ""
                return FakeResponse("https://auth.openai.com/email-verification", mixed_code_page), ""
            if method == "post" and url.endswith("/add-email"):
                return FakeResponse("https://auth.openai.com/email-verification", mixed_code_page), ""
            if method == "post" and url.endswith("/email-verification"):
                return FakeResponse(callback_url, ""), ""
            if method == "post" and url.endswith("/api/accounts/add-email/send"):
                return FakeResponse(url, "{}", body={}), ""
            if method == "post" and "/api/accounts/" in url:
                return FakeResponse(url, "{}", body={}), ""
            return FakeResponse(url, mixed_code_page), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"), \
             patch.object(flow.mail_provider, "wait_for_code", return_value="654321"):
            final_url, bind_email = flow._continue_with_optional_add_email(
                registrar,
                continue_url=f"{register_core.auth_base}/add-email",
                bind_email="bind@example.com",
                bind_mail_config={"providers": [{"type": "icloud"}]},
            )

        self.assertEqual(final_url, callback_url)
        self.assertEqual(bind_email, "bind@example.com")
        verify_call = next(call for call in calls if call[0] == "post" and call[1].endswith("/email-verification"))
        self.assertEqual(verify_call[2]["data"]["state"], "verify-state")
        self.assertEqual(verify_call[2]["data"]["verification_code"], "654321")

    def test_add_email_code_submit_uses_continue_url_from_response_body(self):
        consent_url = "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=oauth-state"
        code_form = '''
        <form action="/email-verification" method="post">
          <input type="hidden" name="state" value="verify-state">
          <input name="otp_code">
        </form>
        '''
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(session=object(), device_id="dev-1", last_authorize={"state": "oauth-state"})

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "get" and url.endswith("/add-email"):
                get_count = sum(1 for call in calls if call[0] == "get" and call[1].endswith("/add-email"))
                if get_count <= 2:
                    return FakeResponse(url, '''
                    <form action="/add-email" method="post">
                      <input type="hidden" name="state" value="email-state">
                      <input type="email" name="email">
                    </form>
                    '''), ""
                return FakeResponse("https://auth.openai.com/email-verification", code_form), ""
            if method == "post" and url.endswith("/add-email"):
                return FakeResponse("https://auth.openai.com/email-verification", code_form), ""
            if method == "post" and url.endswith("/email-verification"):
                return FakeResponse("https://auth.openai.com/email-verification", json.dumps({"continue_url": consent_url})), ""
            if method == "post" and url.endswith("/api/accounts/add-email/send"):
                return FakeResponse(url, "{}", body={}), ""
            if method == "post" and "/api/accounts/" in url:
                return FakeResponse(url, "{}", body={}), ""
            return FakeResponse(url, code_form), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"), \
             patch.object(flow.mail_provider, "wait_for_code", return_value="654321"):
            final_url, bind_email = flow._continue_with_optional_add_email(
                registrar,
                continue_url=f"{register_core.auth_base}/add-email",
                bind_email="bind@example.com",
                bind_mail_config={"providers": [{"type": "icloud"}]},
            )

        self.assertEqual(final_url, consent_url)
        self.assertEqual(bind_email, "bind@example.com")

    def test_add_email_does_not_report_bound_while_still_on_email_verification(self):
        email_form = '''
        <form action="/add-email" method="post">
          <input type="hidden" name="state" value="email-state">
          <input type="email" name="email">
        </form>
        '''
        code_form = '''
        <form action="/email-verification" method="post">
          <input type="hidden" name="state" value="form-state">
          <input name="otp_code">
        </form>
        '''
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(
            session=object(),
            device_id="dev-1",
            last_authorize={"state": "oauth-state"},
        )

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "get" and url.endswith("/add-email"):
                get_count = sum(1 for call in calls if call[0] == "get" and call[1].endswith("/add-email"))
                if get_count <= 2:
                    return FakeResponse(url, email_form), ""
                return FakeResponse("https://auth.openai.com/email-verification", code_form), ""
            if method == "post" and url.endswith("/add-email"):
                return FakeResponse(url, email_form), ""
            if method == "post" and url.endswith("/api/accounts/add-email/send"):
                return FakeResponse(url, "{}", body={}), ""
            if method == "post" and (url.endswith("/email-verification") or "/api/accounts/" in url):
                return FakeResponse("https://auth.openai.com/email-verification", code_form), ""
            return FakeResponse(url, "", status_code=404), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"), \
             patch.object(flow.mail_provider, "wait_for_code", return_value="123456"):
            final_url, bind_email = flow._continue_with_optional_add_email(
                registrar,
                continue_url=f"{register_core.auth_base}/add-email",
                bind_email="bind@example.com",
                bind_mail_config={"providers": [{"type": "icloud"}]},
            )

        self.assertEqual(final_url, "https://auth.openai.com/email-verification")
        self.assertEqual(bind_email, "")
        self.assertTrue(any("/api/accounts/add-email/validate" in call[1] for call in calls))

    def test_add_email_send_failure_does_not_wait_for_code(self):
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(session=object(), device_id="dev-1", last_authorize={"state": "oauth-state"})

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if method == "get" and url.endswith("/add-email"):
                return FakeResponse(url, '''
                <form action="/add-email" method="post">
                  <input type="hidden" name="state" value="email-state">
                  <input type="email" name="email">
                </form>
                '''), ""
            if method == "post" and url.endswith("/api/accounts/add-email/send"):
                return FakeResponse(url, '{"error":"missing_email"}', status_code=400, body={"error": "missing_email"}), ""
            if method == "post" and url.endswith("/api/accounts/add-email"):
                return FakeResponse(url, '{"error":"missing_email"}', status_code=400, body={"error": "missing_email"}), ""
            if method == "post" and url.endswith("/api/accounts/email-otp/send"):
                return FakeResponse(url, '{"error":"missing_email"}', status_code=400, body={"error": "missing_email"}), ""
            if method == "post" and url.endswith("/add-email"):
                return FakeResponse(url, ""), ""
            return FakeResponse(url, "", status_code=404), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"), \
             patch.object(flow.mail_provider, "wait_for_code", side_effect=AssertionError("must not wait after send failure")):
            with self.assertRaisesRegex(RuntimeError, "bind_email_send_failed_400"):
                flow._continue_with_optional_add_email(
                    registrar,
                    continue_url=f"{register_core.auth_base}/add-email",
                    bind_email="bind@example.com",
                    bind_mail_config={"providers": [{"type": "icloud"}]},
                )

        self.assertTrue(any(call[1].endswith("/api/accounts/add-email/send") for call in calls))

    def test_add_email_send_prefers_structured_browser_action_without_sentinel(self):
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(session=object(), device_id="dev-1", last_authorize={"state": "oauth-state"})

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            self.assertEqual(method, "post")
            self.assertTrue(url.endswith("/api/accounts/add-email/send"))
            self.assertEqual(kwargs.get("json"), {"origin_page_type": "add_email", "data": {"email": "bind@example.com"}})
            headers = kwargs.get("headers") or {}
            self.assertNotIn("openai-sentinel-token", {str(key).lower(): value for key, value in headers.items()})
            return FakeResponse(
                url,
                '{"continue_url":"https://auth.openai.com/email-verification"}',
                body={"continue_url": "https://auth.openai.com/email-verification"},
            ), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", side_effect=AssertionError("send must match browser action without sentinel")):
            info = flow._submit_add_email_api(registrar, "bind@example.com", f"{register_core.auth_base}/add-email")

        self.assertTrue(info["ok"])
        self.assertEqual(info["attempt"], "/api/accounts/add-email/send")
        self.assertFalse(info["sentinel"])
        self.assertEqual(len(calls), 1)

    def test_add_email_send_falls_back_to_legacy_email_payload(self):
        calls = []

        class FakeResponse:
            def __init__(self, url, text="", status_code=200, body=None, headers=None):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = headers or {}
                self._body = body or {}

            def json(self):
                return self._body

        registrar = SimpleNamespace(session=object(), device_id="dev-1", last_authorize={"state": "oauth-state"})

        def fake_request(_session, method, url, **kwargs):
            payload = kwargs.get("json")
            calls.append(payload)
            if payload == {"email": "bind@example.com"}:
                return FakeResponse(url, '{"continue_url":"https://auth.openai.com/email-verification"}', body={"continue_url": "https://auth.openai.com/email-verification"}), ""
            return FakeResponse(url, '{"error":{"code":"invalid_auth_step"}}', status_code=400, body={"error": {"code": "invalid_auth_step"}}), ""

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), \
             patch.object(flow, "build_sentinel_token", return_value="sentinel"):
            info = flow._submit_add_email_api(registrar, "bind@example.com", f"{register_core.auth_base}/add-email")

        self.assertTrue(info["ok"])
        self.assertIn({"origin_page_type": "add_email", "data": {"email": "bind@example.com"}}, calls)
        self.assertIn({"email": "bind@example.com"}, calls)

    def test_resolve_consent_callback_direct_clicks_authorize_button_formaction(self):
        consent_url = f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc"
        callback_url = "http://localhost:1455/auth/callback?code=cb123&state=abc"
        consent_html = '''
        <html><body>
          <form action="/fallback-consent" method="post">
            <input type="hidden" name="state" value="abc">
            <button type="submit" formaction="/oauth/authorize?state=abc">Authorize</button>
          </form>
        </body></html>
        '''

        class FakeSession:
            def __init__(self):
                self.calls = []

            def request(self, method, url, **kwargs):
                self.calls.append((method.upper(), url, kwargs))
                if method.upper() == "GET" and url == consent_url:
                    return SimpleNamespace(url=url, text=consent_html, headers={}, status_code=200, json=lambda: {})
                if method.upper() == "POST" and url == f"{register_core.auth_base}/oauth/authorize?state=abc":
                    return SimpleNamespace(url=url, text="", headers={"Location": callback_url}, status_code=302, json=lambda: {})
                raise AssertionError(f"unexpected call: {method} {url}")

            def post(self, url, **kwargs):
                return self.request("POST", url, **kwargs)

            def get(self, url, **kwargs):
                return self.request("GET", url, **kwargs)

        class DummyRegistrar:
            def __init__(self):
                self.session = FakeSession()

            def _build_accounts_headers(self, *_args, **_kwargs):
                return {"referer": consent_url}

        registrar = DummyRegistrar()
        resolved, summary = reauth._resolve_consent_callback_direct(registrar, consent_url, "abc")

        self.assertEqual(resolved, callback_url)
        self.assertTrue(any(call[0] == "POST" and call[1] == f"{register_core.auth_base}/oauth/authorize?state=abc" for call in registrar.session.calls))
        self.assertGreaterEqual(len(summary.get("attempts") or []), 1)

    def test_load_continue_page_extracts_embedded_continue_and_callback(self):
        response = self._response(
            url=f"{register_core.auth_base}/about-you?state=abc",
            text='window.__NEXT_DATA__ = {"callback":"http://localhost:1455/auth/callback?code=cb123&state=abc"}',
        )
        body = {
            "page": {"type": "about_you"},
            "continue_url": "/sign-in-with-chatgpt/codex/consent?state=abc",
        }
        registrar = SimpleNamespace(session=object())
        with patch.object(flow, "request_with_local_retry", return_value=(response, "")), patch.object(flow, "_response_json", return_value=body):
            result = flow._load_continue_page(registrar, f"{register_core.auth_base}/about-you?state=abc")

        self.assertEqual(
            result["continue_url"],
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
        )
        self.assertEqual(result["callback_url"], "http://localhost:1455/auth/callback?code=cb123&state=abc")
        self.assertEqual(result["page_type"], "about_you")

    def test_resolve_oauth_callback_follows_embedded_continue_then_uses_consent_fallback(self):
        about_you = self._response(url=f"{register_core.auth_base}/about-you?state=abc")
        consent = self._response(url=f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc")
        registrar = SimpleNamespace(session=object(), device_id="dev-1")

        def fake_request(_session, _method, url, **_kwargs):
            if "about-you" in url:
                return about_you, ""
            if "authorize/resume" in url or "consent" in url:
                return consent, ""
            raise AssertionError(f"unexpected url: {url}")

        def fake_json(resp):
            if resp is about_you:
                return {
                    "page": {"type": "about_you"},
                    "continue_url": "/sign-in-with-chatgpt/codex/consent?state=abc",
                }
            return {"page": {"type": "consent"}}

        with patch.object(flow, "request_with_local_retry", side_effect=fake_request), patch.object(flow, "_response_json", side_effect=fake_json), patch.object(
            flow,
            "extract_oauth_callback_params_from_consent_session",
            side_effect=lambda _session, consent_url, _device_id: {"code": "xyz", "state": "abc"} if "consent" in consent_url else None,
        ):
            callback_url = flow._resolve_oauth_callback(registrar, f"{register_core.auth_base}/about-you?state=abc", "abc")

        self.assertEqual(callback_url, "http://localhost:1455/auth/callback?code=xyz&state=abc")


class MailProviderFallbackTests(unittest.TestCase):
    def test_create_mailbox_tries_next_provider_after_failure(self):
        calls = []

        def failing_icloud(*_args, **_kwargs):
            calls.append("icloud")
            raise RuntimeError("temporary provider failure")

        def fallback_cloudflare(*_args, **_kwargs):
            calls.append("cloudflare")
            return {"provider": "cloudflare-temp-email", "email": "demo@example.com"}

        config = {
            "providers": [
                {"type": "icloud"},
                {"type": "cloudflare-temp-email", "base_url": "https://mail.example.test", "admin_auth": "key", "domain": "example.com"},
            ]
        }
        with patch.object(mail_provider, "_create_icloud_mailbox", side_effect=failing_icloud), patch.object(
            mail_provider,
            "_create_cloudflare_temp_email_mailbox",
            side_effect=fallback_cloudflare,
        ):
            mailbox = mail_provider.create_mailbox(config, username="demo")

        self.assertEqual(mailbox["email"], "demo@example.com")
        self.assertEqual(calls, ["icloud", "cloudflare"])

    def test_create_mailbox_switches_to_cloudflare_when_icloud_hme_is_limited(self):
        calls = []

        def limited_icloud(*_args, **_kwargs):
            calls.append("icloud")
            raise RuntimeError("iCloud HME 保留别名失败: {'errorCode': '-41015', 'errorMessage': 'You have reached the limit of addresses you can create right now.'}")

        def fallback_cloudflare(*_args, **_kwargs):
            calls.append("cloudflare")
            return {
                "provider": "cloudflare-temp-email",
                "email": "demo@cf.test",
                "base_url": "https://mail.cf.test",
                "admin_auth": "admin-secret",
                "domain": "cf.test",
            }

        config = {
            "providers": [
                {"type": "icloud", "cookies_json": "{\"token\":\"value\"}", "host": "icloud.com"},
                {
                    "type": "cloudflare-temp-email",
                    "base_url": "https://mail.cf.test",
                    "admin_auth": "admin-secret",
                    "domain": "cf.test",
                },
            ]
        }
        output = io.StringIO()
        with redirect_stdout(output), \
             patch.object(mail_provider, "_create_icloud_mailbox", side_effect=limited_icloud), \
             patch.object(mail_provider, "_create_cloudflare_temp_email_mailbox", side_effect=fallback_cloudflare):
            mailbox = mail_provider.create_mailbox(config, username="demo")

        self.assertEqual(mailbox["provider"], "cloudflare-temp-email")
        self.assertEqual(mailbox["email"], "demo@cf.test")
        self.assertEqual(calls, ["icloud", "cloudflare"])
        self.assertIn("阶段：iCloud HME 创建别名被限流，切换 cloudflare-temp-email 邮箱", output.getvalue())

    def test_create_icloud_mailbox_uses_configured_alias(self):
        mailbox = mail_provider.create_mailbox(
            {"providers": [{"type": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"}]},
            username="demo",
        )

        self.assertEqual(mailbox["provider"], "icloud")
        self.assertEqual(mailbox["email"], "alias@icloud.com")
        self.assertEqual(mailbox["alias_source"], "configured")
        self.assertEqual(mailbox["imap_user"], "owner@icloud.com")
        self.assertEqual(mailbox["imap_password"], "app-pass")

    def test_create_icloud_mailbox_can_create_hide_my_email_alias(self):
        class DummyHME:
            def __init__(self, cookies, **kwargs):
                self.cookies = cookies
                self.kwargs = kwargs

            def create_alias(self, *, label=""):
                self.label = label
                return "hme@example.icloud.com"

        with patch.object(mail_provider, "_ICloudHMEClient", DummyHME):
            mailbox = mail_provider.create_mailbox(
                {"providers": [{"type": "icloud", "cookies_json": "{\"token\":\"value\"}", "host": "icloud.com", "hme_label": "RegPilot Test"}]},
                username="demo",
            )

        self.assertEqual(mailbox["provider"], "icloud")
        self.assertEqual(mailbox["email"], "hme@example.icloud.com")
        self.assertEqual(mailbox["alias_source"], "hide-my-email")

    def test_create_icloud_mailbox_accepts_browser_cookie_header(self):
        captured = {}

        class DummyHME:
            def __init__(self, cookies, **kwargs):
                captured["cookies"] = cookies

            def create_alias(self, *, label=""):
                return "hme@example.icloud.com"

        cookie_header = 'X-APPLE-WEBAUTH-USER="v=1:s=1"; X-APPLE-WEBAUTH-TOKEN="token-value"; X-Apple-GCBD-Cookie=1'
        with patch.object(mail_provider, "_ICloudHMEClient", DummyHME):
            mailbox = mail_provider.create_mailbox(
                {"providers": [{"type": "icloud", "cookies_json": cookie_header, "host": "icloud.com"}]},
                username="demo",
            )

        self.assertEqual(mailbox["email"], "hme@example.icloud.com")
        self.assertEqual(captured["cookies"]["X-APPLE-WEBAUTH-USER"], "v=1:s=1")
        self.assertEqual(captured["cookies"]["X-APPLE-WEBAUTH-TOKEN"], "token-value")
        self.assertEqual(captured["cookies"]["X-Apple-GCBD-Cookie"], "1")

    def test_wait_icloud_code_uses_imap_provider_config(self):
        mailbox = {"provider": "icloud", "email": "alias@icloud.com"}
        config = {
            "providers": [
                {
                    "type": "icloud",
                    "imap_user": "owner@icloud.com",
                    "imap_password": "app-pass",
                }
            ],
            "wait_timeout": 5,
            "wait_interval": 1,
            "request_timeout": 5,
        }

        with patch.object(mail_provider, "_wait_icloud_imap_code", return_value="123456") as mock_wait:
            code = mail_provider.wait_for_code(config, mailbox)

        self.assertEqual(code, "123456")
        self.assertEqual(mock_wait.call_args.kwargs["imap_user"], "owner@icloud.com")
        self.assertEqual(mock_wait.call_args.kwargs["imap_password"], "app-pass")

    def test_create_hotmail_api_mailbox_claims_microsoft_pool_account(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(microsoft_mail_pool, "POOL_PATH", Path(tmpdir) / "pool.json"):
            microsoft_mail_pool.upsert_account(
                {
                    "email": "base@hotmail.com",
                    "password": "mail-pass",
                    "client_id": "client-1",
                    "refresh_token": "refresh-1",
                    "status": "authorized",
                }
            )

            mailbox = mail_provider.create_mailbox(
                {
                    "providers": [
                        {
                            "type": "hotmail-api",
                            "base_url": "http://mail-helper.test",
                            "alias_enabled": True,
                            "alias_max_per_account": 5,
                        }
                    ]
                }
            )

        self.assertEqual(mailbox["provider"], "hotmail-api")
        self.assertEqual(mailbox["email"], "base+rp1@hotmail.com")
        self.assertEqual(mailbox["base_email"], "base@hotmail.com")
        self.assertEqual(mailbox["client_id"], "client-1")
        self.assertEqual(mailbox["refresh_token"], "refresh-1")

    def test_wait_hotmail_api_code_calls_helper_and_records_code(self):
        mailbox = {
            "provider": "hotmail-api",
            "email": "base+rp1@hotmail.com",
            "base_email": "base@hotmail.com",
            "client_id": "client-1",
            "refresh_token": "refresh-1",
            "base_url": "http://mail-helper.test",
            "_code_after_ts": 123000,
        }
        captured = {}

        def fake_request(_method, url, **kwargs):
            captured["url"] = url
            captured["json"] = kwargs.get("json")
            return SimpleNamespace(
                status_code=200,
                text="",
                json=lambda: {
                    "ok": True,
                    "code": "654321",
                    "nextRefreshToken": "refresh-2",
                    "message": {
                        "id": "msg-1",
                        "subject": "OpenAI verification code",
                        "bodyPreview": "Code 654321",
                        "receivedTimestamp": 124000,
                    },
                },
            )

        with patch.object(mail_provider, "_request", side_effect=fake_request):
            code = mail_provider.wait_for_code({"wait_timeout": 1, "wait_interval": 1, "request_timeout": 5}, mailbox)

        self.assertEqual(code, "654321")
        self.assertEqual(captured["url"], "http://mail-helper.test/code")
        self.assertEqual(captured["json"]["email"], "base@hotmail.com")
        self.assertEqual(captured["json"]["filterAfterTimestamp"], 123000)
        self.assertEqual(mailbox["refresh_token"], "refresh-2")
        self.assertEqual(mailbox["_last_code_meta"]["provider"], "hotmail-api")

    def test_wait_icloud_code_falls_back_to_cookies_after_imap_miss(self):
        mailbox = {"provider": "icloud", "email": "alias@icloud.com"}
        config = {
            "providers": [
                {
                    "type": "icloud",
                    "imap_user": "owner@icloud.com",
                    "imap_password": "app-pass",
                    "cookies_json": '{"X-APPLE-WEBAUTH-TOKEN":"token"}',
                    "host": "icloud.com",
                }
            ],
            "wait_timeout": 5,
            "wait_interval": 1,
            "request_timeout": 5,
        }

        class DummyHME:
            def __init__(self, cookies, **kwargs):
                self.cookies = cookies

            def poll_mail_for_code(self, target_email, **kwargs):
                self.target_email = target_email
                return "959281"

        with patch.object(mail_provider, "_wait_icloud_imap_code", return_value=None), \
             patch.object(mail_provider, "_ICloudHMEClient", DummyHME):
            code = mail_provider.wait_for_code(config, mailbox)

        self.assertEqual(code, "959281")

    def test_wait_icloud_imap_code_uses_body_peek_when_rfc822_is_empty(self):
        mailbox = {"provider": "icloud", "email": "alias@icloud.com"}
        raw_message = (
            "Date: Sat, 30 May 2026 18:59:00 +0800\r\n"
            "From: OpenAI <noreply@tm.openai.com>\r\n"
            "To: alias@icloud.com\r\n"
            "Subject: OpenAI verification code\r\n"
            "\r\n"
            "Your temporary verification code is 959281.\r\n"
        ).encode("utf-8")

        class FakeIMAP:
            def __init__(self, *args, **kwargs):
                self.fetch_specs = []

            def login(self, *_args):
                return "OK", [b"logged in"]

            def select(self, *_args):
                return "OK", [b"1"]

            def search(self, *_args):
                return "OK", [b"1"]

            def fetch(self, msg_id, spec):
                self.fetch_specs.append(spec)
                if spec == "(INTERNALDATE RFC822)":
                    return "OK", [b"1 ()"]
                return "OK", [(b'1 (INTERNALDATE "01-Jun-2026 02:25:01 +0800" BODY[] {128}', raw_message), b")"]

            def logout(self):
                return "OK", []

        fake = FakeIMAP()
        with patch.object(mail_provider.imaplib, "IMAP4_SSL", return_value=fake):
            code = mail_provider._wait_icloud_imap_code(
                "alias@icloud.com",
                imap_user="owner@icloud.com",
                imap_password="app-pass",
                timeout=2,
                interval=1,
                request_timeout=5,
                after_ts_ms=0,
                excluded=set(),
                mailbox=mailbox,
            )

        self.assertEqual(code, "959281")
        self.assertIn("(INTERNALDATE RFC822)", fake.fetch_specs)
        self.assertIn("(INTERNALDATE BODY.PEEK[])", fake.fetch_specs)
        self.assertGreater(mailbox["_last_code_meta"]["received_at_ms"], 0)

    def test_to_timestamp_ms_parses_rfc2822_date_with_comment_timezone(self):
        value = mail_provider._to_timestamp_ms("Sun, 31 May 2026 18:26:07 -0700 (PDT)")

        self.assertGreater(value, 0)

    def test_wait_icloud_imap_code_ignores_other_hme_alias_codes(self):
        mailbox = {"provider": "icloud", "email": "nicer_feeders2k@icloud.com"}
        correct_message = (
            "Date: Sat, 30 May 2026 18:58:00 +0800\r\n"
            "From: OpenAI <noreply@tm.openai.com>\r\n"
            "To: nicer_feeders2k@icloud.com\r\n"
            "Subject: OpenAI verification code\r\n"
            "\r\n"
            "Your temporary verification code is 959281.\r\n"
        ).encode("utf-8")
        wrong_alias_message = (
            "Date: Sat, 30 May 2026 18:59:00 +0800\r\n"
            "From: OpenAI <noreply@tm.openai.com>\r\n"
            "To: 69.lost-bred@icloud.com\r\n"
            "Subject: OpenAI verification code\r\n"
            "\r\n"
            "Your temporary verification code is 110799.\r\n"
        ).encode("utf-8")

        class FakeIMAP:
            def login(self, *_args):
                return "OK", [b"logged in"]

            def select(self, *_args):
                return "OK", [b"2"]

            def search(self, *_args):
                return "OK", [b"1 2"]

            def fetch(self, msg_id, _spec):
                messages = {b"1": correct_message, b"2": wrong_alias_message}
                return "OK", [(b"1 (RFC822 {128}", messages[msg_id]), b")"]

            def logout(self):
                return "OK", []

        with patch.object(mail_provider.imaplib, "IMAP4_SSL", return_value=FakeIMAP()):
            code = mail_provider._wait_icloud_imap_code(
                "nicer_feeders2k@icloud.com",
                imap_user="owner@icloud.com",
                imap_password="app-pass",
                timeout=2,
                interval=1,
                request_timeout=5,
                after_ts_ms=0,
                excluded=set(),
                mailbox=mailbox,
            )

        self.assertEqual(code, "959281")
        self.assertEqual(mailbox["_last_code_meta"]["code"], "959281")
        self.assertIn("nicer_feeders2k@icloud.com", mailbox["_last_code_meta"]["preview"])
        self.assertNotIn("69.lost-bred@icloud.com", mailbox["_last_code_meta"]["preview"])

    def test_provider_config_for_mailbox_only_matches_icloud_alias_for_icloud(self):
        config = {"providers": [{"type": "icloud-hme", "imap_user": "owner@icloud.com"}]}
        mailbox = {"provider": "cloudflare-temp-email", "email": "user@example.com"}

        self.assertEqual(mail_provider._provider_config_for_mailbox(config, mailbox), {})


class RegisterCoreCallbackFallbackTests(unittest.TestCase):
    def _response(self, *, url: str, text: str = "", headers: dict | None = None, status_code: int = 200):
        return SimpleNamespace(url=url, text=text, headers=headers or {}, status_code=status_code)

    def test_registered_chatgpt_callback_is_followed_before_cpa_oauth(self):
        calls = []

        class DummyRegistrar:
            def __init__(self):
                self.session = object()

            def start_authorize(self, email, authorize_url="", screen_hint=""):
                calls.append(("start_authorize", email, authorize_url, screen_hint))
                return {
                    "status": 200,
                    "final_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=cpa-state",
                    "state": "cpa-state",
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                raise AssertionError("CPA callback path should not use local token exchange")

        def fake_request(_session, method, url, **_kwargs):
            calls.append(("follow_callback", method, url))
            return SimpleNamespace(url="https://chatgpt.com/", status_code=200, headers={}, text=""), ""

        cfg = register_core.RegisterConfig(
            codex2api_url="http://127.0.0.1:8317",
            codex2api_admin_key="key",
            codex2api_auto_import=True,
        )
        with patch.object(register_core, "request_with_local_retry", side_effect=fake_request), \
             patch("regpilot.reauthorize._start_cpa_oauth", return_value={"authorize_url": "https://auth.openai.com/oauth/authorize?state=cpa-state", "state": "cpa-state"}), \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=cpa-state"), \
             patch("regpilot.reauthorize._submit_callback_to_cpa", return_value={"ok": True, "message": "ok"}):
            result = register_core._exchange_registered_account_tokens(
                config=cfg,
                registrar=DummyRegistrar(),
                email="user@example.com",
                password="pw",
                mailbox={},
                code_verifier="",
                callback_url="https://chatgpt.com/api/auth/callback/openai?code=chatgpt-code&state=chatgpt-state",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.callback_url, "http://localhost:1455/auth/callback?code=cb&state=cpa-state")
        self.assertEqual(calls[0][0], "follow_callback")
        self.assertEqual(calls[1][0], "start_authorize")

    def test_registered_phone_signup_cpa_oauth_submits_password_page(self):
        calls = []

        class DummyRegistrar:
            def __init__(self):
                self.session = object()
                self.last_authorize = {}

            def start_authorize(self, email, authorize_url="", screen_hint=""):
                calls.append(("start_authorize", email, authorize_url, screen_hint))
                self.last_authorize = {"state": "cpa-state", "final_url": "https://auth.openai.com/log-in/password"}
                return {
                    "status": 200,
                    "final_url": "https://auth.openai.com/log-in/password",
                    "state": "cpa-state",
                }

            def establish_signup_session(self):
                calls.append(("establish_signup_session",))
                return {"ok": True, "flow_kind": "login"}

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                raise AssertionError("CPA callback path should not use local token exchange")

        def fake_request(_session, method, url, **_kwargs):
            calls.append(("follow_callback", method, url))
            return SimpleNamespace(url="https://chatgpt.com/", status_code=200, headers={}, text=""), ""

        def fake_password_login(_registrar, email, password):
            calls.append(("password_login", email, password))
            return {"ok": True, "status": 200, "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=cpa-state"}}

        cfg = register_core.RegisterConfig(
            codex2api_url="http://127.0.0.1:8317",
            codex2api_admin_key="key",
            codex2api_auto_import=True,
        )
        with patch.object(register_core, "request_with_local_retry", side_effect=fake_request), \
             patch("regpilot.reauthorize._start_cpa_oauth", return_value={"authorize_url": "https://auth.openai.com/oauth/authorize?state=cpa-state", "state": "cpa-state"}), \
             patch("regpilot.reauthorize._attempt_password_login", side_effect=fake_password_login), \
             patch("regpilot.reauthorize._resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=cpa-state"), \
             patch("regpilot.reauthorize._step_requires_phone_verification", return_value=False), \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value=""), \
             patch("regpilot.reauthorize._submit_callback_to_cpa", return_value={"ok": True, "message": "ok"}):
            result = register_core._exchange_registered_account_tokens(
                config=cfg,
                registrar=DummyRegistrar(),
                email="+56994920922",
                password="pw",
                mailbox={},
                code_verifier="",
                callback_url="https://chatgpt.com/api/auth/callback/openai?code=chatgpt-code&state=chatgpt-state",
            )

        self.assertTrue(result.ok)
        self.assertIn(("establish_signup_session",), calls)
        self.assertIn(("password_login", "+56994920922", "pw"), calls)
        self.assertEqual(result.callback_url, "http://localhost:1455/auth/callback?code=cb&state=cpa-state")

    def test_registration_state_treats_login_password_as_password_page(self):
        state = register_core._registration_state_from_info(
            {"final_url": "https://auth.openai.com/log-in/password", "json": {}, "text": ""}
        )

        self.assertEqual(state["kind"], "password")

    def test_registration_state_treats_add_email_as_add_email_page(self):
        state = register_core._registration_state_from_info(
            {"final_url": "https://auth.openai.com/add-email", "json": {}, "text": ""}
        )

        self.assertEqual(state["kind"], "add_email")

    def test_registered_phone_signup_cpa_oauth_handles_add_email_page(self):
        class DummyRegistrar:
            def __init__(self):
                self.session = object()
                self.last_authorize = {}

            def start_authorize(self, email, authorize_url="", screen_hint=""):
                self.last_authorize = {"state": "cpa-state", "final_url": "https://auth.openai.com/add-email"}
                return {
                    "status": 200,
                    "final_url": "https://auth.openai.com/add-email",
                    "state": "cpa-state",
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                raise AssertionError("CPA callback path should not use local token exchange")

        cfg = register_core.RegisterConfig(
            codex2api_url="http://127.0.0.1:8317",
            codex2api_admin_key="key",
            codex2api_auto_import=True,
        )
        cfg.mail.providers = [{"type": "cloudflare-temp-email", "admin_auth": "mail-key", "base_url": "https://mail.example.test", "domain": "example.test"}]
        cfg.mail.wait_timeout = 9
        mailbox = {}
        with patch("regpilot.reauthorize._start_cpa_oauth", return_value={"authorize_url": "https://auth.openai.com/oauth/authorize?state=cpa-state", "state": "cpa-state"}), \
             patch("regpilot.oauth_token_flow._continue_with_optional_add_email", return_value=("http://localhost:1455/auth/callback?code=cb&state=cpa-state", "bind@example.com")) as mock_add_email, \
             patch("regpilot.reauthorize._step_requires_phone_verification", return_value=False), \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value=""), \
             patch("regpilot.reauthorize._submit_callback_to_cpa", return_value={"ok": True, "message": "ok"}):
            result = register_core._exchange_registered_account_tokens(
                config=cfg,
                registrar=DummyRegistrar(),
                email="+56994920922",
                password="pw",
                mailbox=mailbox,
                code_verifier="",
                callback_url="https://chatgpt.com/api/auth/callback/openai?code=chatgpt-code&state=chatgpt-state",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.callback_url, "http://localhost:1455/auth/callback?code=cb&state=cpa-state")
        self.assertEqual(mailbox["bind_email"], "bind@example.com")
        self.assertEqual(mock_add_email.call_args.kwargs["continue_url"], "https://auth.openai.com/add-email")
        self.assertEqual(mock_add_email.call_args.kwargs["bind_mail_config"]["providers"][0]["admin_auth"], "mail-key")

    def test_registered_phone_signup_reopens_oauth_after_add_email_without_callback(self):
        start_urls = []

        class DummyRegistrar:
            def __init__(self):
                self.session = object()
                self.last_authorize = {}

            def start_authorize(self, email, authorize_url="", screen_hint=""):
                start_urls.append(authorize_url)
                final_url = "https://auth.openai.com/add-email" if len(start_urls) == 1 else "http://localhost:1455/auth/callback?code=cb&state=cpa-state"
                self.last_authorize = {"state": "cpa-state", "final_url": final_url}
                return {
                    "status": 200,
                    "final_url": final_url,
                    "state": "cpa-state",
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                raise AssertionError("CPA callback path should not use local token exchange")

        cfg = register_core.RegisterConfig(
            codex2api_url="http://127.0.0.1:8317",
            codex2api_admin_key="key",
            codex2api_auto_import=True,
        )
        mailbox = {}
        with patch("regpilot.reauthorize._start_cpa_oauth", return_value={"authorize_url": "https://auth.openai.com/oauth/authorize?state=cpa-state", "state": "cpa-state"}), \
             patch("regpilot.oauth_token_flow._continue_with_optional_add_email", return_value=("https://auth.openai.com/email-verification", "bind@example.com")) as mock_add_email, \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value=""), \
             patch("regpilot.reauthorize._resolve_callback_step", side_effect=["", "http://localhost:1455/auth/callback?code=cb&state=cpa-state"]), \
             patch("regpilot.reauthorize._step_requires_phone_verification", return_value=False), \
             patch("regpilot.reauthorize._submit_callback_to_cpa", return_value={"ok": True, "message": "ok"}):
            result = register_core._exchange_registered_account_tokens(
                config=cfg,
                registrar=DummyRegistrar(),
                email="+56994920922",
                password="pw",
                mailbox=mailbox,
                code_verifier="",
                callback_url="https://chatgpt.com/api/auth/callback/openai?code=chatgpt-code&state=chatgpt-state",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.callback_url, "http://localhost:1455/auth/callback?code=cb&state=cpa-state")
        self.assertEqual(len(start_urls), 2)
        self.assertEqual(mock_add_email.call_count, 1)

    def test_registered_phone_signup_retries_add_email_when_reopen_still_requires_binding(self):
        start_urls = []

        class DummyRegistrar:
            def __init__(self):
                self.session = object()
                self.last_authorize = {}

            def start_authorize(self, email, authorize_url="", screen_hint=""):
                start_urls.append(authorize_url)
                self.last_authorize = {"state": "cpa-state", "final_url": "https://auth.openai.com/add-email"}
                return {
                    "status": 200,
                    "final_url": "https://auth.openai.com/add-email",
                    "state": "cpa-state",
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                raise AssertionError("CPA callback path should not use local token exchange")

        cfg = register_core.RegisterConfig(
            codex2api_url="http://127.0.0.1:8317",
            codex2api_admin_key="key",
            codex2api_auto_import=True,
        )
        mailbox = {}
        callback_url = "http://localhost:1455/auth/callback?code=cb&state=cpa-state"
        with patch("regpilot.reauthorize._start_cpa_oauth", return_value={"authorize_url": "https://auth.openai.com/oauth/authorize?state=cpa-state", "state": "cpa-state"}), \
             patch("regpilot.oauth_token_flow._continue_with_optional_add_email", side_effect=[("https://auth.openai.com/email-verification", "bind@example.com"), (callback_url, "bind@example.com")]) as mock_add_email, \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value=""), \
             patch("regpilot.reauthorize._resolve_callback_step", return_value=""), \
             patch("regpilot.reauthorize._step_requires_phone_verification", return_value=False), \
             patch("regpilot.reauthorize._submit_callback_to_cpa", return_value={"ok": True, "message": "ok"}):
            result = register_core._exchange_registered_account_tokens(
                config=cfg,
                registrar=DummyRegistrar(),
                email="+56994920922",
                password="pw",
                mailbox=mailbox,
                code_verifier="",
                callback_url="https://chatgpt.com/api/auth/callback/openai?code=chatgpt-code&state=chatgpt-state",
            )

        self.assertTrue(result.ok)
        self.assertEqual(result.callback_url, callback_url)
        self.assertEqual(mailbox["bind_email"], "bind@example.com")
        self.assertEqual(len(start_urls), 2)
        self.assertEqual(mock_add_email.call_count, 2)

    def test_prepare_bind_mailbox_uses_mail_provider_for_explicit_icloud_alias(self):
        mail_config = {
            "providers": [
                {
                    "type": "icloud",
                    "imap_user": "owner@icloud.com",
                    "imap_password": "app-pass",
                    "host": "icloud.com.cn",
                }
            ]
        }

        email, mailbox = flow._prepare_bind_mailbox(mail_config, "alias@icloud.com")

        self.assertEqual(email, "alias@icloud.com")
        self.assertIsNotNone(mailbox)
        self.assertEqual(mailbox["provider"], "icloud")
        self.assertEqual(mailbox["email"], "alias@icloud.com")
        self.assertEqual(mailbox["bind_email"], "alias@icloud.com")
        self.assertEqual(mailbox["imap_user"], "owner@icloud.com")
        self.assertEqual(mailbox["imap_password"], "app-pass")
        self.assertEqual(mailbox["host"], "icloud.com.cn")

    def test_extract_oauth_callback_params_from_consent_session_reads_callback_from_text(self):
        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self, response):
                self.response = response
                self.cookies = FakeCookies()

            def get(self, *_args, **_kwargs):
                return self.response

        response = self._response(
            url=f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
            text='{"redirect":"https:\\/\\/platform.openai.com\\/auth\\/callback?code=fromtext&state=abc"}',
        )
        session = FakeSession(response)

        result = register_core.extract_oauth_callback_params_from_consent_session(
            session,
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
            "dev-1",
        )

        self.assertEqual(result, {"code": "fromtext", "state": "abc", "scope": ""})


    def test_extract_oauth_callback_params_from_response_reads_json_callback(self):
        class FakeResponse:
            url = f"{register_core.auth_base}/api/accounts/workspace/select"
            headers = {}
            text = ""

            def json(self):
                return {"continue_url": "http://localhost:1455/auth/callback?code=jsoncode&state=abc"}

        result = register_core._extract_oauth_callback_params_from_response(FakeResponse())

        self.assertEqual(result, {"code": "jsoncode", "state": "abc", "scope": ""})

    def test_extract_oauth_callback_params_from_consent_session_submits_consent_form_before_workspace_select(self):
        callback = "http://localhost:1455/auth/callback?code=formcode&state=abc"
        consent_html = '''
        <form action="/oauth/authorize?state=abc" method="post">
          <input type="hidden" name="state" value="abc">
          <input type="hidden" name="workspace_id" value="workspace-1">
          <button type="submit" name="action" value="approve">Continue</button>
        </form>
        '''

        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text=consent_html, headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("data") or kwargs.get("json")))
                if url.endswith("/api/accounts/workspace/select"):
                    raise AssertionError("workspace_select should not run before the consent form")
                return SimpleNamespace(url=url, text="", headers={"Location": callback}, status_code=302, json=lambda: {})

        session = FakeSession()
        result = register_core.extract_oauth_callback_params_from_consent_session(
            session,
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent",
            "dev-1",
            state="abc",
        )

        self.assertEqual(result, {"code": "formcode", "state": "abc", "scope": ""})
        self.assertTrue(any(call[0] == "POST" and call[1] == f"{register_core.auth_base}/oauth/authorize?state=abc" for call in session.calls))

    def test_extract_oauth_callback_params_from_consent_session_reads_workspace_select_json_callback(self):
        class FakeCookies:
            def get(self, *_args, **_kwargs):
                payload = base64.urlsafe_b64encode(
                    json.dumps({"workspaces": [{"id": "workspace-1"}]}).encode("utf-8")
                ).decode("ascii").rstrip("=")
                return payload + ".sig"

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text="", headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("json")))
                if "/sign-in-with-chatgpt/codex/consent.data" in url or "/sign-in-with-chatgpt/codex/consent" in url:
                    return SimpleNamespace(url=url, text="", headers={}, status_code=204, json=lambda: {})
                return SimpleNamespace(
                    url=url,
                    text="",
                    headers={},
                    status_code=200,
                    json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=wsjson&state=abc"},
                )

        session = FakeSession()
        result = register_core.extract_oauth_callback_params_from_consent_session(
            session,
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
            "dev-1",
        )

        self.assertEqual(result, {"code": "wsjson", "state": "abc", "scope": ""})
        self.assertTrue(any(call[0] == "POST" and call[1].endswith("/api/accounts/workspace/select") for call in session.calls))
        self.assertTrue(all((call[2] or {}).get("state") is None for call in session.calls if call[0] == "POST"))

    def test_extract_oauth_callback_params_from_consent_session_does_not_send_state_to_workspace_select(self):
        class FakeCookies:
            def get(self, *_args, **_kwargs):
                payload = base64.urlsafe_b64encode(
                    json.dumps({"workspaces": [{"id": "workspace-1"}]}).encode("utf-8")
                ).decode("ascii").rstrip("=")
                return payload + ".sig"

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text="", headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("json")))
                if "/sign-in-with-chatgpt/codex/consent.data" in url or "/sign-in-with-chatgpt/codex/consent" in url:
                    return SimpleNamespace(url=url, text="", headers={}, status_code=204, json=lambda: {})
                return SimpleNamespace(
                    url=url,
                    text="",
                    headers={},
                    status_code=200,
                    json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=nostate&state=abc"},
                )

        session = FakeSession()
        result = register_core.extract_oauth_callback_params_from_consent_session(
            session,
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent",
            "dev-1",
            state="abc",
        )

        self.assertEqual(result, {"code": "nostate", "state": "abc", "scope": ""})
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/workspace/select", {"workspace_id": "workspace-1"}), session.calls)

    def test_extract_oauth_callback_params_from_consent_session_reads_workspace_id_from_consent_html(self):
        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                text = ""
                if "/sign-in-with-chatgpt/codex/consent" in url and "consent.data" not in url:
                    text = '<form><input type="hidden" name="workspace_id" value="workspace-from-html"><button>Continue</button></form>'
                return SimpleNamespace(url=url, text=text, headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("json")))
                if "/sign-in-with-chatgpt/codex/consent.data" in url or "/sign-in-with-chatgpt/codex/consent" in url:
                    return SimpleNamespace(url=url, text="", headers={}, status_code=204, json=lambda: {})
                return SimpleNamespace(
                    url=url,
                    text="",
                    headers={},
                    status_code=200,
                    json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=htmlws&state=abc"},
                )

        session = FakeSession()
        result = register_core.extract_oauth_callback_params_from_consent_session(
            session,
            f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
            "dev-1",
        )

        self.assertEqual(result, {"code": "htmlws", "state": "abc", "scope": ""})
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/workspace/select", {"workspace_id": "workspace-from-html"}), session.calls)

    def test_extract_oauth_callback_params_from_consent_session_submits_remix_data_before_workspace_select(self):
        callback = "http://localhost:1455/auth/callback?code=remixdata&state=abc"
        consent_html = '{"workspace_id":"workspace-from-remix","route":"SIGN_IN_WITH_CHATGPT_CODEX_CONSENT"}'

        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text=consent_html, headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                body = kwargs.get("data") or kwargs.get("json")
                self.calls.append(("POST", url, body))
                if url.endswith("/api/accounts/workspace/select"):
                    raise AssertionError("workspace_select should not run before consent data submit")
                if "/sign-in-with-chatgpt/codex/consent.data" in url:
                    return SimpleNamespace(url=url, text="", headers={"Location": callback}, status_code=302, json=lambda: {})
                return SimpleNamespace(url=url, text="", headers={}, status_code=500, json=lambda: {})

        session = FakeSession()
        with patch.object(register_core, "build_sentinel_token", return_value="sentinel"):
            result = register_core.extract_oauth_callback_params_from_consent_session(
                session,
                f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
                "dev-1",
                state="abc",
            )

        self.assertEqual(result, {"code": "remixdata", "state": "abc", "scope": ""})
        self.assertTrue(any(call[0] == "POST" and "/sign-in-with-chatgpt/codex/consent.data" in call[1] for call in session.calls))

    def test_extract_oauth_callback_params_from_consent_session_uses_client_action_workspace_select(self):
        callback = "http://localhost:1455/auth/callback?code=clientaction&state=abc"
        consent_html = '''
        <form method="POST">
          <input type="hidden" name="workspace_id" value="workspace-client-action">
          <button type="submit">Continue</button>
        </form>
        '''

        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text=consent_html, headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("data") or kwargs.get("json")))
                if url.endswith("/api/accounts/workspace/select"):
                    return SimpleNamespace(url=url, text="", headers={"Location": callback}, status_code=302, json=lambda: {})
                raise AssertionError(f"unexpected form post: {url}")

        session = FakeSession()
        with patch.object(register_core, "build_sentinel_token", return_value="sentinel"):
            result = register_core.extract_oauth_callback_params_from_consent_session(
                session,
                f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
                "dev-1",
                state="abc",
            )

        self.assertEqual(result, {"code": "clientaction", "state": "abc", "scope": ""})
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/workspace/select", {"workspace_id": "workspace-client-action"}), session.calls)

    def test_extract_oauth_callback_params_from_consent_session_uses_external_form_workspace_input(self):
        callback = "http://localhost:1455/auth/callback?code=externalinput&state=abc"
        consent_html = '''
        <form id="consent-form" method="POST"><button type="submit">Continue</button></form>
        <input form="consent-form" type="hidden" name="workspace_id" value="workspace-external-input">
        '''

        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text=consent_html, headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("data") or kwargs.get("json")))
                if url.endswith("/api/accounts/workspace/select"):
                    return SimpleNamespace(url=url, text="", headers={"Location": callback}, status_code=302, json=lambda: {})
                raise AssertionError(f"unexpected form post: {url}")

        session = FakeSession()
        with patch.object(register_core, "build_sentinel_token", return_value="sentinel"):
            result = register_core.extract_oauth_callback_params_from_consent_session(
                session,
                f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent?state=abc",
                "dev-1",
                state="abc",
            )

        self.assertEqual(result, {"code": "externalinput", "state": "abc", "scope": ""})
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/workspace/select", {"workspace_id": "workspace-external-input"}), session.calls)

    def test_extract_oauth_callback_params_from_consent_session_does_not_append_state_to_consent_data(self):
        class FakeCookies:
            def get(self, *_args, **_kwargs):
                return ""

        class FakeSession:
            def __init__(self):
                self.cookies = FakeCookies()
                self.calls = []

            def get(self, url, **_kwargs):
                self.calls.append(("GET", url))
                return SimpleNamespace(url=url, text="", headers={}, status_code=200, json=lambda: {})

            def post(self, url, **kwargs):
                self.calls.append(("POST", url, kwargs.get("data") or kwargs.get("json")))
                return SimpleNamespace(url=url, text="", headers={}, status_code=204, json=lambda: {})

        session = FakeSession()
        with patch.object(register_core, "build_sentinel_token", return_value="sentinel"):
            result = register_core.extract_oauth_callback_params_from_consent_session(
                session,
                f"{register_core.auth_base}/sign-in-with-chatgpt/codex/consent",
                "dev-1",
                state="abc",
            )

        self.assertIsNone(result)
        consent_data_urls = [url for method, url, *_rest in session.calls if method == "GET" and "consent.data" in url]
        self.assertTrue(consent_data_urls)
        self.assertTrue(all("state=" not in url for url in consent_data_urls))


class CpaOAuthManagementTests(unittest.TestCase):
    def test_start_cpa_oauth_reads_management_codex_auth_url(self):
        calls = []

        class FakeResponse:
            status_code = 200
            def json(self):
                return {"auth_url": "https://auth.openai.com/oauth/authorize?client_id=cpa-client&state=cpa-state&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback"}

        def fake_get(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse()

        with patch("regpilot.reauthorize.requests.get", side_effect=fake_get):
            result = reauth._start_cpa_oauth(cpa_url="https://cpa.example.com/management.html#/oauth", cpa_management_key="mgmt-key", email="u@example.com")

        self.assertEqual(result["authorize_url"].split("?")[0], "https://auth.openai.com/oauth/authorize")
        self.assertEqual(result["state"], "cpa-state")
        self.assertEqual(result["client_id"], "cpa-client")
        self.assertEqual(calls[0][0], "https://cpa.example.com/v0/management/codex-auth-url")
        self.assertEqual(calls[0][1]["headers"]["Authorization"], "Bearer mgmt-key")
        self.assertEqual(calls[0][1]["headers"]["X-Management-Key"], "mgmt-key")

    def test_submit_callback_to_cpa_posts_redirect_url(self):
        calls = []

        class FakeResponse:
            status_code = 200
            def json(self):
                return {"message": "CPA 宸查€氳繃鎺ュ彛鎻愪氦鍥炶皟"}

        def fake_post(url, **kwargs):
            calls.append((url, kwargs))
            return FakeResponse()

        callback = "http://localhost:1455/auth/callback?code=cb&state=abc"
        with patch("regpilot.reauthorize.requests.post", side_effect=fake_post):
            result = reauth._submit_callback_to_cpa(callback, cpa_url="https://cpa.example.com/management.html#/oauth", cpa_management_key="mgmt-key", expected_state="abc")

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0][0], "https://cpa.example.com/v0/management/oauth-callback")
        self.assertEqual(calls[0][1]["headers"]["Authorization"], "Bearer mgmt-key")
        self.assertEqual(calls[0][1]["headers"]["X-Management-Key"], "mgmt-key")
        self.assertEqual(calls[0][1]["json"], {"provider": "codex", "redirect_url": callback})

    def test_reauthorize_import_success_marks_account_authorized(self):
        saved_records = []

        def fake_save(result, *, source, account_id):
            self.assertEqual(source, "reauthorize")
            return {
                "id": account_id,
                "email": result.email,
                "password": result.password,
                "status": "active",
                "source": source,
                "last_auth_at": "2026-05-26 10:00:00",
                "last_sub2api_submit_at": "",
                "last_error": "",
                "callback_url": result.callback_url,
                "mailbox": result.mailbox,
            }

        def fake_upsert(record):
            saved_records.append(dict(record))
            return dict(record)

        result = register_core.RegistrationResult(ok=True, email="u@example.com", callback_url="http://localhost:1455/auth/callback?code=cb&state=abc")
        account = {"id": "acc-1", "email": "u@example.com", "password": "pw", "mailbox": {"provider": "mail"}}
        with patch.object(reauth, "save_registration_result_to_account", side_effect=fake_save), patch.object(reauth, "upsert_account", side_effect=fake_upsert):
            outcome = reauth._save_result_and_import_codex2api(account, result, source="reauthorize")

        self.assertTrue(outcome.ok)
        self.assertEqual(outcome.account["status"], "authorized")
        self.assertEqual(outcome.account["last_error"], "")
        self.assertEqual(outcome.account["last_sub2api_submit_at"], saved_records[-1]["last_sub2api_submit_at"])
        self.assertEqual(outcome.account["callback_url"], result.callback_url)

    def test_cpa_submit_success_skips_local_token_capture(self):
        saved_records = []
        account = {"id": "acc-1", "email": "u@example.com", "password": "pw", "status": "active", "mailbox": {}}
        mailbox = {"provider": "icloud"}
        debug = {}

        def fake_upsert(record):
            saved_records.append(dict(record))
            return dict(record)

        with patch.object(reauth, "upsert_account", side_effect=fake_upsert), \
             patch.object(reauth, "_exchange_local_tokens_after_cpa", side_effect=AssertionError("CPA-only flow should not fetch local tokens")):
            outcome = reauth._finalize_cpa_submit_with_optional_local_tokens(
                SimpleNamespace(),
                account,
                mailbox,
                email="u@example.com",
                password="pw",
                cpa_callback_url="http://localhost:1455/auth/callback?code=cb&state=abc",
                cpa_result={"ok": True, "message": "CPA callback submitted"},
                debug=debug,
            )

        self.assertTrue(outcome.ok)
        self.assertEqual(saved_records[-1]["status"], "authorized")
        self.assertTrue(saved_records[-1]["mailbox"]["_cpa_submit_ok"])
        self.assertEqual(debug["local_token_after_cpa"]["reason"], "cpa_only")

    def test_cpa_submitted_registration_result_is_saved_authorized(self):
        result = register_core.RegistrationResult(
            ok=True,
            email="u@example.com",
            password="pw",
            callback_url="http://localhost:1455/auth/callback?code=cb&state=abc",
            mailbox={"_cpa_submit_ok": True, "_cpa_submit_message": "CPA callback submitted"},
        )

        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            original_db = accounts_store.DB_PATH
            accounts_store.DB_PATH = Path(tmp) / "accounts.db"
            try:
                item = accounts_store.save_registration_result_to_account(result, source="phone_signup")
            finally:
                accounts_store.DB_PATH = original_db

        self.assertEqual(item["status"], "authorized")
        self.assertTrue(item["last_sub2api_submit_at"])

    def test_reauthorize_exchange_failure_marks_account_auth_failed(self):
        saved_records = []

        def fake_upsert(record):
            saved_records.append(dict(record))
            return dict(record)

        result = register_core.RegistrationResult(ok=False, email="u@example.com", error="bad_code")
        account = {"id": "acc-1", "email": "u@example.com", "password": "pw", "status": "active"}
        with patch.object(reauth, "upsert_account", side_effect=fake_upsert):
            outcome = reauth._save_result_and_import_codex2api(account, result, source="reauthorize")

        self.assertFalse(outcome.ok)
        self.assertEqual(outcome.account["status"], "auth_failed")
        self.assertEqual(outcome.account["last_error"], "bad_code")
        self.assertEqual(saved_records[-1]["status"], "auth_failed")


class PhoneFlowRuntimeTests(unittest.TestCase):
    def test_phone_signup_authorize_matches_browser_har_shape(self):
        calls = []

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return SimpleNamespace(url="https://auth.openai.com/create-account/password", status_code=302, text=""), ""

        with patch("regpilot.register_core.build_sentinel_token", return_value="sentinel"), \
             patch("regpilot.register_core.request_with_local_retry", side_effect=fake_request):
            registrar = register_core.PlatformRegistrar()
            info = registrar.start_phone_signup("+628123456789")
            registrar.close()

        self.assertEqual(info["final_url"], "https://auth.openai.com/create-account/password")
        self.assertEqual(calls[0][0], "get")
        self.assertIn("/api/accounts/authorize?", calls[0][1])
        self.assertIn("client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH", calls[0][1])
        self.assertIn("redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Fopenai", calls[0][1])
        self.assertIn("login_hint=%2B628123456789", calls[0][1])
        self.assertEqual(calls[0][2]["headers"].get("referer"), "https://chatgpt.com/")

    def test_email_signup_authorize_uses_chatgpt_signup_entry(self):
        calls = []

        def fake_request(_session, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return SimpleNamespace(url="https://auth.openai.com/create-account/password", status_code=302, text=""), ""

        with patch("regpilot.register_core.build_sentinel_token", return_value="sentinel"), \
             patch("regpilot.register_core.request_with_local_retry", side_effect=fake_request):
            registrar = register_core.PlatformRegistrar()
            info = registrar.start_email_signup("user@example.com")
            registrar.close()

        self.assertEqual(info["final_url"], "https://auth.openai.com/create-account/password")
        self.assertEqual(calls[0][0], "get")
        self.assertIn("/api/accounts/authorize?", calls[0][1])
        self.assertIn("client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH", calls[0][1])
        self.assertIn("redirect_uri=https%3A%2F%2Fchatgpt.com%2Fapi%2Fauth%2Fcallback%2Fopenai", calls[0][1])
        self.assertIn("login_hint=user%40example.com", calls[0][1])
        self.assertEqual(calls[0][2]["headers"].get("referer"), "https://chatgpt.com/")

    def test_fastapi_phone_bind_defaults_to_single_attempt_when_ui_does_not_send_toggle(self):
        saved = {
            "register": {"sms_wait_timeout": 180, "sms_wait_interval": 5},
            "hero_phone_bind": {"sms_auto_retry": False, "hero_sms_country": "151"},
        }

        with patch("regpilot.api._load_webui_config", return_value=saved):
            merged = fastapi_api._merge_task_values("hero_phone_bind", {"hero_sms_api_key": "k"})

        self.assertIs(merged["sms_auto_retry"], False)
        self.assertEqual(merged["hero_sms_country"], "151")
        self.assertEqual(merged["sms_wait_timeout"], 180)
        self.assertEqual(merged["sms_retry_count"], 3)

    def test_fastapi_phone_bind_respects_explicit_auto_retry_false(self):
        saved = {"hero_phone_bind": {"sms_auto_retry": True}}

        with patch("regpilot.api._load_webui_config", return_value=saved):
            merged = fastapi_api._merge_task_values("hero_phone_bind", {"sms_auto_retry": False})

        self.assertIs(merged["sms_auto_retry"], False)

    def test_fastapi_phone_bind_respects_explicit_retry_count(self):
        saved = {"hero_phone_bind": {"sms_auto_retry": False, "sms_retry_count": 3}}

        with patch("regpilot.api._load_webui_config", return_value=saved):
            merged = fastapi_api._merge_task_values(
                "hero_phone_bind",
                {"sms_auto_retry": True, "sms_retry_count": 5},
            )

        self.assertIs(merged["sms_auto_retry"], True)
        self.assertEqual(merged["sms_retry_count"], 5)

    def test_phone_direct_batch_uses_total_and_thread_count(self):
        active = 0
        max_active = 0
        calls: list[int] = []
        lock = threading.Lock()

        def fake_once(payload, **_kwargs):
            nonlocal active, max_active
            with lock:
                calls.append(int(payload.get("total") or 0))
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.03)
            with lock:
                active -= 1
            return {"ok": True, "phone_number": f"+100{len(calls)}", "password": "pw"}

        with patch("regpilot.api_tasks._phone_direct_once", side_effect=fake_once):
            result = api_tasks._phone_direct({"total": 3, "threads": 2})

        self.assertTrue(result["ok"])
        self.assertEqual(result["target_total"], 3)
        self.assertEqual(result["threads"], 2)
        self.assertEqual(result["success_count"], 3)
        self.assertEqual(calls, [1, 1, 1])
        self.assertGreaterEqual(max_active, 2)

    def test_phone_direct_random_environment_rotates_between_phone_retries(self):
        profiles = [
            register_core.EnvironmentProfile("ua1", "en-US", "America/New_York", 1366, 768, "proxy-1", True),
            register_core.EnvironmentProfile("ua2", "en-GB", "Europe/London", 1440, 900, "proxy-2", True),
            register_core.EnvironmentProfile("ua3", "en-US", "America/Los_Angeles", 1536, 864, "proxy-3", True),
        ]
        seen_profiles = []

        def fake_once(payload, **kwargs):
            seen_profiles.append(kwargs.get("env_profile"))
            if len(seen_profiles) == 1:
                exc = RuntimeError("registration_disallowed")
                exc.phones_attempted = ["+573000000001"]
                exc.phone_number = "+573000000001"
                raise exc
            return {"ok": True, "phone_number": "+573000000002", "password": "pw", "phones_attempted": ["+573000000002"]}

        with patch("regpilot.api_tasks.prepare_environment_profile_from_payload", side_effect=profiles), \
             patch("regpilot.api_tasks._phone_direct_once", side_effect=fake_once):
            result = api_tasks._phone_direct(
                {
                    "total": 2,
                    "threads": 1,
                    "env_random_enabled": True,
                    "sms_auto_retry": True,
                    "sms_retry_count": 2,
                    "sms_provider": "smsbower",
                    "hero_sms_api_key": "sms-key",
                }
            )

        self.assertEqual([p.proxy for p in seen_profiles[:2]], ["proxy-1", "proxy-2"])
        self.assertEqual(result["success_count"], 2)
        self.assertEqual(result["items"][0]["phones_attempted"], ["+573000000001", "+573000000002"])

    def test_phone_direct_serializes_cpa_oauth_state_section(self):
        source = Path(api_tasks.__file__).read_text(encoding="utf-8")

        self.assertIn("_CPA_OAUTH_LOCK = threading.Lock()", source)
        self.assertIn("with _CPA_OAUTH_LOCK:", source)
        self.assertIn("避免并发授权 state 被覆盖", source)

    def test_fastapi_task_merge_allows_explicit_empty_to_clear_saved_value(self):
        saved = {"register": {"mail_type": "cloudflare-temp-email", "cf_temp_admin_auth": "saved-key"}}

        with patch("regpilot.api._load_webui_config", return_value=saved):
            merged = fastapi_api._merge_task_values("register", {"cf_temp_admin_auth": ""})

        self.assertEqual(merged["cf_temp_admin_auth"], "")

    def test_save_partial_result_persists_unified_phone_flow_state(self):
        phone_flow = flow._build_phone_flow_runtime(
            phone_number="+66123456789",
            activation_id="act-1",
            provider="hero_sms",
            stage="oauth_phone_verified",
            purpose="signup",
            status="verified",
            bind_email="bind@example.com",
            callback_url="https://callback.example.com/?code=1&state=2",
            callback_source="cpa_management",
        )
        flow._set_phone_flow_stage(
            phone_flow,
            "cpa_callback_fetched",
            status="callback_ready",
            cpa_submit_ok=False,
            cpa_submit_message="waiting",
            last_error="",
            error_code="",
            error_retryable=False,
            recovery_action="stop",
        )

        path = flow._save_partial_hero_phone_bind_result(
            phone_flow=phone_flow,
            password="pw-1",
            note="test",
        )
        payload = __import__("json").loads(__import__("pathlib").Path(path).read_text(encoding="utf-8"))

        self.assertEqual(payload["stage"], "cpa_callback_fetched")
        self.assertEqual(payload["provider"], "hero_sms")
        self.assertEqual(payload["verification_purpose"], "signup")
        self.assertEqual(payload["email"], "bind@example.com")
        self.assertEqual(payload["callback_source"], "cpa_management")
        self.assertEqual(payload["phone_flow"]["callback"]["url"], "https://callback.example.com/?code=1&state=2")
        self.assertTrue(payload["phone_flow"]["signup_verified"])
        self.assertTrue(payload["phone_flow"]["oauth_verified"])
        self.assertEqual(payload["phone_flow"]["error"]["recovery_action"], "stop")
        self.assertGreaterEqual(payload["attempt_count"], 1)
        self.assertEqual(payload["attempts"][-1]["stage"], "cpa_callback_fetched")
        self.assertEqual(payload["attempts"][-1]["note"], "test")

    def test_classify_phone_flow_error_uses_typed_recovery(self):
        classified = flow._classify_phone_flow_error("sms_code_timeout")
        self.assertEqual(classified.code, "sms_timeout")
        self.assertTrue(classified.retryable)
        self.assertEqual(classified.recovery_action, "resend_or_replace_phone")

        classified = flow._classify_phone_flow_error("whatsapp_channel_detected")
        self.assertEqual(classified.code, "unexpected_delivery_channel")
        self.assertTrue(classified.retryable)
        self.assertEqual(classified.recovery_action, "replace_phone")

        classified = flow._classify_phone_flow_error("cpa_callback_submit_failed: HTTP 500")
        self.assertEqual(classified.code, "cpa_callback_submit_failed")
        self.assertTrue(classified.retryable)
        self.assertEqual(classified.recovery_action, "retry_callback_submit")

    def test_poll_hero_sms_code_reports_wait_progress_before_timeout(self):
        class SteppingDatetime:
            current = 0

            @classmethod
            def now(cls, tz=None):
                value = cls.current
                cls.current += 2
                return real_datetime.fromtimestamp(value, tz)

        progress = []
        config = flow.HeroSMSConfig(api_key="k", wait_timeout=15, wait_interval=1)

        with patch.object(flow, "datetime", SteppingDatetime), \
             patch.object(flow, "_hero_sms_request", return_value="STATUS_WAIT_CODE"), \
             patch.object(flow.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "sms_code_timeout"):
                flow.poll_hero_sms_code(config, "act-1", on_progress=progress.append, progress_interval=5)

        self.assertGreaterEqual(len(progress), 1)
        self.assertIn("elapsed", progress[0])
        self.assertIn("remaining", progress[0])
        self.assertEqual(progress[0]["resend_after_seconds"], 30)
        self.assertFalse(progress[0]["resent"])

    def test_poll_hero_sms_code_defaults_to_sixty_seconds_after_resend(self):
        class SteppingDatetime:
            current = 0

            @classmethod
            def now(cls, tz=None):
                value = cls.current
                cls.current += 2
                return real_datetime.fromtimestamp(value, tz)

        progress = []
        resend_calls = []
        config = flow.HeroSMSConfig(api_key="k", wait_timeout=180, wait_interval=1)

        with patch.object(flow, "datetime", SteppingDatetime), \
             patch.object(flow, "_hero_sms_request", return_value="STATUS_WAIT_CODE"), \
             patch.object(flow.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "sms_code_timeout"):
                flow.poll_hero_sms_code(
                    config,
                    "act-1",
                    on_resend=lambda: resend_calls.append(1),
                    on_progress=progress.append,
                    progress_interval=5,
                )

        self.assertEqual(len(resend_calls), 1)
        resent_progress = [item for item in progress if item.get("resent")]
        self.assertTrue(resent_progress)
        self.assertEqual(resent_progress[0]["timeout_after_resend"], 60)

    def test_sms_wait_progress_message_uses_resend_window_before_resend(self):
        message = api_tasks._sms_wait_progress_message(
            {
                "elapsed": 18,
                "wait_timeout": 180,
                "remaining": 161,
                "resent": False,
                "resend_after_seconds": 30,
            }
        )

        self.assertIn("18/30", message)
        self.assertIn("距离自动重发", message)
        self.assertNotIn("18/180", message)

    def test_sms_wait_progress_message_uses_after_resend_window_after_resend(self):
        message = api_tasks._sms_wait_progress_message(
            {
                "elapsed": 36,
                "remaining": 59,
                "resent": True,
                "after_resend_elapsed": 0,
                "timeout_after_resend": 60,
            }
        )

        self.assertIn("重发后已等待 0/60", message)
        self.assertIn("总计 36 秒", message)

    def test_submit_callback_to_cpa_with_retry_retries_before_success(self):
        calls = []

        def fake_submit(*_args):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("temporary")
            return {"message": "ok"}

        with patch.object(flow, "submit_callback_to_cpa_management", side_effect=fake_submit), patch.object(flow.time, "sleep"):
            result = flow._submit_callback_to_cpa_with_retry("https://cpa.example", "key", "https://callback.example")

        self.assertEqual(len(calls), 2)
        self.assertEqual(result["message"], "ok")
        self.assertEqual(result["submit_attempts"], 2)

    def test_login_phone_flow_runtime_tracks_login_purpose(self):
        phone_flow = flow._build_phone_flow_runtime(
            phone_number="+447700900001",
            activation_id="act-login",
            provider="hero_sms",
            stage="signup_phone_acquired",
            purpose="login",
            status="pending_verification",
        )
        flow._set_phone_flow_stage(
            phone_flow,
            "awaiting_cpa_callback",
            status="verified",
            callback_url="https://callback.example.com/?code=login&state=abc",
            callback_source="cpa_management",
            last_error="",
            error_code="",
            error_retryable=False,
            recovery_action="stop",
        )

        self.assertEqual(phone_flow["purpose"], "login")
        self.assertEqual(phone_flow["stage"], "awaiting_cpa_callback")
        self.assertTrue(phone_flow["oauth_verified"])
        self.assertEqual(phone_flow["callback"]["source"], "cpa_management")


class HeroPhoneBindAboutYouFallbackTests(unittest.TestCase):
    def test_about_you_form_refreshes_page_html_before_submit(self):
        class DummyResponse:
            def __init__(self, url: str, text: str, status_code: int = 200):
                self.url = url
                self.text = text
                self.status_code = status_code
                self.headers = {}

        class DummyRegistrar:
            def __init__(self):
                self.session = object()

        registrar = DummyRegistrar()
        refreshed_html = '<form action="/about-you"><input name="name"><input name="birthday"></form>'

        def fake_request_with_local_retry(_session, method, url, **kwargs):
            if method.lower() == 'get':
                return DummyResponse(url, refreshed_html), None
            raise AssertionError('unexpected http call')

        with patch('regpilot.oauth_token_flow.request_with_local_retry', side_effect=fake_request_with_local_retry), \
             patch('regpilot.oauth_token_flow._post_form_and_follow', return_value=('https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc', 'ok')):
            final_url, _ = flow._submit_about_you_form(
                registrar,
                page_url='https://auth.openai.com/about-you',
                page_html='',
                full_name='Test User',
                birthdate='1999-01-02',
            )

        self.assertIn('/sign-in-with-chatgpt/codex/consent', final_url)

    def test_about_you_form_prefers_visible_age_over_hidden_birthday(self):
        class DummyRegistrar:
            def __init__(self):
                self.session = object()

        submitted_payloads = []
        page_html = '<form action="/about-you"><input name="name"><input name="age"><input type="hidden" name="birthday" value="2026-05-27"></form>'

        def fake_post_form(_registrar, *, page_url, action, payload):
            submitted_payloads.append(payload)
            return 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc', 'ok'

        with patch('regpilot.oauth_token_flow.request_with_local_retry', return_value=(None, "")), \
             patch('regpilot.oauth_token_flow._post_form_and_follow', side_effect=fake_post_form):
            flow._submit_about_you_form(
                DummyRegistrar(),
                page_url='https://auth.openai.com/about-you',
                page_html=page_html,
                full_name='Test User',
                birthdate='1999-01-02',
            )

        self.assertEqual(submitted_payloads[0].get("age"), str(real_datetime.now().year - 1999))
        self.assertNotIn("birthday", submitted_payloads[0])
        self.assertNotIn("birthdate", submitted_payloads[0])

    def test_about_you_form_prefers_visible_birthdate_field(self):
        class DummyRegistrar:
            def __init__(self):
                self.session = object()

        submitted_payloads = []
        page_html = '<form action="/about-you"><input name="name"><input name="birthdate"></form>'

        def fake_post_form(_registrar, *, page_url, action, payload):
            submitted_payloads.append(payload)
            return 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc', 'ok'

        with patch('regpilot.oauth_token_flow.request_with_local_retry', return_value=(None, "")), \
             patch('regpilot.oauth_token_flow._post_form_and_follow', side_effect=fake_post_form):
            flow._submit_about_you_form(
                DummyRegistrar(),
                page_url='https://auth.openai.com/about-you',
                page_html=page_html,
                full_name='Test User',
                birthdate='1999-01-02',
            )

        self.assertEqual(submitted_payloads[0].get("birthdate"), "1999-01-02")
        self.assertNotIn("age", submitted_payloads[0])

    def test_about_you_form_includes_required_consent_checkbox(self):
        class DummyRegistrar:
            def __init__(self):
                self.session = object()

        submitted_payloads = []
        page_html = (
            '<form action="/about-you">'
            '<input name="name">'
            '<input name="age">'
            '<input type="hidden" name="isExplicitConsentRequired" value="true">'
            '<input type="checkbox" name="explicitConsent" value="true" required>'
            '</form>'
        )

        def fake_post_form(_registrar, *, page_url, action, payload):
            submitted_payloads.append(payload)
            return 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc', 'ok'

        with patch('regpilot.oauth_token_flow.request_with_local_retry', return_value=(None, "")), \
             patch('regpilot.oauth_token_flow._post_form_and_follow', side_effect=fake_post_form):
            flow._submit_about_you_form(
                DummyRegistrar(),
                page_url='https://auth.openai.com/about-you',
                page_html=page_html,
                full_name='Test User',
                birthdate='1999-01-02',
            )

        self.assertEqual(submitted_payloads[0].get("isExplicitConsentRequired"), "true")
        self.assertEqual(submitted_payloads[0].get("explicitConsent"), "true")

    def test_about_you_form_reads_form_associated_hidden_inputs(self):
        class DummyRegistrar:
            def __init__(self):
                self.session = object()

        submitted_payloads = []
        page_html = (
            '<form id="about-form" action="/about-you" method="post"></form>'
            '<input form="about-form" name="name">'
            '<input form="about-form" name="age">'
            '<input form="about-form" type="hidden" name="isExplicitConsentRequired" value="false">'
        )

        def fake_post_form(_registrar, *, page_url, action, payload):
            submitted_payloads.append(payload)
            return 'https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc', 'ok'

        with patch('regpilot.oauth_token_flow.request_with_local_retry', return_value=(None, "")), \
             patch('regpilot.oauth_token_flow._post_form_and_follow', side_effect=fake_post_form):
            flow._submit_about_you_form(
                DummyRegistrar(),
                page_url='https://auth.openai.com/about-you',
                page_html=page_html,
                full_name='Test User',
                birthdate='1999-01-02',
            )

        self.assertEqual(submitted_payloads[0].get("age"), str(real_datetime.now().year - 1999))
        self.assertEqual(submitted_payloads[0].get("isExplicitConsentRequired"), "false")

    def test_phone_bind_uses_create_account_then_resolves_callback(self):
        class DummyTokenResult:
            def __init__(self):
                self.ok = True
                self.error = ""
                self.email = ""
                self.password = ""
                self.mailbox = {}

        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                self.closed = False
                self.last_authorize = {}

            def start_phone_signup(self, phone_number=""):
                self.phone_number = phone_number
                return {"status": 200, "code_verifier": "verifier", "final_url": "https://auth.openai.com/create-account/password"}

            def start_authorize(self, email):
                raise AssertionError("phone signup should not start from oauth authorize")

            def create_account_start(self, _phone):
                raise AssertionError("create_account_start should not run after password page is reached")

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {
                    "status": 200,
                    "ok": True,
                    "json": {"continue_url": "https://auth.openai.com/about-you?state=abc"},
                    "final_url": "https://auth.openai.com/about-you?state=abc",
                }

            def create_account(self, _name, _birthdate, referer=""):
                return {
                    "status": 200,
                    "ok": True,
                    "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"},
                    "location": "",
                    "final_url": "https://auth.openai.com/api/accounts/create_account",
                    "referer": referer,
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                return DummyTokenResult()

            def close(self):
                self.closed = True

        payload = {
            "hero_sms_api_key": "k",
        }

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", return_value="123456"), \
             patch("regpilot.api_tasks.HERO_SMS_MAX_RETRY_COUNT", 3), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks._load_continue_page", return_value={"continue_url": "https://auth.openai.com/about-you?state=abc", "page_type": "about_you", "text": '<input autocomplete="name"><input name="birthday">'}), \
             patch("regpilot.api_tasks._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=abc"), \
             patch("regpilot.api_tasks._continue_with_optional_add_email", return_value=("http://localhost:1455/auth/callback?code=cb&state=abc", "")), \
             patch("regpilot.api_tasks.save_result"), \
             patch("regpilot.api_tasks._save_partial_hero_phone_bind_result"), \
             patch("regpilot.api_tasks.set_hero_sms_status") as mock_set_status:
            result = _hero_phone_bind(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(result["callback_url"], "http://localhost:1455/auth/callback?code=cb&state=abc")
        mock_set_status.assert_called_once_with(unittest.mock.ANY, "act-1", 6)

    def test_phone_bind_passes_mail_config_to_post_registration_exchange(self):
        captured = {}

        class DummyTokenResult:
            def __init__(self):
                self.ok = True
                self.error = ""
                self.email = ""
                self.password = ""
                self.mailbox = {"bind_email": "bind@example.com"}
                self.callback_url = "http://localhost:1455/auth/callback?code=cb&state=abc"

        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                pass

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier", "final_url": "https://auth.openai.com/create-account/password"}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/about-you?state=abc"}, "final_url": "https://auth.openai.com/about-you?state=abc"}

            def create_account(self, _name, _birthdate, referer=""):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"}, "location": "", "final_url": "https://auth.openai.com/api/accounts/create_account"}

            def close(self):
                pass

        def fake_exchange(*, config, **_kwargs):
            captured["providers"] = list(config.mail.providers)
            captured["wait_timeout"] = config.mail.wait_timeout
            captured["proxy"] = config.mail.proxy
            return DummyTokenResult()

        payload = {
            "hero_sms_api_key": "k",
            "mail_type": "cloudflare-temp-email",
            "cf_temp_admin_auth": "mail-key",
            "cf_temp_base_url": "https:/mail.example.test/v1",
            "cf_temp_domain": "example.test",
            "wait_timeout": 17,
            "proxy": "http://proxy.example.test:8080",
        }

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", return_value="123456"), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks._load_continue_page", return_value={"continue_url": "https://auth.openai.com/about-you?state=abc", "page_type": "about_you", "text": '<input autocomplete="name"><input name="birthday">'}), \
             patch("regpilot.api_tasks._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=abc"), \
             patch("regpilot.api_tasks._exchange_registered_account_tokens", side_effect=fake_exchange), \
             patch("regpilot.api_tasks.save_result"), \
             patch("regpilot.api_tasks._save_partial_hero_phone_bind_result"), \
             patch("regpilot.api_tasks.set_hero_sms_status"):
            result = _hero_phone_bind(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(captured["providers"][0]["admin_auth"], "mail-key")
        self.assertEqual(captured["providers"][0]["base_url"], "https://mail.example.test/v1")
        self.assertEqual(captured["wait_timeout"], 17)
        self.assertEqual(captured["proxy"], "http://proxy.example.test:8080")

    def test_phone_bind_ignores_sub2api_and_saves_account_after_cpa_success(self):
        class DummyTokenResult:
            def __init__(self):
                self.ok = True
                self.error = ""
                self.email = ""
                self.password = ""
                self.mailbox = {
                    "bind_email": "bind@example.com",
                    "_cpa_submit_ok": True,
                    "_cpa_submit_message": "CPA callback submitted",
                }
                self.callback_url = "http://localhost:1455/auth/callback?code=cb&state=abc"

        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                pass

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier", "final_url": "https://auth.openai.com/create-account/password"}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/about-you?state=abc"}, "final_url": "https://auth.openai.com/about-you?state=abc"}

            def create_account(self, _name, _birthdate, referer=""):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"}, "location": "", "final_url": "https://auth.openai.com/api/accounts/create_account"}

            def close(self):
                pass

        payload = {
            "hero_sms_api_key": "k",
            "codex2api_url": "http://192.168.1.4:8317",
            "codex2api_admin_key": "key",
            "codex2api_auto_import": True,
        }

        saved_accounts = []
        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", return_value="123456"), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks._load_continue_page", return_value={"continue_url": "https://auth.openai.com/about-you?state=abc", "page_type": "about_you", "text": '<input autocomplete="name"><input name="birthday">'}), \
             patch("regpilot.api_tasks._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=abc"), \
             patch("regpilot.api_tasks._exchange_registered_account_tokens", return_value=DummyTokenResult()), \
             patch("regpilot.api_tasks.save_result"), \
             patch("regpilot.accounts_store.save_registration_result_to_account", side_effect=lambda result, **kwargs: saved_accounts.append((result, kwargs)) or {"id": "acc-1"}), \
             patch("regpilot.api_tasks._save_partial_hero_phone_bind_result"), \
             patch("regpilot.api_tasks.set_hero_sms_status"):
            result = _hero_phone_bind(payload)

        self.assertTrue(result["ok"])
        self.assertTrue(result["import_submit_ok"])
        self.assertEqual(result["import_submit_message"], "CPA callback submitted")
        self.assertTrue(result["codex2api_import_submit_ok"])
        self.assertEqual(saved_accounts[0][0].email, "bind@example.com")
        self.assertEqual(saved_accounts[0][1]["source"], "phone_signup")

    def test_phone_bind_logs_password_value_and_uses_fixed_password(self):
        registered_passwords = []

        class DummyTokenResult:
            def __init__(self):
                self.ok = True
                self.error = ""
                self.email = ""
                self.password = ""
                self.mailbox = {}

        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                pass

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier", "final_url": "https://auth.openai.com/create-account/password"}

            def create_account_start(self, _phone):
                raise AssertionError("password page already reached")

            def register_user(self, _phone, password):
                registered_passwords.append(password)
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/about-you?state=abc"}, "final_url": "https://auth.openai.com/about-you?state=abc"}

            def create_account(self, _name, _birthdate, referer=""):
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"}, "location": "", "final_url": "https://auth.openai.com/api/accounts/create_account"}

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                return DummyTokenResult()

            def close(self):
                pass

        payload = {
            "hero_sms_api_key": "k",
            "default_password": "FixedPass123!",
        }
        buf = io.StringIO()
        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", return_value="123456"), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks._load_continue_page", return_value={"continue_url": "https://auth.openai.com/about-you?state=abc", "page_type": "about_you", "text": '<input autocomplete="name"><input name="birthday">'}), \
             patch("regpilot.api_tasks._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=abc"), \
             patch("regpilot.api_tasks.save_result"), \
             patch("regpilot.api_tasks._save_partial_hero_phone_bind_result"), \
             patch("regpilot.api_tasks.set_hero_sms_status"), \
             redirect_stdout(buf):
            result = _hero_phone_bind(payload)

        self.assertTrue(result["ok"])
        self.assertEqual(registered_passwords, ["FixedPass123!"])
        self.assertIn("本次账号密码：FixedPass123!", buf.getvalue())

    def test_phone_bind_releases_after_timeout_without_new_number_when_auto_retry_disabled(self):
        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                self.closed = False

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier"}

            def start_authorize(self, email):
                raise AssertionError("phone signup should not start from oauth authorize")

            def create_account_start(self, _phone):
                return {"status": 200, "ok": True}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def close(self):
                self.closed = True

        payload = {
            "hero_sms_api_key": "k",
            "sms_auto_retry": False,
            "sms_wait_timeout": 120,
        }

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", side_effect=RuntimeError("sms_code_timeout")), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks.set_hero_sms_status") as mock_set_status:
            with self.assertRaises(RuntimeError) as ctx:
                _hero_phone_bind(payload)

        self.assertIn("sms_code_timeout", str(ctx.exception))
        mock_set_status.assert_called_with(unittest.mock.ANY, "act-1", 8)

    def test_phone_bind_does_not_finish_sms_order_before_openai_otp_success(self):
        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                self.closed = False

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier"}

            def create_account_start(self, _phone):
                return {"status": 200, "ok": True}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {"status": 400, "ok": False, "json": {"error": {"code": "invalid_otp"}}}

            def close(self):
                self.closed = True

        payload = {
            "hero_sms_api_key": "k",
            "sms_auto_retry": False,
            "sms_wait_timeout": 120,
        }

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", return_value="123456"), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks.set_hero_sms_status") as mock_set_status:
            with self.assertRaises(RuntimeError) as ctx:
                _hero_phone_bind(payload)

        self.assertIn("validate_phone_signup_otp_400", str(ctx.exception))
        self.assertEqual([call.args[1:] for call in mock_set_status.call_args_list], [("act-1", 8)])

    def test_phone_bind_triggers_gpt_resend_not_hero_resend_after_30_seconds(self):
        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                self.closed = False
                self.resend_calls = 0

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier"}

            def start_authorize(self, email):
                raise AssertionError("phone signup should not start from oauth authorize")

            def create_account_start(self, _phone):
                return {"status": 200, "ok": True}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def resend_phone_otp(self):
                self.resend_calls += 1
                return {"status": 200, "ok": True}

            def close(self):
                self.closed = True

        payload = {
            "hero_sms_api_key": "k",
            "sms_auto_retry": False,
            "sms_wait_timeout": 120,
        }
        registrar_instances = []
        poll_kwargs = {}

        def registrar_factory(*args, **kwargs):
            instance = DummyRegistrar(*args, **kwargs)
            registrar_instances.append(instance)
            return instance

        def fake_poll(_hero_sms, _activation_id, *, on_resend=None, **_kwargs):
            poll_kwargs.update(_kwargs)
            if on_resend:
                on_resend()
            raise RuntimeError("sms_code_timeout")

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", return_value={"phone_number": "+15551234567", "activation_id": "act-1"}), \
             patch("regpilot.api_tasks.poll_hero_sms_code", side_effect=fake_poll), \
             patch("regpilot.api_tasks.PlatformRegistrar", side_effect=registrar_factory), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks.set_hero_sms_status") as mock_set_status:
            with self.assertRaises(RuntimeError):
                _hero_phone_bind(payload)

        self.assertEqual(len(registrar_instances), 1)
        self.assertEqual(registrar_instances[0].resend_calls, 1)
        self.assertEqual(poll_kwargs["timeout_after_resend"], 60)
        mock_set_status.assert_called_with(unittest.mock.ANY, "act-1", 8)

    def test_phone_bind_retries_new_number_up_to_three_times_when_auto_retry_enabled(self):
        class DummyRegistrar:
            def __init__(self, *_args, **_kwargs):
                self.closed = False

            def start_phone_signup(self, _phone_number=""):
                return {"status": 200, "code_verifier": "verifier", "final_url": "https://auth.openai.com/u/signup/identifier"}

            def start_authorize(self, email):
                raise AssertionError("phone signup should not start from oauth authorize")

            def create_account_start(self, _phone):
                return {"status": 200, "ok": True}

            def register_user(self, _phone, _password):
                return {"status": 200, "ok": True}

            def send_phone_otp(self):
                return {"status": 200, "ok": True}

            def validate_phone_signup_otp(self, _code):
                return {
                    "status": 200,
                    "ok": True,
                    "json": {"continue_url": "https://auth.openai.com/about-you?state=abc"},
                    "final_url": "https://auth.openai.com/about-you?state=abc",
                }

            def create_account(self, _name, _birthdate, referer=""):
                return {
                    "status": 200,
                    "ok": True,
                    "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"},
                    "location": "",
                    "final_url": "https://auth.openai.com/api/accounts/create_account",
                    "referer": referer,
                }

            def exchange_platform_tokens(self, _code_verifier, _callback_url):
                class DummyTokenResult:
                    def __init__(self):
                        self.ok = True
                        self.error = ""
                        self.email = ""
                        self.password = ""
                        self.mailbox = {}
                return DummyTokenResult()

            def close(self):
                self.closed = True

        payload = {
            "hero_sms_api_key": "k",
            "sms_auto_retry": True,
        }

        acquire_results = [
            {"phone_number": "+15550000001", "activation_id": "act-1"},
            {"phone_number": "+15550000002", "activation_id": "act-2"},
            {"phone_number": "+15550000003", "activation_id": "act-3"},
        ]
        poll_results = [RuntimeError("sms_code_timeout"), RuntimeError("sms_code_timeout"), "123456"]

        with patch("regpilot.api_tasks.acquire_hero_sms_phone", side_effect=acquire_results), \
             patch("regpilot.api_tasks.poll_hero_sms_code", side_effect=poll_results), \
             patch("regpilot.api_tasks.HERO_SMS_MAX_RETRY_COUNT", 3), \
             patch("regpilot.api_tasks.PlatformRegistrar", DummyRegistrar), \
             patch("regpilot.api_tasks._probe_phone_signup_password_page", return_value={"status": 200, "ok": True, "matched": True, "final_url": "https://auth.openai.com/u/signup/password?state=abc", "title": "Create your password", "text": ""}), \
             patch("regpilot.api_tasks._load_continue_page", return_value={"continue_url": "https://auth.openai.com/about-you?state=abc", "page_type": "about_you", "text": '<input autocomplete="name"><input name="birthday">'}), \
             patch("regpilot.api_tasks._resolve_oauth_callback", return_value="http://localhost:1455/auth/callback?code=cb&state=abc"), \
             patch("regpilot.api_tasks._continue_with_optional_add_email", return_value=("http://localhost:1455/auth/callback?code=cb&state=abc", "")), \
             patch("regpilot.api_tasks.save_result"), \
             patch("regpilot.api_tasks._save_partial_hero_phone_bind_result"), \
             patch("regpilot.api_tasks.set_hero_sms_status") as mock_set_status:
            result = _hero_phone_bind(payload)

        self.assertTrue(result["ok"])
        self.assertEqual([call.args[1:] for call in mock_set_status.call_args_list], [("act-1", 8), ("act-2", 8), ("act-3", 6)])

    def test_sms_retry_exhausted_message_uses_selected_provider(self):
        self.assertEqual(
            fastapi_api._hero_phone_bind.__globals__["_sms_retry_exhausted_message"]("smsbower", 3, "phone_signup_password_page_not_reached"),
            "smsbower_retry_exhausted_after_3_attempts: phone_signup_password_page_not_reached",
        )

    def test_register_failure_summary_redacts_sensitive_values(self):
        summary = fastapi_api._hero_phone_bind.__globals__["_safe_register_failure_summary"](
            {
                "status": 400,
                "json": {"error": "bad request", "code": "invalid"},
                "text": "phone +628123456789 password Secret123!",
                "sentinel_token_present": True,
            }
        )

        self.assertIn("status=400", summary)
        self.assertIn("code=invalid", summary)
        self.assertIn("message=bad request", summary)
        self.assertNotIn("+628123456789", summary)
        self.assertNotIn("Secret123!", summary)

    def test_register_failure_summary_compacts_invalid_auth_step(self):
        summary = fastapi_api._hero_phone_bind.__globals__["_safe_register_failure_summary"](
            {
                "status": 400,
                "json": {"error": {"message": "Invalid authorization step.", "type": "invalid_request_error", "code": "invalid_auth_step"}},
                "text": '{ "error": { "message": "Invalid authorization step.", "type": "invalid_request_error", "code": "invalid_auth_step" } }',
                "sentinel_token_present": True,
            }
        )

        self.assertEqual(
            summary,
            "status=400 code=invalid_auth_step message=Invalid authorization step. action=replace_phone_or_environment sentinel_present=True",
        )
        self.assertNotIn("text=", summary)


class EmailRegistrationFlowTests(unittest.TestCase):
    def test_create_account_prefers_age_payload_when_about_you_page_asks_age(self):
        registrar = object.__new__(register_core.PlatformRegistrar)
        registrar.session = object()
        registrar.device_id = "dev-1"
        registrar.last_authorize = {}
        registrar._ensure_sentinel_token = lambda _flow: "sentinel"
        calls = []

        def fake_request(_session, method, url, **kwargs):
            payload = kwargs.get("json") or {}
            calls.append(payload)
            ok = payload == {"name": "Test User", "age": str(register_core._age_from_birthdate("1999-09-19"))}
            return SimpleNamespace(
                status_code=200 if ok else 400,
                text="ok" if ok else '{"error":{"code":"missing_required_parameter"}}',
                url=url,
                headers={"Location": "https://auth.openai.com/next"} if ok else {},
                json=lambda: {} if ok else {"error": {"code": "missing_required_parameter"}},
            ), ""

        with patch.object(register_core, "request_with_local_retry", side_effect=fake_request):
            result = registrar.create_account(
                "Test User",
                "1999-09-19",
                referer="https://auth.openai.com/about-you",
                page_context="How old are you? age",
            )

        self.assertTrue(result["ok"])
        self.assertEqual(calls[0], {"name": "Test User", "age": str(register_core._age_from_birthdate("1999-09-19"))})
        self.assertEqual(result["payload_attempts"][0]["keys"], ["name", "age"])

    def test_create_account_uses_birthdate_payload_by_default(self):
        payloads = register_core._about_you_create_account_payloads("Test User", "1999-09-19")

        self.assertEqual(payloads[0], {"name": "Test User", "birthdate": "1999-09-19"})

    def test_create_account_prefers_age_when_age_and_hidden_birthday_both_exist(self):
        page_html = '<title>How old are you?</title><input name="age"><input type="hidden" name="birthday" value="2026-05-27">'
        payloads = register_core._about_you_create_account_payloads("Test User", "1999-09-19", page_context=page_html)

        self.assertEqual(payloads[0], {"name": "Test User", "age": str(register_core._age_from_birthdate("1999-09-19"))})
        self.assertGreater(payloads.index({"name": "Test User", "birthdate": "1999-09-19"}), 0)
        self.assertIn("优先填写=年龄", register_core._about_you_shape_log_summary(page_html))
        self.assertIn("隐藏字段=生日", register_core._about_you_shape_log_summary(page_html))

    def test_create_account_prefers_visible_birthdate_payload(self):
        page_html = '<title>Date of birth</title><input name="name"><input name="birthdate" type="date">'
        payloads = register_core._about_you_create_account_payloads("Test User", "1999-09-19", page_context=page_html)

        self.assertEqual(payloads[0], {"name": "Test User", "birthdate": "1999-09-19"})
        self.assertGreater(payloads.index({"name": "Test User", "age": str(register_core._age_from_birthdate("1999-09-19"))}), 0)

    def test_create_account_payload_omits_about_you_consent_fields_for_api(self):
        page_html = (
            '<title>How old are you?</title>'
            '<input name="age">'
            '<input type="hidden" name="isExplicitConsentRequired" value="true">'
            '<input type="checkbox" name="explicitConsent" value="true" required>'
        )
        payloads = register_core._about_you_create_account_payloads("Test User", "1999-09-19", page_context=page_html)

        self.assertEqual(
            payloads[0],
            {
                "name": "Test User",
                "age": str(register_core._age_from_birthdate("1999-09-19")),
            },
        )
        self.assertNotIn("isExplicitConsentRequired", payloads[0])
        self.assertNotIn("explicitConsent", payloads[0])

    def test_create_account_stops_after_registration_disallowed(self):
        registrar = object.__new__(register_core.PlatformRegistrar)
        registrar.session = object()
        registrar.device_id = "dev-1"
        registrar.last_authorize = {}
        registrar._ensure_sentinel_token = lambda _flow: "sentinel"
        calls = []

        def fake_request(_session, method, url, **kwargs):
            payload = kwargs.get("json") or {}
            calls.append(payload)
            return SimpleNamespace(
                status_code=400,
                text='{"error":{"code":"registration_disallowed"}}',
                url=url,
                headers={},
                json=lambda: {"error": {"code": "registration_disallowed"}},
            ), ""

        with patch.object(register_core, "request_with_local_retry", side_effect=fake_request):
            result = registrar.create_account(
                "Test User",
                "1999-09-19",
                referer="https://auth.openai.com/about-you",
                page_context="",
            )

        self.assertFalse(result["ok"])
        self.assertEqual(calls, [{"name": "Test User", "birthdate": "1999-09-19"}])
        self.assertEqual(result["payload_attempts"][0]["error_code"], "registration_disallowed")

    def test_register_user_failure_does_not_send_or_wait_for_email_otp(self):
        calls = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                calls.append(("init", proxy))

            def start_email_signup(self, email):
                calls.append(("start_email_signup", email))
                return {"status": 200, "final_url": "https://auth.openai.com/create-account", "code_verifier": "verifier"}

            def establish_signup_session(self):
                calls.append(("establish_signup_session",))
                return {"ok": True, "cookie_summary": {"present": ["oai-client-auth-session"]}}

            def create_account_start(self, email):
                calls.append(("create_account_start", email))
                return {"status": 200, "ok": True, "final_url": "https://auth.openai.com/create-account/password"}

            def register_user(self, email, password):
                calls.append(("register_user", email, bool(password)))
                return {"status": 409, "ok": False, "json": {"message": "already exists"}}

            def send_otp(self):
                raise AssertionError("send_otp should not be called after register_user failure")

            def close(self):
                calls.append(("close",))

        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "wait_for_code", side_effect=AssertionError("wait_for_code should not be called")), \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertFalse(result.ok)
        self.assertEqual(result.email, "user@example.com")
        self.assertTrue(result.error.startswith("register_user_409"))
        self.assertIn(("create_account_start", "user@example.com"), calls)
        self.assertIn(("register_user", "user@example.com", True), calls)
        self.assertNotIn(("send_otp",), calls)

    def test_authorize_error_stops_before_signup_session(self):
        calls = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                calls.append(("start_email_signup", email))
                return {
                    "status": 200,
                    "final_url": "https://auth.openai.com/error?errorCode=authorize_hydra_invalid_request",
                }

            def establish_signup_session(self):
                raise AssertionError("signup session should not start after authorize error")

            def close(self):
                calls.append(("close",))

        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertFalse(result.ok)
        self.assertEqual(result.error, "authorize_hydra_invalid_request")
        self.assertEqual(calls, [("start_email_signup", "user@example.com"), ("close",)])

    def test_email_verification_entry_does_not_reinitialize_signup_start(self):
        calls = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                calls.append(("start_email_signup", email))
                return {"status": 200, "final_url": "https://auth.openai.com/email-verification", "code_verifier": ""}

            def create_account_start(self, email):
                raise AssertionError("email-verification entry should continue to OTP flow")

            def establish_signup_session(self):
                calls.append(("establish_signup_session",))
                return {"ok": True, "cookie_summary": {"present": ["oai-client-auth-session"]}}

            def validate_signup_otp(self, code):
                calls.append(("validate_signup_otp", code))
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/create-account/password"}}

            def register_user(self, email, password):
                calls.append(("register_user", email, bool(password)))
                return {"status": 409, "ok": False, "json": {"message": "already exists"}}

            def send_otp(self):
                raise AssertionError("email-verification entry should use the automatically sent code first")

            def close(self):
                calls.append(("close",))

        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "wait_for_code", return_value="123456"), \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertFalse(result.ok)
        self.assertTrue(result.error.startswith("register_user_409"))
        self.assertEqual(calls[0], ("start_email_signup", "user@example.com"))
        self.assertIn(("establish_signup_session",), calls)
        self.assertLess(calls.index(("validate_signup_otp", "123456")), calls.index(("register_user", "user@example.com", True)))

    def test_email_verification_about_you_uses_form_fallback_after_api_400(self):
        calls = []

        class DummyTokenResult:
            ok = False
            error = "missing_oauth_callback"
            email = ""
            password = ""
            mailbox = {}

        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                calls.append(("start_email_signup", email))
                return {"status": 200, "final_url": "https://auth.openai.com/email-verification", "code_verifier": ""}

            def establish_signup_session(self):
                calls.append(("establish_signup_session",))
                return {"ok": True, "cookie_summary": {"present": ["oai-client-auth-session"]}}

            def validate_signup_otp(self, code):
                calls.append(("validate_signup_otp", code))
                return {"status": 200, "ok": True, "json": {"continue_url": "https://auth.openai.com/about-you"}}

            def register_user(self, email, password):
                raise AssertionError("about-you branch should not submit password before name/birthdate")

            def create_account(self, name, birthdate, referer=""):
                calls.append(("create_account", name, birthdate, referer))
                return {"status": 400, "ok": False, "text": "bad about-you payload", "final_url": "https://auth.openai.com/api/accounts/create_account"}

            def exchange_platform_tokens(self, _code_verifier, callback_url):
                calls.append(("exchange_platform_tokens", callback_url))
                return DummyTokenResult()

            def close(self):
                calls.append(("close",))

        about_you_html = '<form action="/about-you"><input name="name"><input name="birthdate"></form>'
        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "wait_for_code", return_value="123456"), \
             patch.object(register_core, "_load_registration_state", return_value={"kind": "about_you", "url": "https://auth.openai.com/about-you", "raw": {"text": about_you_html}}), \
             patch("regpilot.oauth_token_flow._submit_about_you_form", return_value=("https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc", "ok")) as submit_about_you, \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertFalse(result.ok)
        self.assertIn(("validate_signup_otp", "123456"), calls)
        self.assertTrue(any(call[0] == "create_account" and call[3] == "https://auth.openai.com/about-you" for call in calls))
        self.assertEqual(submit_about_you.call_args.kwargs["page_html"], about_you_html)
        self.assertIn(("exchange_platform_tokens", "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=abc"), calls)

    def test_email_about_you_success_resolves_oauth_callback_before_exchange(self):
        exchange_calls = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                self.last_authorize = {"state": "signup-state"}

            def start_email_signup(self, email):
                return {"status": 200, "final_url": "https://auth.openai.com/email-verification", "state": "signup-state", "code_verifier": "verifier"}

            def establish_signup_session(self):
                return {"ok": True, "cookie_summary": {"present": ["oai-client-auth-session"]}}

            def validate_signup_otp(self, code):
                return {"status": 200, "ok": True, "json": {"page": {"type": "about_you"}, "continue_url": "https://auth.openai.com/about-you"}}

            def create_account(self, name, birthdate, referer="", page_context=""):
                return {
                    "status": 200,
                    "ok": True,
                    "json": {"continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent?state=signup-state"},
                    "final_url": "https://auth.openai.com/api/accounts/create_account",
                }

            def close(self):
                pass

        def fake_exchange(**kwargs):
            exchange_calls.append(kwargs["callback_url"])
            return register_core.RegistrationResult(
                ok=True,
                email=kwargs["email"],
                password=kwargs["password"],
                callback_url=kwargs["callback_url"],
            )

        resolved_callback = "http://localhost:1455/auth/callback?code=cb&state=signup-state"
        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "wait_for_code", return_value="123456"), \
             patch.object(register_core, "_load_registration_state", return_value={"kind": "about_you", "url": "https://auth.openai.com/about-you", "raw": {"text": ""}}), \
             patch("regpilot.oauth_token_flow._resolve_oauth_callback", return_value=resolved_callback), \
             patch.object(register_core, "_exchange_registered_account_tokens", side_effect=fake_exchange), \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertTrue(result.ok)
        self.assertEqual(exchange_calls, [resolved_callback])
        self.assertEqual(result.callback_url, resolved_callback)

    def test_email_registration_logs_are_readable_chinese(self):
        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                return {"status": 200, "final_url": "https://auth.openai.com/error?errorCode=authorize_hydra_invalid_request"}

            def close(self):
                pass

        buf = io.StringIO()
        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "save_result", return_value="saved.json"), \
             redirect_stdout(buf):
            register_core.run_placeholder(register_core.RegisterConfig())

        output = buf.getvalue()
        self.assertIn("阶段：已创建邮箱：user@example.com", output)
        self.assertIn("已创建邮箱：user@example.com", output)
        self.assertIn("已生成注册资料：密码已生成", output)
        self.assertNotIn("宸", output)
        self.assertNotIn("鎴", output)

    def test_email_registration_logs_generated_password_value(self):
        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                return {"status": 200, "final_url": "https://auth.openai.com/error?errorCode=authorize_hydra_invalid_request"}

            def close(self):
                pass

        buf = io.StringIO()
        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "_random_password", return_value="RandPass123!"), \
             patch.object(register_core, "save_result", return_value="saved.json"), \
             redirect_stdout(buf):
            register_core.run_placeholder(register_core.RegisterConfig())

        self.assertIn("本次账号密码：RandPass123!", buf.getvalue())

    def test_registration_disallowed_skips_about_you_form_fallback(self):
        class DummyRegistrar:
            def __init__(self, proxy=""):
                pass

            def start_email_signup(self, email):
                return {"status": 200, "final_url": "https://auth.openai.com/email-verification", "code_verifier": ""}

            def establish_signup_session(self):
                return {"ok": True, "cookie_summary": {"present": ["oai-client-auth-session"]}}

            def validate_signup_otp(self, code):
                return {"status": 200, "ok": True, "json": {"page": {"type": "about_you"}, "continue_url": "https://auth.openai.com/about-you"}}

            def create_account(self, name, birthdate, referer="", page_context=""):
                return {
                    "status": 400,
                    "ok": False,
                    "json": {"error": {"code": "registration_disallowed", "message": "Sorry, we cannot create your account with the given information."}},
                    "text": "",
                    "final_url": "https://auth.openai.com/api/accounts/create_account",
                }

            def close(self):
                pass

        with patch.object(register_core, "create_mailbox", return_value={"email": "user@example.com"}), \
             patch.object(register_core, "PlatformRegistrar", DummyRegistrar), \
             patch.object(register_core, "wait_for_code", return_value="123456"), \
             patch("regpilot.oauth_token_flow._submit_about_you_form", side_effect=AssertionError("terminal upstream rejection should not use form fallback")), \
             patch.object(register_core, "save_result", return_value="saved.json"):
            result = register_core.run_placeholder(register_core.RegisterConfig())

        self.assertFalse(result.ok)
        self.assertEqual(result.error, "registration_disallowed")


class SMSProviderTests(unittest.TestCase):
    def test_enrich_mailbox_with_bind_mail_provider_carries_cloudflare_config(self):
        mailbox = {"phone_number": "+15551234567", "bind_email": "bind@example.com"}
        mail_config = {
            "providers": [
                {
                    "type": "cloudflare-temp-email",
                    "base_url": "https://mail.example.test",
                    "admin_auth": "admin-secret",
                    "domain": "example.com",
                }
            ]
        }

        out = api_tasks._enrich_mailbox_with_bind_mail_provider(mailbox, mail_config, "bind@example.com")

        self.assertEqual(out["provider"], "cloudflare-temp-email")
        self.assertEqual(out["email"], "bind@example.com")
        self.assertEqual(out["bind_email"], "bind@example.com")
        self.assertEqual(out["base_url"], "https://mail.example.test")
        self.assertEqual(out["admin_auth"], "admin-secret")
        self.assertEqual(out["domain"], "example.com")

    def test_enrich_mailbox_with_bind_mail_provider_uses_matching_cloudflare_provider(self):
        mailbox = {"provider": "cloudflare-temp-email", "bind_email": "bind@cf.test"}
        mail_config = {
            "providers": [
                {
                    "type": "icloud",
                    "imap_user": "owner@icloud.com",
                    "imap_password": "app-pass",
                    "host": "icloud.com",
                },
                {
                    "type": "cloudflare-temp-email",
                    "base_url": "https://mail.cf.test",
                    "admin_auth": "admin-secret",
                    "domain": "cf.test",
                },
            ]
        }

        out = api_tasks._enrich_mailbox_with_bind_mail_provider(mailbox, mail_config, "bind@cf.test")

        self.assertEqual(out["provider"], "cloudflare-temp-email")
        self.assertEqual(out["base_url"], "https://mail.cf.test")
        self.assertEqual(out["admin_auth"], "admin-secret")
        self.assertEqual(out["domain"], "cf.test")
        self.assertNotIn("imap_password", out)

    def test_smsbower_countries_use_chinese_label_and_default_visible(self):
        config = flow.HeroSMSConfig(provider="smsbower", api_key="k", base_url=flow.SMSBOWER_BASE_URL)
        payload = [{"id": 1003, "rus": "Бермуды", "eng": "Bermuda", "chn": "百慕大"}]

        with patch.object(flow, "_hero_sms_request", return_value=payload):
            items = flow.fetch_hero_sms_countries(config)

        self.assertEqual(items[0]["id"], "1003")
        self.assertEqual(items[0]["label"], "百慕大")
        self.assertTrue(items[0]["visible"])

    def test_smsbower_acquire_phone_uses_get_number_v2_json(self):
        calls = []

        def fake_request(_config, params):
            calls.append(params)
            return {"activationId": "act-1", "phoneNumber": "15551234567"}

        config = flow.HeroSMSConfig(
            provider="smsbower",
            api_key="k",
            base_url=flow.SMSBOWER_BASE_URL,
            country="1003",
            max_price=0.027,
        )

        with patch.object(flow, "_hero_sms_request", side_effect=fake_request):
            result = flow.acquire_hero_sms_phone(config)

        self.assertEqual(calls[0]["action"], "getNumberV2")
        self.assertEqual(calls[0]["country"], "1003")
        self.assertEqual(calls[0]["maxPrice"], 0.027)
        self.assertEqual(result, {"activation_id": "act-1", "phone_number": "+15551234567"})

    def test_hero_sms_acquire_phone_uses_max_price_when_response_has_no_price(self):
        calls = []

        def fake_request(_config, params):
            calls.append(params)
            return "ACCESS_NUMBER:act-1:15551234567"

        config = flow.HeroSMSConfig(
            provider="hero_sms",
            api_key="k",
            country="151",
            max_price=0.023,
        )

        with patch.object(flow, "_hero_sms_request", side_effect=fake_request):
            result = flow.acquire_hero_sms_phone(config)

        self.assertEqual(calls[0]["action"], "getNumber")
        self.assertEqual(calls[0]["maxPrice"], 0.023)
        self.assertEqual(result, {"activation_id": "act-1", "phone_number": "+15551234567", "price": "≤0.0230"})

    def test_5sim_acquire_phone_uses_activation_endpoint(self):
        calls = []

        def fake_request(_config, path, params=None):
            calls.append((path, params or {}))
            return {"id": 12345, "phone": "15551234567", "price": 0.12}

        config = flow.HeroSMSConfig(
            provider="5sim",
            api_key="k",
            base_url=flow.FIVESIM_BASE_URL,
            country="england",
            service="openai",
            max_price=0.13,
        )

        with patch.object(flow, "_5sim_request", side_effect=fake_request):
            result = flow.acquire_hero_sms_phone(config)

        self.assertEqual(calls[0][0], "/user/buy/activation/england/any/openai")
        self.assertEqual(calls[0][1]["maxPrice"], 0.13)
        self.assertEqual(result, {"activation_id": "12345", "phone_number": "+15551234567", "price": "0.12"})

    def test_5sim_countries_use_chinese_label_from_english_name(self):
        config = flow.HeroSMSConfig(provider="5sim", api_key="k", base_url=flow.FIVESIM_BASE_URL)
        payload = {
            "england": {"text_en": "England", "text_ru": "Англия"},
            "colombia": {"text_en": "Colombia"},
        }

        with (
            patch.object(flow, "_5sim_request", return_value=payload),
            patch.object(flow, "fetch_country_name_zh_map", return_value={"England": "英格兰", "Colombia": "哥伦比亚"}),
        ):
            items = flow.fetch_hero_sms_countries(config)

        by_id = {item["id"]: item for item in items}
        self.assertEqual(by_id["england"]["chn"], "英格兰")
        self.assertEqual(by_id["england"]["label"], "英格兰（England）")
        self.assertEqual(by_id["colombia"]["label"], "哥伦比亚（Colombia）")

    def test_5sim_poll_code_reads_sms_code_list(self):
        config = flow.HeroSMSConfig(provider="5sim", api_key="k", base_url=flow.FIVESIM_BASE_URL, wait_timeout=15, wait_interval=1)

        with patch.object(flow, "_5sim_request", return_value={"status": "RECEIVED", "sms": [{"code": "123456", "text": "OpenAI code 123456"}]}):
            code = flow.poll_hero_sms_code(config, "12345")

        self.assertEqual(code, "123456")

    def test_5sim_code_extraction_ignores_order_dates_when_sms_is_empty(self):
        payload = {
            "id": 1020218950,
            "status": "PENDING",
            "created_at": "2026-06-01T04:03:25.799610Z",
            "expires": "2026-06-01T04:23:25.799610Z",
            "sms": [],
        }

        self.assertEqual(flow._extract_5sim_sms_code(payload), "")

    def test_5sim_status_maps_to_rest_endpoints(self):
        calls = []

        def fake_request(_config, path, params=None):
            calls.append(path)
            return {"ok": True}

        config = flow.HeroSMSConfig(provider="5sim", api_key="k", base_url=flow.FIVESIM_BASE_URL)

        with patch.object(flow, "_5sim_request", side_effect=fake_request):
            flow.set_hero_sms_status(config, "12345", 6)
            flow.set_hero_sms_status(config, "12345", 8)
            flow.set_hero_sms_status(config, "12345", 3)

        self.assertEqual(calls, ["/user/finish/12345", "/user/cancel/12345"])

    def test_5sim_provider_uses_generic_key_and_slug_defaults(self):
        payload = {"sms_provider": "five-sim", "sms_api_key": "five-key", "hero_sms_country": "", "hero_sms_service": ""}

        cfg = api_tasks._sms_config_from_payload(payload)

        self.assertEqual(cfg.provider, "5sim")
        self.assertEqual(cfg.api_key, "five-key")
        self.assertEqual(cfg.base_url, flow.FIVESIM_BASE_URL)
        self.assertEqual(cfg.country, "england")
        self.assertEqual(cfg.service, "openai")

    def test_cpa_oauth_proxy_does_not_fallback_to_register_proxy(self):
        saved = {"register": {"proxy": "http://127.0.0.1:7890", "codex2api_proxy_url": ""}}

        with patch("regpilot.api._load_webui_config", return_value=saved):
            proxy_url = fastapi_api._prefer_codex2api_proxy_url("")

        self.assertEqual(proxy_url, "")

    def test_smsbower_key_does_not_fallback_to_hero_key(self):
        payload = {"sms_provider": "smsbower", "hero_sms_api_key": "hero-key", "sms_api_key": "", "smsbower_api_key": ""}

        self.assertEqual(fastapi_api._hero_phone_bind.__globals__["_sms_api_key_from_payload"](payload, "smsbower"), "")


class ApiJobOutputTests(unittest.TestCase):
    def test_safe_job_filters_debug_summary_from_visible_output(self):
        job = {
            "id": "job-1",
            "kind": "reauthorize",
            "output": "\n".join(
                [
                    "阶段：开始重新授权",
                    "Flow debug summary: " + ("x" * 200),
                    "Flow debug encode failed: bad json",
                    "阶段：重新授权任务结束：CPA 回调已提交",
                ]
            ),
            "result": {"ok": True, "access_token": "secret-token"},
            "error": {"message": "bad", "traceback": "secret local path"},
        }

        safe = fastapi_api._safe_job(job)

        self.assertNotIn("Flow debug summary:", safe["output"])
        self.assertNotIn("Flow debug encode failed:", safe["output"])
        self.assertIn("阶段：开始重新授权", safe["output"])
        self.assertEqual(safe["result"]["access_token"], "***")
        self.assertEqual(safe["error"]["traceback"], "[hidden; see server logs]")

    def test_safe_job_redacts_api_keys_from_result_and_output(self):
        job = {
            "id": "job-1",
            "kind": "register",
            "output": 'request failed admin_auth=mail-secret {"sms_api_key":"sms-secret","password":"pw"}',
            "result": {
                "ok": False,
                "cf_temp_admin_auth": "mail-secret",
                "hero_sms_api_key": "hero-secret",
                "nested": {"smsbower_api_key": "bower-secret"},
            },
        }

        safe = fastapi_api._safe_job(job)
        text = json.dumps(safe, ensure_ascii=False)

        self.assertNotIn("mail-secret", text)
        self.assertNotIn("hero-secret", text)
        self.assertNotIn("sms-secret", text)
        self.assertNotIn("bower-secret", text)
        self.assertNotIn('"password":"pw"', text)
        self.assertEqual(safe["result"]["cf_temp_admin_auth"], "***")
        self.assertIn("admin_auth=[hidden]", safe["output"])

    def test_safe_job_redacts_bearer_tokens_from_output(self):
        job = {
            "id": "job-1",
            "kind": "reauthorize",
            "output": "request Authorization: Bearer sk-test-secret-token\nretry with Bearer abcdefghijklmnop",
        }

        safe = fastapi_api._safe_job(job)

        self.assertNotIn("sk-test-secret-token", safe["output"])
        self.assertNotIn("abcdefghijklmnop", safe["output"])
        self.assertIn("Authorization: Bearer [hidden]", safe["output"])
        self.assertIn("Bearer [hidden]", safe["output"])
        self.assertIn("authorization\\s*[:=]\\s*bearer", fastapi_api.FASTAPI_INDEX_HTML)


class ApiAccountSafetyTests(unittest.TestCase):
    def _jwt(self, payload: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii").rstrip("=")
        return f"header.{raw}.sig"

    def _account(self) -> dict:
        return {
            "id": "acc-1",
            "email": "u@example.com",
            "password": "account-password",
            "access_token": "access-secret",
            "refresh_token": "refresh-secret",
            "id_token": "id-secret",
            "status": "authorized",
            "source": "manual",
            "mailbox": {"admin_auth": "mail-secret", "account_id": "org-1"},
            "updated_at": "2026-05-29 02:00:00",
        }

    def test_account_list_redacts_secrets_but_keeps_status_fields(self):
        with patch("regpilot.api.list_accounts", return_value=[self._account()]), \
             patch("regpilot.api.count_accounts", return_value=1):
            out = fastapi_api.api_list_accounts()

        item = out["items"][0]
        text = json.dumps(item, ensure_ascii=False)
        self.assertNotIn("account-password", text)
        self.assertNotIn("access-secret", text)
        self.assertNotIn("refresh-secret", text)
        self.assertNotIn("id-secret", text)
        self.assertNotIn("mail-secret", text)
        self.assertEqual(item["access_token"], "***")
        self.assertEqual(item["refresh_token"], "***")
        self.assertEqual(item["password"], "***")
        self.assertEqual(item["token_status"], "refreshable")
        self.assertIs(item["token_refreshable"], True)
        self.assertIn("phone_status", item)
        self.assertEqual(item["mail_provider"], "")
        self.assertEqual(item["mail_provider_label"], "-")

    def test_account_safe_output_includes_mail_provider_label(self):
        account = self._account()
        account["mailbox"] = {"provider": "icloud", "email": "alias@icloud.com", "imap_password": "app-pass"}

        safe = fastapi_api._safe_account_with_status(account)

        self.assertEqual(safe["mail_provider"], "icloud")
        self.assertEqual(safe["mail_provider_label"], "iCloud")
        self.assertEqual(safe["mailbox"]["imap_password"], "***")

    def test_account_safe_output_infers_cloudflare_provider_from_configured_domain(self):
        account = self._account()
        account["email"] = "ocdemo@19971109.xyz"
        account["mailbox"] = {"bind_email": "ocdemo@19971109.xyz"}

        with patch("regpilot.api._load_webui_config", return_value={"register": {"cf_temp_domain": "19971109.xyz"}}):
            safe = fastapi_api._safe_account_with_status(account)

        self.assertEqual(safe["mail_provider"], "cloudflare-temp-email")
        self.assertEqual(safe["mail_provider_label"], "Cloudflare")

    def test_account_list_accepts_search_query(self):
        with patch("regpilot.api.list_accounts", return_value=[self._account()]) as list_mock, \
             patch("regpilot.api.count_accounts", return_value=1) as count_mock:
            out = fastapi_api.api_list_accounts(q=" example ")

        self.assertEqual(out["q"], "example")
        list_mock.assert_called_once_with(limit=200, offset=0, search="example")
        count_mock.assert_called_once_with(search="example")

    def test_accounts_store_search_filters_email_status_source_notes_and_mailbox(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"):
            accounts_store.upsert_account(
                {
                    "id": "acc-1",
                    "email": "alpha@example.com",
                    "password": "password-1",
                    "status": "authorized",
                    "source": "manual",
                    "notes": "priority account",
                    "mailbox": {"provider": "hotmail-api", "domain": "mail.test"},
                    "tags": ["vip"],
                }
            )
            accounts_store.upsert_account(
                {
                    "id": "acc-2",
                    "email": "beta@example.com",
                    "password": "password-2",
                    "status": "failed",
                    "source": "register",
                    "notes": "blocked",
                    "mailbox": {"provider": "cloudflare-temp-email", "domain": "cf.test"},
                }
            )

            self.assertEqual([a["id"] for a in accounts_store.list_accounts(search="alpha")], ["acc-1"])
            self.assertEqual([a["id"] for a in accounts_store.list_accounts(search="failed")], ["acc-2"])
            self.assertEqual([a["id"] for a in accounts_store.list_accounts(search="manual vip")], ["acc-1"])
            self.assertEqual(accounts_store.count_accounts(search="cloudflare"), 1)

    def test_account_detail_and_save_responses_are_redacted(self):
        account = self._account()
        with patch("regpilot.api.get_account", return_value=account):
            detail = fastapi_api.api_get_account("acc-1")
        with patch("regpilot.api.upsert_account", return_value=account):
            saved = fastapi_api.api_upsert_account(
                fastapi_api.AccountUpsertRequest(
                    id="acc-1",
                    email="u@example.com",
                    password="account-password",
                    access_token="access-secret",
                    refresh_token="refresh-secret",
                    id_token="id-secret",
                )
            )

        for payload in (detail["item"], saved["item"]):
            text = json.dumps(payload, ensure_ascii=False)
            self.assertNotIn("account-password", text)
            self.assertNotIn("access-secret", text)
            self.assertNotIn("refresh-secret", text)
            self.assertEqual(payload["access_token"], "***")
            self.assertEqual(payload["password"], "***")

    def test_account_status_tolerates_malformed_jwt_exp(self):
        account = self._account()
        account["access_token"] = self._jwt({"exp": "not-a-number"})

        safe = fastapi_api._safe_account_with_status(account)

        self.assertEqual(safe["token_status"], "refreshable")
        self.assertEqual(safe["token_expires_at"], 0)
        self.assertEqual(safe["access_token"], "***")

    def test_account_text_fields_redact_embedded_secrets(self):
        account = self._account()
        account["last_error"] = "failed with Authorization: Bearer sk-test-secret-token"
        account["notes"] = "manual password=note-secret"
        account["mailbox"] = {
            "provider": "cloudflare-temp-email",
            "last_response": '{"refresh_token":"refresh-secret"}',
            "message": "retry Bearer abcdefghijklmnop",
        }

        safe = fastapi_api._safe_account_with_status(account)
        text = json.dumps(safe, ensure_ascii=False)

        self.assertNotIn("sk-test-secret-token", text)
        self.assertNotIn("note-secret", text)
        self.assertNotIn("refresh-secret", text)
        self.assertNotIn("abcdefghijklmnop", text)
        self.assertIn("Authorization: Bearer [hidden]", safe["last_error"])
        self.assertIn("password=[hidden]", safe["notes"])
        self.assertIn("Bearer [hidden]", safe["mailbox"]["message"])

    def test_account_update_preserves_existing_password_and_tokens_when_omitted(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"):
            accounts_store.upsert_account(
                {
                    "id": "acc-1",
                    "email": "old@example.com",
                    "password": "original-password",
                    "status": "authorized",
                    "source": "manual",
                    "callback_url": "http://callback.example.test",
                    "access_token": "access-secret",
                    "refresh_token": "refresh-secret",
                    "id_token": "id-secret",
                    "last_auth_at": "2026-05-29 01:00:00",
                }
            )

            updated = accounts_store.upsert_account(
                {
                    "id": "acc-1",
                    "email": "new@example.com",
                    "password": "***",
                    "status": "authorized",
                    "source": "manual",
                    "mailbox": {"provider": "cloudflare-temp-email"},
                }
            )

        self.assertEqual(updated["email"], "new@example.com")
        self.assertEqual(updated["password"], "original-password")
        self.assertEqual(updated["callback_url"], "http://callback.example.test")
        self.assertEqual(updated["access_token"], "access-secret")
        self.assertEqual(updated["refresh_token"], "refresh-secret")
        self.assertEqual(updated["id_token"], "id-secret")
        self.assertEqual(updated["last_auth_at"], "2026-05-29 01:00:00")

    def test_webui_account_fill_does_not_reuse_redacted_password(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("set('password','')", html)
        self.assertIn("password!=='***'", html)

    def test_webui_account_table_shows_mail_provider(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("<th>邮箱服务</th>", html)
        self.assertIn("function mailProviderText", html)
        self.assertIn("${esc(mailProviderText(a))}", html)
        self.assertIn('<option value="icloud">iCloud</option>', html)

    def test_webui_hides_icloud_cookie_fields(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("mail-icloud-cookie-field", html)
        self.assertIn("可留空，使用 cookies 自动创建 HME", html)
        self.assertIn("iCloud 需填写 HME 邮箱或 Cookies", html)
        self.assertIn("$('icloud_cookies_path')?.closest('label')?.classList.add('hidden')", html)
        self.assertNotIn("document.querySelectorAll('.mail-icloud-cookie-field').forEach(el=>el.classList.add('hidden'))", html)


class StabilityTests(unittest.TestCase):
    def test_request_with_local_retry_respects_explicit_timeout(self):
        class FakeSession:
            def __init__(self):
                self.calls = []

            def request(self, method, url, **kwargs):
                self.calls.append((method, url, kwargs))
                return SimpleNamespace(status_code=200, url=url, text="", headers={})

        session = FakeSession()
        response, error = register_core.request_with_local_retry(session, "get", "https://example.test", timeout=7)

        self.assertEqual(error, "")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(session.calls[0][2]["timeout"], 7)

    def test_webui_config_loader_returns_shared_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            config = fastapi_api._load_webui_config()

        self.assertIn("register", config)
        self.assertEqual(config["register"]["mail_type"], "cloudflare-temp-email")
        self.assertEqual(config["logs"]["job_log_max_mb"], 100)

    def test_webui_config_loader_uses_last_valid_when_current_file_is_corrupt(self):
        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"), \
             patch("regpilot.api_tasks.WEBUI_CONFIG_LAST_VALID_PATH", Path(tmpdir) / "webui_config.last_valid.json"):
            current = Path(tmpdir) / "webui_config.json"
            last_valid = Path(tmpdir) / "webui_config.last_valid.json"
            current.write_text('{"register": {"proxy": "unterminated}', encoding="utf-8")
            last_valid.write_text(
                json.dumps({"register": {"mail_type": "cloudflare-temp-email", "cf_temp_domain": "example.test"}}),
                encoding="utf-8",
            )

            config = fastapi_api._load_webui_config()
            backups = list(Path(tmpdir).glob("webui_config.corrupt-*.json"))

        self.assertEqual(config["register"]["mail_type"], "cloudflare-temp-email")
        self.assertEqual(config["register"]["cf_temp_domain"], "example.test")
        self.assertTrue(backups)

    def test_webui_config_save_filters_unknown_keys_and_preserves_defaults(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            out = fastapi_api.api_save_config(
                fastapi_api.ConfigSaveRequest(section="register", values={"proxy": "http://127.0.0.1:7890", "unknown": "x"})
            )
            last_valid_exists = (Path(tmpdir) / "webui_config.last_valid.json").exists()

        self.assertTrue(out["ok"])
        self.assertEqual(out["config"]["register"]["proxy"], "http://127.0.0.1:7890")
        self.assertNotIn("unknown", out["config"]["register"])
        self.assertEqual(out["config"]["logs"]["job_log_max_mb"], 100)
        self.assertTrue(last_valid_exists)

    def test_webui_config_save_normalizes_boolean_and_integer_strings(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            out = fastapi_api.api_save_config(
                fastapi_api.ConfigSaveRequest(
                    section="hero_phone_bind",
                    values={"sms_auto_retry": "false", "sms_retry_count": "5"},
                )
            )

        self.assertTrue(out["ok"])
        self.assertIs(out["config"]["hero_phone_bind"]["sms_auto_retry"], False)
        self.assertEqual(out["config"]["hero_phone_bind"]["sms_retry_count"], 5)

    def test_webui_config_save_preserves_optional_blank_integer_strings(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            out = fastapi_api.api_save_config(
                fastapi_api.ConfigSaveRequest(
                    section="hero_phone_bind",
                    values={"hero_sms_min_price": "", "hero_sms_max_price": ""},
                )
            )

        self.assertTrue(out["ok"])
        self.assertEqual(out["config"]["hero_phone_bind"]["hero_sms_min_price"], "")
        self.assertEqual(out["config"]["hero_phone_bind"]["hero_sms_max_price"], "")

    def test_webui_config_save_rejects_invalid_boolean_before_persist(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            with self.assertRaises(fastapi_api.HTTPException) as ctx:
                fastapi_api.api_save_config(
                    fastapi_api.ConfigSaveRequest(section="hero_phone_bind", values={"sms_auto_retry": "maybe"})
                )

            self.assertFalse((Path(tmpdir) / "webui_config.json").exists())

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_auto_retry")

    def test_webui_config_save_rejects_invalid_integer_before_persist(self):
        with tempfile.TemporaryDirectory() as tmpdir, patch("regpilot.api_tasks.WEBUI_CONFIG_PATH", Path(tmpdir) / "webui_config.json"):
            with self.assertRaises(fastapi_api.HTTPException) as ctx:
                fastapi_api.api_save_config(
                    fastapi_api.ConfigSaveRequest(section="logs", values={"job_log_max_mb": "1.5"})
                )

            self.assertFalse((Path(tmpdir) / "webui_config.json").exists())

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_job_log_max_mb")

    def test_cli_config_preserves_json_values_when_flags_are_absent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(
                json.dumps(
                    {
                        "env_random_enabled": "true",
                        "total": 5,
                        "threads": 2,
                        "codex2api_auto_import": "false",
                        "hero_sms_min_price": "0.01",
                        "hero_sms_max_price": "0.023",
                        "sms_auto_retry": "false",
                        "sms_retry_count": "7",
                    }
                ),
                encoding="utf-8",
            )
            args = cli.build_parser().parse_args(["register", "--config", str(path)])
            cfg = cli.load_config(args)

        self.assertIs(cfg.env_random_enabled, True)
        self.assertEqual(cfg.total, 5)
        self.assertEqual(cfg.threads, 2)
        self.assertIs(cfg.codex2api_auto_import, False)
        self.assertAlmostEqual(cfg.hero_sms_min_price, 0.01)
        self.assertAlmostEqual(cfg.hero_sms_max_price, 0.023)
        self.assertIs(cfg.hero_sms_auto_retry, False)
        self.assertEqual(cfg.hero_sms_retry_count, 7)

    def test_cli_flags_override_retry_config_only_when_present(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "config.json"
            path.write_text(json.dumps({"sms_auto_retry": True, "sms_retry_count": 2}), encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["register", "--config", str(path), "--no-hero-sms-auto-retry", "--hero-sms-retry-count", "4"]
            )
            cfg = cli.load_config(args)

        self.assertIs(cfg.hero_sms_auto_retry, False)
        self.assertEqual(cfg.hero_sms_retry_count, 4)

    def test_core_boolean_parsing_handles_string_false(self):
        config = SimpleNamespace(
            env_random_enabled="false",
            proxy="",
            env_proxy_pool="",
            env_ua_pool="",
            env_accept_language_pool="",
            env_timezone_pool="",
            env_viewport_pool="",
        )
        profile = register_core.prepare_environment_profile_from_config(config)

        self.assertFalse(profile.randomized)

    def test_accounts_db_connection_sets_busy_timeout_and_wal(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(accounts_store, "DB_PATH", Path(tmpdir) / "accounts.db"):
            with accounts_store.connect_db() as conn:
                busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
                journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
                conn.execute("PRAGMA journal_mode = DELETE")

        self.assertEqual(busy_timeout, 30000)
        self.assertEqual(str(journal_mode).lower(), "wal")

    def test_hero_phone_bind_preflight_rejects_missing_sms_key_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "codex2api_auto_import": True,
                "codex2api_url": "http://127.0.0.1:8317",
                "codex2api_admin_key": "key",
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "",
                "sms_api_key": "",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "sms_api_key_required")

    def test_hero_phone_bind_preflight_rejects_missing_import_target_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(values={"hero_sms_api_key": "sms-key", "sms_provider": "hero_sms"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "codex2api_required")

    def test_hero_phone_bind_preflight_rejects_unknown_sms_provider_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "smsbwoer",
                "hero_sms_api_key": "sms-key",
                "codex2api_auto_import": True,
                "codex2api_url": "http://127.0.0.1:8317",
                "codex2api_admin_key": "key",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_provider")
        self.assertIn("接码服务类型无效", fastapi_api.FASTAPI_INDEX_HTML)

    def test_sms_config_rejects_unknown_provider_in_lookup_helpers(self):
        with self.assertRaises(ValueError) as ctx:
            api_tasks._sms_config_from_payload({"sms_provider": "smsbwoer", "hero_sms_api_key": "sms-key"})

        self.assertEqual(str(ctx.exception), "invalid_sms_provider")

    def test_task_builders_parse_string_false_booleans(self):
        cfg = api_tasks._register_config_from_payload(
            {
                "mail_type": "cloudflare-temp-email",
                "cf_temp_base_url": "https://mail.example.test",
                "cf_temp_admin_auth": "key",
                "cf_temp_domain": "example.test",
                "codex2api_auto_import": "false",
                "sms_auto_retry": "false",
                "cf_temp_use_random_subdomain": "false",
                "env_random_enabled": "false",
            }
        )

        self.assertIs(cfg.codex2api_auto_import, False)
        self.assertIs(cfg.hero_sms_auto_retry, False)
        self.assertIs(cfg.env_random_enabled, False)
        self.assertIs(api_tasks._bool_from_payload({"codex2api_auto_import": "false"}, "codex2api_auto_import", True), False)

    def test_task_builders_append_cloudflare_fallback_for_icloud_mail(self):
        payload = {
            "mail_type": "icloud",
            "icloud_imap_user": "owner@icloud.com",
            "icloud_imap_password": "app-pass",
            "icloud_cookies_json": "{\"token\":\"value\"}",
            "cf_temp_base_url": "https://mail.cf.test",
            "cf_temp_admin_auth": "admin-secret",
            "cf_temp_domain": "cf.test",
        }

        cfg = api_tasks._register_config_from_payload(payload)
        mail_config = api_tasks._mail_config_dict_from_payload(payload)

        self.assertEqual([item["type"] for item in cfg.mail.providers], ["icloud", "cloudflare-temp-email"])
        self.assertEqual(cfg.mail.providers[1]["base_url"], "https://mail.cf.test")
        self.assertEqual(cfg.mail.providers[1]["admin_auth"], "admin-secret")
        self.assertEqual(cfg.mail.providers[1]["domain"], "cf.test")
        self.assertEqual([item["type"] for item in mail_config["providers"]], ["icloud", "cloudflare-temp-email"])

    def test_task_builders_include_hotmail_api_provider(self):
        payload = {
            "mail_type": "hotmail-api",
            "hotmail_api_base_url": "http://mail-helper.test",
            "hotmail_alias_enabled": "false",
            "hotmail_alias_max_per_account": "7",
            "hotmail_mailboxes": "INBOX,Junk",
        }

        cfg = api_tasks._register_config_from_payload(payload)
        mail_config = api_tasks._mail_config_dict_from_payload(payload)

        self.assertEqual(cfg.mail.providers[0]["type"], "hotmail-api")
        self.assertEqual(cfg.mail.providers[0]["base_url"], "http://mail-helper.test")
        self.assertIs(cfg.mail.providers[0]["alias_enabled"], False)
        self.assertEqual(cfg.mail.providers[0]["alias_max_per_account"], 7)
        self.assertEqual(mail_config["providers"][0]["type"], "hotmail-api")

    def test_hero_phone_bind_preflight_treats_codex_false_string_as_disabled(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
                "codex2api_auto_import": "false",
                "codex2api_url": "http://127.0.0.1:8317",
                "codex2api_admin_key": "key",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "codex2api_required")

    def test_webui_parses_saved_false_booleans(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("function boolValue", html)
        self.assertIn("boolValue(h.env_random_enabled ?? r.env_random_enabled ?? false)", html)
        self.assertIn("boolValue(h.sms_auto_retry ?? r.sms_auto_retry ?? h.hero_sms_auto_retry ?? r.hero_sms_auto_retry ?? false)", html)

    def test_reauthorize_job_rejects_unknown_sms_provider_before_job_start(self):
        payload = fastapi_api.ReauthorizeAutoRequest(account_id="acc-1", sms_provider="smsbwoer", hero_sms_api_key="sms-key")

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_reauthorize_auto_job(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_provider")

    def test_webui_translates_sms_price_shortage_errors(self):
        self.assertIn("可用最低价", fastapi_api.FASTAPI_INDEX_HTML)
        self.assertIn("请提高最高价或更换国家", fastapi_api.FASTAPI_INDEX_HTML)

    def test_webui_async_account_actions_show_failures(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("账号加载失败", html)
        self.assertIn("保存账号失败", html)
        self.assertIn("批量重新授权失败", html)
        self.assertIn("任务加载失败", html)

    def test_webui_exposes_cloudflare_mail_config(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("cf_temp_admin_auth", html)
        self.assertIn("Cloudflare Admin Auth", html)
        self.assertIn("onMailProviderChange", html)
        self.assertIn("Cloudflare Admin Auth 必填", html)

    def test_webui_exposes_icloud_mail_config(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn('option value="icloud"', html)
        self.assertIn("icloud_imap_user", html)
        self.assertIn("icloud_cookies_json", html)
        self.assertIn("icloud_email_or_cookies_required", html)

    def test_webui_task_payload_does_not_clear_hidden_environment_pools(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertNotIn("env_random_enabled:true", html)
        self.assertNotIn("env_ua_pool:''", html)
        self.assertIn("if($('env_ua_pool'))values.env_ua_pool=val('env_ua_pool')", html)

    def test_webui_register_settings_exposes_fixed_password_control(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("注册设置", html)
        self.assertIn("openRegisterSettings", html)
        self.assertIn('id="registerSettingsPanel"', html)
        self.assertIn('id="default_password"', html)
        self.assertIn("固定密码", html)
        self.assertIn("default_password:val('default_password')", html)

    def test_webui_exposes_hotmail_api_provider_and_microsoft_mail_pool(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn('<option value="hotmail-api">Outlook/Hotmail</option>', html)
        self.assertIn("微软邮箱账户池", html)
        self.assertIn("/api/microsoft-mail/accounts", html)
        self.assertIn("hotmail_api_base_url", html)
        self.assertIn("hotmail_alias_enabled:checked('hotmail_alias_enabled')", html)
        self.assertIn('id="microsoftMailPoolSection" class="card span-2 hidden"', html)
        self.assertIn('class="mail-hotmail-field mail-hotmail-advanced hidden">Hotmail API 地址', html)
        self.assertIn("document.querySelectorAll('.mail-hotmail-advanced').forEach(el=>el.classList.add('hidden'))", html)
        self.assertIn("pool.classList.toggle('hidden',!isHotmail)", html)

    def test_webui_start_tasks_do_not_save_config_before_preflight(self):
        html = fastapi_api.FASTAPI_INDEX_HTML
        register_fn = html[html.index("async function startRegisterTask()"):html.index("async function startPhoneDirectTask()")]
        phone_fn = html[html.index("async function startPhoneDirectTask()"):html.index("async function stopJob(")]

        self.assertLess(register_fn.index("/api/tasks/register"), register_fn.index("/api/config"))
        self.assertLess(phone_fn.index("/api/tasks/phone-direct"), phone_fn.index("/api/config"))
        self.assertIn("任务已提交，但配置保存失败", register_fn)
        self.assertIn("任务已提交，但配置保存失败", phone_fn)

    def test_webui_task_panel_keeps_finished_summary(self):
        html = fastapi_api.FASTAPI_INDEX_HTML

        self.assertIn("function latestRegisterJob", html)
        self.assertIn("function finalTaskHeadline", html)
        self.assertIn("最近注册结果", html)
        self.assertIn("任务完成：成功", html)
        self.assertIn("status-summary-grid", html)
        self.assertIn("status-result-list", html)
        self.assertIn("这里会显示当前阶段和完成结果", html)
        self.assertIn("function renderStatusResultRows", html)
        self.assertIn("rows.slice(0,10)", html)
        self.assertIn("显示其余", html)
        self.assertIn("${active&&steps.length?", html)
        self.assertIn("任务结束：成功 ${counts.success}", html)
        self.assertNotIn("失败 ${counts.failure}；${message}", html)

    def test_webui_show_job_renders_inline_task_log(self):
        html = fastapi_api.FASTAPI_INDEX_HTML
        show_job_fn = html[html.index("async function showJob("):html.index("const unifiedLogState")]

        self.assertIn("renderJobLogPanel", html)
        self.assertIn("任务日志：", html)
        self.assertIn("task-log-preview", html)
        self.assertIn("jobs.innerHTML=renderJobLogPanel(j)", show_job_fn)
        self.assertIn("日志已显示在任务区", show_job_fn)

    def test_register_preflight_rejects_removed_mail_type_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(values={"mail_type": "unknown-mail"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_mail_type")

    def test_register_preflight_rejects_incomplete_cloudflare_config(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "mail_type": "cloudflare-temp-email",
                "cf_temp_base_url": "https://mail.example.test",
                "cf_temp_admin_auth": "",
                "cf_temp_domain": "example.test",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "cf_temp_admin_auth_required")

    def test_register_preflight_accepts_icloud_with_imap_alias(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "mail_type": "icloud",
                "icloud_email": "alias@icloud.com",
                "icloud_imap_user": "owner@icloud.com",
                "icloud_imap_password": "app-pass",
            }
        )

        with patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", return_value={"ok": True, "job_id": "job-1"}) as mock_run:
            result = fastapi_api.api_task_register(payload)

        self.assertEqual(result["job_id"], "job-1")
        self.assertEqual(mock_run.call_args.args[1], fastapi_api._run_register)

    def test_register_preflight_accepts_hotmail_api_with_pool_account(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "mail_type": "hotmail-api",
                "hotmail_api_base_url": "http://mail-helper.test",
                "hotmail_alias_enabled": True,
            }
        )

        with patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch.object(fastapi_api.microsoft_mail_pool, "count_available", return_value=1), \
             patch("regpilot.api._run_job", return_value={"ok": True, "job_id": "job-1"}) as mock_run:
            result = fastapi_api.api_task_register(payload)

        self.assertEqual(result["job_id"], "job-1")
        self.assertEqual(mock_run.call_args.args[1], fastapi_api._run_register)

    def test_register_preflight_rejects_hotmail_api_without_pool_account(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "mail_type": "hotmail-api",
                "hotmail_api_base_url": "http://mail-helper.test",
                "hotmail_alias_enabled": True,
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch.object(fastapi_api.microsoft_mail_pool, "count_available", return_value=0), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "microsoft_mail_pool_empty")

    def test_register_preflight_rejects_icloud_without_receive_config(self):
        payload = fastapi_api.TaskRunRequest(values={"mail_type": "icloud", "icloud_email": "alias@icloud.com"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "icloud_imap_or_cookies_required")

    def test_register_preflight_rejects_unknown_mail_type_before_fallback(self):
        payload = fastapi_api.TaskRunRequest(values={"mail_type": "unknown-mail", "cf_temp_admin_auth": "key"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_mail_type")
        self.assertIn("邮箱服务类型无效", fastapi_api.FASTAPI_INDEX_HTML)

    def test_register_preflight_rejects_invalid_task_bounds_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(values={"mail_type": "cloudflare-temp-email", "cf_temp_base_url": "https://mail.example.test", "cf_temp_admin_auth": "key", "cf_temp_domain": "example.test", "total": "abc"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_total")
        self.assertIn("注册数量必须是大于 0 的整数", fastapi_api.FASTAPI_INDEX_HTML)

    def test_register_preflight_rejects_fractional_task_bounds_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(values={"mail_type": "cloudflare-temp-email", "cf_temp_base_url": "https://mail.example.test", "cf_temp_admin_auth": "key", "cf_temp_domain": "example.test", "total": "1.5"})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_total")

    def test_register_preflight_rejects_invalid_timeout_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={"mail_type": "cloudflare-temp-email", "cf_temp_base_url": "https://mail.example.test", "cf_temp_admin_auth": "key", "cf_temp_domain": "example.test", "request_timeout": "slow"}
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_register(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_request_timeout")
        self.assertIn("请求超时时间必须是大于 0 的整数", fastapi_api.FASTAPI_INDEX_HTML)

    def test_hero_phone_bind_preflight_requires_codex2api_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "codex2api_required")
        self.assertIn("CPA 自动导入开关值无效", fastapi_api.FASTAPI_INDEX_HTML)

    def test_hero_phone_bind_preflight_rejects_invalid_sms_price_range_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
                "hero_sms_min_price": "0.08",
                "hero_sms_max_price": "0.03",
                "codex2api_auto_import": True,
                "codex2api_url": "http://127.0.0.1:8317",
                "codex2api_admin_key": "key",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_price_range")
        self.assertIn("最低价不能高于最高价", fastapi_api.FASTAPI_INDEX_HTML)

    def test_hero_phone_bind_preflight_rejects_non_finite_sms_price_before_job_start(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
                "hero_sms_max_price": "nan",
                "codex2api_auto_import": True,
                "codex2api_url": "http://127.0.0.1:8317",
                "codex2api_admin_key": "key",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._run_job", side_effect=AssertionError("job should not start")):
            fastapi_api.api_task_hero_phone_bind(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_max_price")

    def test_sms_price_lookup_rejects_invalid_values_before_provider_call(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
                "sms_wait_timeout": "later",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._hero_price_lookup", side_effect=AssertionError("provider should not be queried")):
            fastapi_api.api_sms_price(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_wait_timeout")

    def test_sms_country_lookup_rejects_missing_key_before_provider_call(self):
        payload = fastapi_api.TaskRunRequest(values={"sms_provider": "smsbower", "smsbower_api_key": ""})

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._hero_country_lookup", side_effect=AssertionError("provider should not be queried")):
            fastapi_api.api_sms_countries(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "sms_api_key_required")

    def test_sms_price_lookup_rejects_invalid_price_range_before_provider_call(self):
        payload = fastapi_api.TaskRunRequest(
            values={
                "sms_provider": "hero_sms",
                "hero_sms_api_key": "sms-key",
                "hero_sms_min_price": "0.08",
                "hero_sms_max_price": "0.03",
            }
        )

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api._load_webui_config", return_value={"register": {}, "hero_phone_bind": {}}), \
             patch("regpilot.api._hero_price_lookup", side_effect=AssertionError("provider should not be queried")):
            fastapi_api.api_sms_price(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_price_range")

    def test_reauthorize_sms_values_parses_saved_false_auto_retry(self):
        payload = fastapi_api.ReauthorizeAutoRequest(account_id="acc-1")

        with patch(
            "regpilot.api._load_webui_config",
            return_value={
                "register": {},
                "hero_phone_bind": {
                    "sms_provider": "hero_sms",
                    "hero_sms_api_key": "sms-key",
                    "sms_auto_retry": "false",
                },
            },
        ):
            values = fastapi_api._prefer_reauthorize_sms_values(payload)

        self.assertIs(values["sms_auto_retry"], False)

    def test_reauthorize_sms_values_rejects_invalid_auto_retry_string(self):
        payload = fastapi_api.ReauthorizeAutoRequest(account_id="acc-1")

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch(
                 "regpilot.api._load_webui_config",
                 return_value={
                     "register": {},
                     "hero_phone_bind": {
                         "sms_provider": "hero_sms",
                         "hero_sms_api_key": "sms-key",
                         "sms_auto_retry": "maybe",
                     },
                 },
             ):
            fastapi_api._prefer_reauthorize_sms_values(payload)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "invalid_sms_auto_retry")

    def test_run_register_honors_requested_total_successes(self):
        results = [
            register_core.RegistrationResult(ok=True, email="one@example.com", access_token="a1", mailbox={}),
            register_core.RegistrationResult(ok=True, email="two@example.com", access_token="a2", mailbox={}),
        ]

        with patch("regpilot.api_tasks.run_placeholder", side_effect=results) as run, \
             patch("regpilot.api_tasks.save_result", return_value=Path("saved.json")), \
             patch("regpilot.api_tasks.time.sleep"):
            out = api_tasks._run_register({"total": 2, "mail_type": "cloudflare-temp-email", "cf_temp_base_url": "https://mail.example.test", "cf_temp_admin_auth": "key", "cf_temp_domain": "example.test"})

        self.assertTrue(out["ok"])
        self.assertEqual(run.call_count, 2)
        self.assertEqual(out["target_total"], 2)
        self.assertEqual(out["success_count"], 2)
        self.assertEqual([item["email"] for item in out["items"]], ["one@example.com", "two@example.com"])

    def test_run_register_retries_registration_disallowed_until_target_met(self):
        results = [
            register_core.RegistrationResult(ok=False, email="blocked@example.com", error="registration_disallowed", mailbox={}),
            register_core.RegistrationResult(ok=True, email="one@example.com", access_token="a1", mailbox={}),
            register_core.RegistrationResult(ok=True, email="two@example.com", access_token="a2", mailbox={}),
        ]

        with patch("regpilot.api_tasks.run_placeholder", side_effect=results) as run, \
             patch("regpilot.api_tasks.save_result", return_value=Path("saved.json")), \
             patch("regpilot.api_tasks.time.sleep") as sleep, \
             redirect_stdout(io.StringIO()) as buf:
            out = api_tasks._run_register({"total": 2, "mail_type": "cloudflare-temp-email", "cf_temp_base_url": "https://mail.example.test", "cf_temp_admin_auth": "key", "cf_temp_domain": "example.test", "registration_disallowed_retry_count": 3})

        self.assertTrue(out["ok"])
        self.assertEqual(run.call_count, 3)
        self.assertEqual(sleep.call_count, 1)
        self.assertEqual(out["success_count"], 2)
        self.assertEqual(out["failure_count"], 1)
        self.assertEqual(out["failures"][0]["error"], "registration_disallowed")
        self.assertIn("阶段：注册尝试 1/6", buf.getvalue())
        self.assertIn("阶段：本次被上游拒绝创建账号", buf.getvalue())

    def test_job_store_uses_chinese_stage_lines_for_current_stage(self):
        store = api_tasks.JobStore()
        job_id = store.create("register")

        store.append_output(job_id, "阶段：已创建邮箱：user@example.com\n")
        store.append_output(job_id, "阶段：邮箱验证码校验结果：status=200 ok=True continue_url=https://auth.openai.com/about-you\n")

        job = store.list()[0]
        self.assertEqual(job["meta"]["stage"], "邮箱验证码校验结果：status=200 ok=True continue_url=https://auth.openai.com/about-you")

    def test_refresh_account_tokens_marks_request_failure(self):
        item = {
            "id": "acc-1",
            "email": "u@example.com",
            "refresh_token": "refresh-token",
            "status": "authorized",
        }

        with self.assertRaises(fastapi_api.HTTPException) as ctx, \
             patch("regpilot.api.requests.post", side_effect=fastapi_api.requests.RequestException("timeout")), \
             patch("regpilot.api.upsert_account") as upsert:
            fastapi_api._refresh_account_tokens(item)

        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.detail, "refresh_token_failed:request_failed")
        saved = upsert.call_args.args[0]
        self.assertEqual(saved["status"], "auth_failed")
        self.assertEqual(saved["last_error"], "refresh_token_failed:request_failed")

    def test_job_store_starts_queued_and_allows_stop_before_running(self):
        store = api_tasks.JobStore()
        job_id = store.create("register")

        first = store.list()[0]
        self.assertEqual(first["status"], "queued")

        stop = store.request_stop(job_id)
        self.assertTrue(stop["ok"])
        self.assertEqual(stop["status"], "stopping")
        self.assertTrue(store.should_stop(job_id))

        store.mark_running(job_id)
        after = store.list()[0]
        self.assertEqual(after["status"], "stopping")

    def test_job_store_marks_running_after_queue(self):
        store = api_tasks.JobStore()
        job_id = store.create("register")

        store.mark_running(job_id)

        self.assertEqual(store.list()[0]["status"], "running")

    def test_job_store_marks_ok_false_result_as_failed(self):
        store = api_tasks.JobStore()
        job_id = store.create("register")

        store.finish(job_id, result={"ok": False, "error": "registration_target_not_reached"}, output="阶段：完成\n")
        job = store.list()[0]

        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["meta"]["stage"], "结束：注册目标未达成")

    def test_job_store_restores_persisted_logs_after_restart(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "jobs"
            log_dir.mkdir(parents=True)
            log_path = log_dir / "20260531-021851-job-4-phone_direct.log"
            log_path.write_text(
                "阶段：任务开始执行\n"
                "阶段：已收到短信验证码：123456\n"
                "阶段：手机直注短信验证码已取到，已立即释放手机号\n",
                encoding="utf-8",
            )
            with patch.object(api_tasks, "LOG_DIR", Path(tmpdir)):
                store = api_tasks.JobStore(restore=True)

            jobs = store.list()
            self.assertEqual(len(jobs), 1)
            self.assertEqual(jobs[0]["id"], "job-4")
            self.assertEqual(jobs[0]["kind"], "phone_direct")
            self.assertEqual(jobs[0]["status"], "done")
            self.assertIn("已收到短信验证码：123456", jobs[0]["output"])
            self.assertEqual(jobs[0]["meta"]["stage"], "手机直注短信验证码已取到，已立即释放手机号")
            self.assertEqual(store.create("register"), "job-5")

    def test_job_store_restore_keeps_duplicate_old_job_ids(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "jobs"
            log_dir.mkdir(parents=True)
            (log_dir / "20260531-010000-job-1-register.log").write_text("阶段：任务开始执行\n", encoding="utf-8")
            (log_dir / "20260531-020000-job-1-phone_direct.log").write_text("阶段：任务失败：boom\n", encoding="utf-8")
            with patch.object(api_tasks, "LOG_DIR", Path(tmpdir)):
                store = api_tasks.JobStore(restore=True)

            jobs = sorted(store.list(), key=lambda item: item["started_at"])
            self.assertEqual(len(jobs), 2)
            self.assertEqual(jobs[0]["id"], "job-1")
            self.assertEqual(jobs[1]["id"], "job-1-20260531-020000")
            self.assertEqual(jobs[1]["status"], "failed")

    def test_job_store_repairs_mojibake_when_restoring_old_logs(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            log_dir = Path(tmpdir) / "jobs"
            log_dir.mkdir(parents=True)
            mojibake = "阶段：手机直注批量完成 成功=2/2 失败=0".encode("utf-8").decode("latin1")
            (log_dir / "20260531-021851-job-4-phone_direct.log").write_text(mojibake, encoding="utf-8")
            with patch.object(api_tasks, "LOG_DIR", Path(tmpdir)):
                store = api_tasks.JobStore(restore=True)

            job = store.list()[0]
            self.assertIn("阶段：手机直注批量完成", job["output"])
            self.assertEqual(job["meta"]["stage"], "手机直注批量完成 成功=2/2 失败=0")


class ReauthorizePhoneVerificationTests(unittest.TestCase):
    def test_phone_otp_send_page_requires_phone_verification(self):
        info = {
            "ok": True,
            "status": 200,
            "json": {
                "continue_url": f"{register_core.auth_base}/api/accounts/phone-otp/send",
                "page": {"type": "phone_otp_send"},
            },
        }

        self.assertTrue(reauth._step_requires_phone_verification(info))

    def test_optional_phone_verification_submits_phone_and_validates_sms(self):
        calls = []

        class FakeSession:
            def post(self, url, **kwargs):
                calls.append(("POST", url, kwargs.get("json")))
                if url.endswith("/api/accounts/add-phone/send"):
                    return SimpleNamespace(url=url, status_code=200, headers={}, text="", json=lambda: {})
                if url.endswith("/api/accounts/phone-otp/validate"):
                    return SimpleNamespace(
                        url=url,
                        status_code=200,
                        headers={},
                        text="",
                        json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=phone-code&state=state-1"},
                    )
                raise AssertionError(f"unexpected post: {url}")

        registrar = SimpleNamespace(session=FakeSession(), device_id="dev-1", last_authorize={})
        source_info = {"ok": True, "status": 200, "json": {"page": {"type": "add_phone"}, "continue_url": "/add-phone"}}
        sms_config = flow.HeroSMSConfig(provider="smsbower", api_key="sms-key", base_url=flow.SMSBOWER_BASE_URL, country="1003")
        statuses = []

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.object(reauth, "DATA_DIR", Path(tmpdir)), \
             patch.object(reauth, "acquire_hero_sms_phone", return_value={"activation_id": "act-1", "phone_number": "+15551234567"}), \
             patch.object(reauth, "poll_hero_sms_code", return_value="654321") as mock_poll, \
             patch.object(reauth, "set_hero_sms_status", side_effect=lambda _cfg, activation_id, status: statuses.append((activation_id, status))):
            callback, _info, debug = reauth._continue_with_optional_phone_verification(
                registrar,
                source_info,
                "state-1",
                sms_config=sms_config,
                retry_count=1,
                account_id="acc-1",
                email="user@example.com",
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=phone-code&state=state-1")
        self.assertEqual(mock_poll.call_args.kwargs["timeout_after_resend"], 60)
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/add-phone/send", {"phone_number": "+15551234567"}), calls)
        self.assertIn(("POST", f"{register_core.auth_base}/api/accounts/phone-otp/validate", {"code": "654321"}), calls)
        self.assertEqual(statuses[-1], ("act-1", 3))
        self.assertEqual(debug["phone_reuse"], {"use_count": 1, "max_uses": 3, "completed": False, "remaining": 2})
        self.assertTrue(debug["callback_ready"])

    def test_phone_verification_reuses_number_until_third_success(self):
        class FakeSession:
            def post(self, url, **kwargs):
                if url.endswith("/api/accounts/add-phone/send"):
                    return SimpleNamespace(url=url, status_code=200, headers={}, text="", json=lambda: {})
                if url.endswith("/api/accounts/phone-otp/validate"):
                    return SimpleNamespace(
                        url=url,
                        status_code=200,
                        headers={},
                        text="",
                        json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=phone-code&state=state-1"},
                    )
                raise AssertionError(f"unexpected post: {url}")

        source_info = {"ok": True, "status": 200, "json": {"page": {"type": "add_phone"}, "continue_url": "/add-phone"}}
        sms_config = flow.HeroSMSConfig(provider="hero_sms", api_key="sms-key", country="16")
        statuses = []

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch.object(reauth, "DATA_DIR", Path(tmpdir)), \
             patch.object(reauth, "acquire_hero_sms_phone", return_value={"activation_id": "act-1", "phone_number": "+15551234567"}) as mock_acquire, \
             patch.object(reauth, "poll_hero_sms_code", return_value="654321"), \
             patch.object(reauth, "set_hero_sms_status", side_effect=lambda _cfg, activation_id, status: statuses.append((activation_id, status))):
            for index in range(3):
                registrar = SimpleNamespace(session=FakeSession(), device_id="dev-1", last_authorize={})
                callback, _info, debug = reauth._continue_with_optional_phone_verification(
                    registrar,
                    source_info,
                    "state-1",
                    sms_config=sms_config,
                    retry_count=1,
                    account_id=f"acc-{index + 1}",
                    email=f"user{index + 1}@example.com",
                )
                self.assertEqual(callback, "http://localhost:1455/auth/callback?code=phone-code&state=state-1")

        self.assertEqual(mock_acquire.call_count, 1)
        self.assertEqual(statuses, [("act-1", 3), ("act-1", 3), ("act-1", 6)])
        self.assertEqual(debug["phone_reuse"], {"use_count": 3, "max_uses": 3, "completed": True, "remaining": 0})

    def test_auto_reauthorize_reports_manual_phone_verification_after_password(self):
        account = {
            "id": "acc-1",
            "email": "user@example.com",
            "password": "pw",
            "mailbox": {"provider": "cloudflare-temp-email", "bind_email": "user@example.com"},
        }
        saved_accounts = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                self.last_authorize = {"state": "state-1"}

            def start_authorize(self, email="", authorize_url="", screen_hint=""):
                return {"ok": True, "status": 200, "final_url": authorize_url, "state": "state-1"}

            def establish_signup_session(self):
                return {"ok": True, "flow_kind": "login"}

            def close(self):
                pass

        password_info = {"ok": True, "status": 200, "json": {"page": {"type": "add_phone"}, "continue_url": "/add-phone"}}

        with patch.object(reauth, "get_account", return_value=dict(account)), \
             patch.object(reauth, "upsert_account", side_effect=lambda item: saved_accounts.append(dict(item)) or item), \
             patch.object(reauth, "PlatformRegistrar", DummyRegistrar), \
             patch.object(reauth, "_start_cpa_oauth", return_value={"authorize_url": f"{register_core.auth_base}/oauth/authorize?state=state-1", "state": "state-1"}), \
             patch.object(reauth, "_attempt_password_login", return_value=password_info), \
             patch.object(reauth, "_continue_with_optional_phone_verification", side_effect=AssertionError("reauthorize must not use SMS service for phone second verification")), \
             patch.object(reauth, "_send_login_otp", side_effect=AssertionError("phone verification branch must not send email otp")), \
             patch.object(reauth, "_submit_callback_to_cpa", side_effect=AssertionError("manual phone verification cannot submit CPA callback")):
            result = reauth.auto_reauthorize_account_with_email_otp(
                "acc-1",
                codex2api_url="http://127.0.0.1:8317",
                codex2api_admin_key="key",
                sms_provider="smsbower",
                sms_api_key="sms-key",
                hero_sms_country="1003",
                sms_wait_timeout=120,
                sms_wait_interval=6,
                sms_resend_after_seconds=11,
                sms_timeout_after_resend_seconds=22,
                sms_release_after_seconds=33,
                sms_auto_retry=True,
                sms_retry_count=4,
            )

        self.assertFalse(result.ok)
        self.assertEqual(result.message, "manual_phone_verification_required")
        self.assertEqual(saved_accounts[-1]["status"], "auth_failed")
        self.assertIn("manual_phone_verification_required", result.debug)

    def test_phone_signup_reauthorize_uses_bound_email_login_when_available(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "source": "phone_signup",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "bind_email": "alias@icloud.com", "phone_number": "+15551234567", "phone_number_verified": True},
        }
        start_calls = []

        class DummyRegistrar:
            def __init__(self, proxy=""):
                self.last_authorize = {"state": "state-1"}

            def start_authorize(self, email="", authorize_url="", screen_hint=""):
                start_calls.append(email)
                return {"ok": True, "status": 200, "final_url": f"{register_core.auth_base}/log-in/password", "state": "state-1"}

            def establish_signup_session(self):
                return {"ok": True, "flow_kind": "login"}

            def close(self):
                pass

        password_info = {"ok": True, "status": 200, "json": {"page": {"type": "add_email"}, "continue_url": f"{register_core.auth_base}/add-email"}, "final_url": f"{register_core.auth_base}/api/accounts/password/verify"}

        with patch.object(reauth, "get_account", return_value=dict(account)), \
             patch.object(reauth, "upsert_account", side_effect=lambda item: item), \
             patch.object(reauth, "PlatformRegistrar", DummyRegistrar), \
             patch.object(reauth, "_start_cpa_oauth", return_value={"authorize_url": f"{register_core.auth_base}/oauth/authorize?state=state-1", "state": "state-1"}), \
             patch.object(reauth, "_attempt_password_login", return_value=password_info) as mock_password, \
             patch.object(reauth, "_continue_with_optional_add_email", return_value=("http://localhost:1455/auth/callback?code=cb&state=state-1", "alias@icloud.com")) as mock_add_email, \
             patch.object(reauth, "_submit_callback_to_cpa", return_value={"ok": True, "message": "CPA callback submitted"}), \
             patch.object(reauth, "_finalize_cpa_submit_with_optional_local_tokens", return_value=reauth.ReauthorizeAutoOutcome(ok=True, message="CPA callback submitted", callback_url="http://localhost:1455/auth/callback?code=cb&state=state-1", codex2api_import_submit_ok=True)):
            result = reauth.auto_reauthorize_account_with_email_otp(
                "acc-1",
                codex2api_url="http://127.0.0.1:8317",
                codex2api_admin_key="key",
            )

        self.assertTrue(result.ok)
        self.assertEqual(start_calls[0], "alias@icloud.com")
        self.assertEqual(mock_password.call_args.args[1], "alias@icloud.com")
        self.assertEqual(mock_add_email.call_args.kwargs["bind_email"], "alias@icloud.com")

    def test_phone_signup_reauthorize_binds_email_when_about_you_returns_missing_email(self):
        account = {
            "id": "acc-1",
            "email": "+15551234567",
            "password": "pw",
            "source": "phone_signup",
            "mailbox": {"provider": "icloud", "phone_number": "+15551234567", "phone_number_verified": True},
        }

        class DummyRegistrar:
            def __init__(self, proxy=""):
                self.last_authorize = {"state": "state-1"}

            def start_authorize(self, email="", authorize_url="", screen_hint=""):
                return {"ok": True, "status": 200, "final_url": f"{register_core.auth_base}/log-in/password", "state": "state-1"}

            def establish_signup_session(self):
                return {"ok": True, "flow_kind": "login"}

            def close(self):
                pass

        password_info = {"ok": True, "status": 200, "json": {"page": {"type": "about_you"}, "continue_url": f"{register_core.auth_base}/about-you"}, "final_url": f"{register_core.auth_base}/api/accounts/password/verify"}

        with patch.object(reauth, "get_account", return_value=dict(account)), \
             patch.object(reauth, "upsert_account", side_effect=lambda item: item), \
             patch.object(reauth, "PlatformRegistrar", DummyRegistrar), \
             patch.object(reauth, "_start_cpa_oauth", return_value={"authorize_url": f"{register_core.auth_base}/oauth/authorize?state=state-1", "state": "state-1"}), \
             patch.object(reauth, "_attempt_password_login", return_value=password_info), \
             patch.object(reauth, "_continue_with_optional_about_you", side_effect=[
                 ("", {"create_account_error_code": "missing_email", "missing_email_continue_url": f"{register_core.auth_base}/add-email?from=about-you"}),
                 ("http://localhost:1455/auth/callback?code=cb&state=state-1", {"callback_ready": True}),
             ]) as mock_about_you, \
             patch.object(reauth, "_continue_with_optional_add_email", return_value=(f"{register_core.auth_base}/about-you", "alias@icloud.com")) as mock_add_email, \
             patch.object(reauth, "_submit_callback_to_cpa", return_value={"ok": True, "message": "CPA callback submitted"}), \
             patch.object(reauth, "_finalize_cpa_submit_with_optional_local_tokens", return_value=reauth.ReauthorizeAutoOutcome(ok=True, message="CPA callback submitted", callback_url="http://localhost:1455/auth/callback?code=cb&state=state-1", codex2api_import_submit_ok=True)):
            result = reauth.auto_reauthorize_account_with_email_otp(
                "acc-1",
                codex2api_url="http://127.0.0.1:8317",
                codex2api_admin_key="key",
            )

        self.assertTrue(result.ok)
        self.assertEqual(mock_about_you.call_count, 2)
        self.assertIn("@", mock_add_email.call_args.kwargs["bind_email"])
        self.assertEqual(mock_add_email.call_args.kwargs["continue_url"], f"{register_core.auth_base}/add-email?from=about-you")

    def test_about_you_missing_email_form_submit_supplies_add_email_continue_url(self):
        class DummyRegistrar:
            def create_account(self, name, birthdate, referer="", page_context=""):
                return {
                    "ok": False,
                    "status": 400,
                    "json": {"error": {"code": "missing_email"}},
                    "text": "",
                    "final_url": f"{register_core.auth_base}/api/accounts/create_account",
                }

        about_you_html = '<form method="POST"><input name="name"><input name="age"></form>'

        with patch.object(reauth, "_load_continue_page", return_value={"ok": True, "continue_url": f"{register_core.auth_base}/about-you", "text": about_you_html, "json": {"page": {"type": "about_you"}}}), \
             patch.object(reauth, "_submit_about_you_form", return_value=(f"{register_core.auth_base}/add-email?state=state-1", '<form><input type="email" name="email"></form>')):
            callback, debug = reauth._continue_with_optional_about_you(
                DummyRegistrar(),
                f"{register_core.auth_base}/about-you",
                "state-1",
            )

        self.assertEqual(callback, "")
        self.assertEqual(debug["create_account_error_code"], "missing_email")
        self.assertEqual(debug["missing_email_continue_url"], f"{register_core.auth_base}/add-email?state=state-1")

    def test_reauthorize_login_identifier_uses_phone_only_without_email(self):
        account = {"email": "+15551234567", "source": "phone_signup"}
        mailbox = {"provider": "icloud", "phone_number": "+15551234567", "phone_number_verified": True}

        self.assertEqual(reauth._login_identifier_for_account(account, mailbox, "+15551234567"), "+15551234567")

    def test_reauthorize_bind_email_hint_ignores_phone_only_identifier(self):
        account = {"email": "+15551234567", "source": "phone_signup"}
        mailbox = {"provider": "icloud", "phone_number": "+15551234567", "phone_number_verified": True}

        self.assertEqual(reauth._bind_email_hint_for_account(account, mailbox, "+15551234567"), "")

    def test_reauthorize_handles_email_otp_returned_by_password_verify(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "source": "phone_signup",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "phone_number": "+15551234567", "phone_number_verified": True},
        }

        class DummyRegistrar:
            def __init__(self, proxy=""):
                self.last_authorize = {"state": "state-1"}

            def start_authorize(self, email="", authorize_url="", screen_hint=""):
                return {"ok": True, "status": 200, "final_url": f"{register_core.auth_base}/log-in/password", "state": "state-1"}

            def establish_signup_session(self):
                return {"ok": True, "flow_kind": "login"}

            def close(self):
                pass

        password_info = {"ok": True, "status": 200, "json": {"page": {"type": "email_otp_verification"}, "continue_url": f"{register_core.auth_base}/email-verification"}, "final_url": f"{register_core.auth_base}/api/accounts/password/verify"}

        with patch.object(reauth, "get_account", return_value=dict(account)), \
             patch.object(reauth, "upsert_account", side_effect=lambda item: item), \
             patch.object(reauth, "PlatformRegistrar", DummyRegistrar), \
             patch.object(reauth, "_start_cpa_oauth", return_value={"authorize_url": f"{register_core.auth_base}/oauth/authorize?state=state-1", "state": "state-1"}), \
             patch.object(reauth, "_attempt_password_login", return_value=password_info), \
             patch.object(reauth, "_handle_email_otp_step", return_value=("http://localhost:1455/auth/callback?code=cb&state=state-1", {"ok": True, "status": 200, "json": {}}, {"email_code_received": True})) as mock_email_otp, \
             patch.object(reauth, "_send_login_otp", side_effect=AssertionError("email otp page should not use legacy send endpoint")), \
             patch.object(reauth, "_submit_callback_to_cpa", return_value={"ok": True, "message": "CPA callback submitted"}), \
             patch.object(reauth, "_finalize_cpa_submit_with_optional_local_tokens", return_value=reauth.ReauthorizeAutoOutcome(ok=True, message="CPA callback submitted", callback_url="http://localhost:1455/auth/callback?code=cb&state=state-1", codex2api_import_submit_ok=True)):
            result = reauth.auto_reauthorize_account_with_email_otp(
                "acc-1",
                codex2api_url="http://127.0.0.1:8317",
                codex2api_admin_key="key",
            )

        self.assertTrue(result.ok)
        self.assertTrue(mock_email_otp.called)

    def test_reauthorize_mail_wait_config_uses_account_provider_and_webui_icloud_credentials(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "host": "icloud.com"},
        }
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(reauth, "DATA_DIR", Path(tmpdir)):
            Path(tmpdir, "webui_config.json").write_text(
                json.dumps(
                    {
                        "register": {
                            "mail_type": "icloud",
                            "icloud_email": "other@icloud.com",
                            "icloud_imap_user": "owner@icloud.com",
                            "icloud_imap_password": "app-pass",
                            "icloud_host": "icloud.com",
                        }
                    }
                ),
                encoding="utf-8",
            )

            cfg = reauth._mail_wait_config_for_account(
                account,
                account["mailbox"],
                proxy="http://127.0.0.1:7890",
                wait_timeout=9,
                wait_interval=3,
                request_timeout=11,
            )

        self.assertEqual(cfg.proxy, "http://127.0.0.1:7890")
        self.assertEqual(cfg.mail.wait_timeout, 9)
        self.assertEqual(cfg.mail.wait_interval, 3)
        self.assertEqual(cfg.mail.request_timeout, 11)
        provider = cfg.mail.providers[0]
        self.assertEqual(provider["type"], "icloud")
        self.assertEqual(provider["email"], "alias@icloud.com")
        self.assertEqual(provider["imap_user"], "owner@icloud.com")
        self.assertEqual(provider["imap_password"], "app-pass")

    def test_reauthorize_bind_mail_config_appends_cloudflare_fallback_for_icloud(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "host": "icloud.com"},
        }
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmpdir, patch.object(reauth, "DATA_DIR", Path(tmpdir)):
            Path(tmpdir, "webui_config.json").write_text(
                json.dumps(
                    {
                        "register": {
                            "mail_type": "icloud",
                            "icloud_imap_user": "owner@icloud.com",
                            "icloud_imap_password": "app-pass",
                            "cf_temp_base_url": "https://mail.cf.test",
                            "cf_temp_admin_auth": "admin-secret",
                            "cf_temp_domain": "cf.test",
                        }
                    }
                ),
                encoding="utf-8",
            )

            cfg = reauth._bind_mail_config_for_account(
                account,
                account["mailbox"],
                proxy="",
                wait_timeout=9,
                wait_interval=3,
                request_timeout=11,
            )

        self.assertEqual([item["type"] for item in cfg["providers"]], ["icloud", "cloudflare-temp-email"])
        self.assertEqual(cfg["providers"][1]["base_url"], "https://mail.cf.test")
        self.assertEqual(cfg["providers"][1]["admin_auth"], "admin-secret")
        self.assertEqual(cfg["providers"][1]["domain"], "cf.test")

    def test_handle_email_otp_waits_with_account_mail_provider_config(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }
        wait_configs = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(config, mailbox):
            wait_configs.append(config)
            return "123456"

        with patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_validate_login_otp", return_value={"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        provider = wait_configs[0].mail.providers[0]
        self.assertEqual(provider["type"], "icloud")
        self.assertEqual(provider["imap_user"], "owner@icloud.com")
        self.assertEqual(provider["imap_password"], "app-pass")

    def test_handle_email_otp_discards_stale_quick_check_code(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }
        wait_codes = [("836889", 1000), ("224466", 9999999999999)]
        submitted_codes = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(_config, mailbox):
            code, received_at_ms = wait_codes.pop(0)
            mailbox["_last_code_meta"] = {"received_at_ms": received_at_ms}
            return code

        def fake_validate(_registrar, _state, code):
            submitted_codes.append(code)
            return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}

        with patch.object(reauth.time, "time", return_value=2000), \
             patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_validate_login_otp", side_effect=fake_validate), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        self.assertEqual(submitted_codes, ["224466"])

    def test_handle_email_otp_accepts_code_with_small_timestamp_skew(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }
        submitted_codes = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(_config, mailbox):
            mailbox["_last_code_meta"] = {"received_at_ms": 1998900}
            return "906465"

        def fake_validate(_registrar, _state, code):
            submitted_codes.append(code)
            return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}

        with patch.object(reauth.time, "time", return_value=2000), \
             patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_validate_login_otp", side_effect=fake_validate), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        self.assertEqual(submitted_codes, ["906465"])

    def test_handle_email_otp_preserves_pre_authorize_threshold(self):
        account = {
            "id": "acc-1",
            "email": "alias@cf.test",
            "password": "pw",
            "mailbox": {"provider": "cloudflare-temp-email", "email": "alias@cf.test", "_code_after_ts": 990000},
        }
        submitted_codes = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(_config, mailbox):
            mailbox["_last_code_meta"] = {"received_at_ms": 995000}
            return "764914"

        def fake_validate(_registrar, _state, code):
            submitted_codes.append(code)
            return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}

        with patch.object(reauth.time, "time", return_value=1000), \
             patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_validate_login_otp", side_effect=fake_validate), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        self.assertEqual(submitted_codes, ["764914"])
        self.assertEqual(account["mailbox"]["_code_after_ts"], 990000)

    def test_handle_email_otp_keeps_initial_threshold_across_resend_attempts(self):
        account = {
            "id": "acc-1",
            "email": "alias@cf.test",
            "password": "pw",
            "mailbox": {"provider": "cloudflare-temp-email", "email": "alias@cf.test"},
        }
        wait_codes = [("", 0), ("333444", 1010000)]
        submitted_codes = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(_config, mailbox):
            code, received_at_ms = wait_codes.pop(0)
            if code:
                mailbox["_last_code_meta"] = {"received_at_ms": received_at_ms}
            return code

        def fake_validate(_registrar, _state, code):
            submitted_codes.append(code)
            return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}

        with patch.object(reauth.time, "time", side_effect=[1000, 1015, 1020]), \
             patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_enter_login_email_otp_step", return_value={"ok": True, "status": 200, "final_url": "https://auth.openai.com/log-in/email-verification"}), \
             patch.object(reauth, "_submit_login_email_otp_page_form", side_effect=AssertionError("page form should be skipped")), \
             patch.object(reauth, "_trigger_passwordless_login_otp", return_value={"ok": False, "status": 404, "attempt": "passwordless_login_send_otp"}), \
             patch.object(reauth, "_send_login_otp", return_value={"ok": True, "status": 500, "attempt": "remix:email_otp_send"}), \
             patch.object(reauth, "_validate_login_otp", side_effect=fake_validate), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        self.assertEqual(submitted_codes, ["333444"])
        self.assertEqual(account["mailbox"]["_code_after_ts"], 1000000)
        self.assertEqual(wait_codes, [])

    def test_handle_email_otp_discards_code_without_received_time(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }
        wait_codes = [("665270", 0), ("775511", 9999999999999)]
        submitted_codes = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        def fake_wait(_config, mailbox):
            code, received_at_ms = wait_codes.pop(0)
            mailbox["_last_code_meta"] = {"received_at_ms": received_at_ms}
            return code

        def fake_validate(_registrar, _state, code):
            submitted_codes.append(code)
            return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}}

        with patch.object(reauth.time, "time", return_value=2000), \
             patch.object(reauth, "wait_for_code", side_effect=fake_wait), \
             patch.object(reauth, "_validate_login_otp", side_effect=fake_validate), \
             patch.object(reauth, "_resolve_callback_step", return_value="http://localhost:1455/auth/callback?code=cb&state=state-1"):
            callback, _validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "http://localhost:1455/auth/callback?code=cb&state=state-1")
        self.assertEqual(submitted_codes, ["775511"])
        self.assertEqual(account["mailbox"]["_exclude_codes"], ["665270"])

    def test_handle_email_otp_returns_immediately_for_phone_verification(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        validate_info = {
            "ok": True,
            "status": 200,
            "json": {"page": {"type": "phone_otp_send"}, "continue_url": "https://auth.openai.com/api/accounts/phone-otp/send"},
            "final_url": "https://auth.openai.com/api/accounts/email-otp/validate",
        }

        with patch.object(reauth.time, "time", return_value=2000), \
             patch.object(reauth, "wait_for_code", return_value="123456"), \
             patch.object(reauth, "_validate_login_otp", return_value=validate_info), \
             patch.object(reauth, "_resolve_consent_callback_direct", side_effect=AssertionError("phone OTP must not run consent probing")), \
             patch.object(reauth, "_resolve_callback_step", side_effect=AssertionError("phone OTP must return before callback probing")):
            callback, returned_validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "")
        self.assertIs(returned_validate_info, validate_info)

    def test_handle_email_otp_does_not_probe_consent_for_about_you(self):
        account = {
            "id": "acc-1",
            "email": "alias@icloud.com",
            "password": "pw",
            "mailbox": {"provider": "icloud", "email": "alias@icloud.com", "imap_user": "owner@icloud.com", "imap_password": "app-pass"},
        }

        class DummyRegistrar:
            last_authorize = {"state": "state-1"}

        validate_info = {
            "ok": True,
            "status": 200,
            "json": {"page": {"type": "about_you"}, "continue_url": "https://auth.openai.com/about-you"},
            "final_url": "https://auth.openai.com/api/accounts/email-otp/validate",
        }

        with patch.object(reauth.time, "time", return_value=2000), \
             patch.object(reauth, "wait_for_code", return_value="123456"), \
             patch.object(reauth, "_validate_login_otp", return_value=validate_info), \
             patch.object(reauth, "_resolve_consent_callback_direct", side_effect=AssertionError("about-you must not run consent probing")), \
             patch.object(reauth, "_resolve_callback_step", side_effect=AssertionError("about-you must return before callback probing")):
            callback, returned_validate_info, _debug = reauth._handle_email_otp_step(
                DummyRegistrar(),
                account,
                account["mailbox"],
                "state-1",
                proxy="",
                wait_timeout=60,
                wait_interval=2,
                request_timeout=30,
            )

        self.assertEqual(callback, "")
        self.assertIs(returned_validate_info, validate_info)

    def test_send_login_otp_uses_email_verification_route_action(self):
        calls = []

        class DummyRegistrar:
            last_authorize = {"state": "state-1", "flow_kind": "login"}

            def _post_accounts_payload(self, payload, referer_path, candidates=None):
                calls.append((payload, referer_path, candidates or []))
                return {
                    "ok": True,
                    "status": 200,
                    "json": {"page": {"type": "email_otp_verification"}},
                    "text": "",
                    "final_url": f"{register_core.auth_base}/log-in/email-verification?state=state-1",
                    "attempts": [{"status": 200, "final_url": f"{register_core.auth_base}/log-in/email-verification?state=state-1"}],
                }

        info = reauth._send_login_otp(DummyRegistrar(), "state-1")

        self.assertTrue(info["ok"])
        self.assertEqual(info["attempt"], "remix:email_otp_send")
        self.assertEqual(calls[0][0]["origin_page_type"], "email_otp_send")
        self.assertIn("routes%2Flog-in%2Femail-verification", calls[0][2][0][0])

    def test_validate_login_otp_sends_state_device_and_sentinel_headers(self):
        captured = {}

        class FakeSession:
            def post(self, url, **kwargs):
                captured["url"] = url
                captured["json"] = kwargs.get("json")
                captured["headers"] = kwargs.get("headers") or {}
                return SimpleNamespace(
                    url=url,
                    status_code=200,
                    headers={},
                    text="",
                    json=lambda: {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"},
                )

        registrar = SimpleNamespace(session=FakeSession(), device_id="dev-1", last_authorize={"state": "state-1"})
        with patch.object(reauth, "build_sentinel_token", return_value="sentinel-1"):
            info = reauth._validate_login_otp(registrar, "state-1", "123456")

        self.assertTrue(info["ok"])
        self.assertEqual(captured["json"], {"code": "123456"})
        self.assertEqual(captured["headers"]["oai-device-id"], "dev-1")
        self.assertEqual(captured["headers"]["openai-sentinel-token"], "sentinel-1")
        self.assertIn("/log-in/email-verification?state=state-1", captured["headers"]["referer"])

    def test_validate_login_otp_falls_back_to_email_verification_route_action(self):
        calls = []

        class FakeSession:
            def post(self, url, **kwargs):
                return SimpleNamespace(
                    url=url,
                    status_code=400,
                    headers={},
                    text='{"error":{"code":"invalid_auth_step"}}',
                    json=lambda: {"error": {"code": "invalid_auth_step"}},
                )

        class DummyRegistrar:
            session = FakeSession()
            device_id = "dev-1"
            last_authorize = {"state": "state-1", "flow_kind": "login"}

            def _post_accounts_payload(self, payload, referer_path, candidates=None):
                calls.append((payload, referer_path, candidates or []))
                return {
                    "ok": True,
                    "status": 200,
                    "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"},
                    "text": "",
                    "final_url": f"{register_core.auth_base}/log-in/email-verification?state=state-1",
                    "attempts": [{"status": 200}],
                }

        with patch.object(reauth, "build_sentinel_token", return_value="sentinel-1"):
            info = reauth._validate_login_otp(DummyRegistrar(), "state-1", "123456")

        self.assertTrue(info["ok"])
        self.assertEqual(info["attempt"], "remix:email_otp_validate")
        self.assertEqual(calls[0][0]["origin_page_type"], "email_otp_verification")
        self.assertEqual(calls[0][0]["data"]["intent"], "validate")

    def test_attempt_password_login_keeps_oauth_state_on_remix_submit(self):
        captured = {}

        class FakeSession:
            def post(self, url, **_kwargs):
                return SimpleNamespace(url=url, status_code=404, headers={}, text="", json=lambda: {})

        class DummyRegistrar:
            session = FakeSession()
            last_authorize = {"state": "state-1"}

            def _post_accounts_payload(self, payload, referer_path, candidates=None):
                captured["payload"] = payload
                captured["referer_path"] = referer_path
                captured["candidates"] = candidates or []
                return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}, "text": "", "final_url": ""}

        info = reauth._attempt_password_login(DummyRegistrar(), "user@example.com", "pw")

        self.assertTrue(info["ok"])
        self.assertIn("/log-in/password?state=state-1", captured["referer_path"])
        self.assertTrue(any("state=state-1" in url for url, _mode in captured["candidates"]))
        self.assertEqual(captured["payload"]["origin_page_type"], "login_password")
        self.assertEqual(captured["payload"]["data"]["username"], {"kind": "email", "value": "user@example.com"})

    def test_post_accounts_payload_uses_auth_sentinel_for_login_email_otp(self):
        captured = {}

        class FakeSession:
            def request(self, _method, url, **kwargs):
                captured["headers"] = kwargs.get("headers") or {}
                return SimpleNamespace(url=url, status_code=200, headers={}, text="", json=lambda: {})

        registrar = register_core.PlatformRegistrar("")
        registrar.session = FakeSession()
        registrar.last_authorize = {"state": "state-1", "flow_kind": "login"}
        registrar.sentinel_tokens = {"auth": "auth-token", "signup": "signup-token"}

        info = registrar._post_accounts_payload(
            {"origin_page_type": "email_otp_send"},
            "/log-in/email-verification?state=state-1",
            candidates=[(f"{register_core.auth_base}/log-in/email-verification", "json")],
        )

        self.assertTrue(info["ok"])
        self.assertEqual(captured["headers"]["OpenAI-Sentinel-Token"], "auth-token")

    def test_attempt_password_login_uses_phone_number_username_kind(self):
        captured = {}

        class FakeSession:
            def post(self, url, **_kwargs):
                return SimpleNamespace(url=url, status_code=404, headers={}, text="", json=lambda: {})

        class DummyRegistrar:
            session = FakeSession()
            last_authorize = {"state": "state-1"}

            def _post_accounts_payload(self, payload, referer_path, candidates=None):
                captured["payload"] = payload
                return {"ok": True, "status": 200, "json": {"continue_url": "http://localhost:1455/auth/callback?code=cb&state=state-1"}, "text": "", "final_url": ""}

        info = reauth._attempt_password_login(DummyRegistrar(), "+573144817836", "pw")

        self.assertTrue(info["ok"])
        self.assertEqual(captured["payload"]["data"]["username"], {"kind": "phone_number", "value": "+573144817836"})

    def test_trigger_passwordless_login_otp_uses_state_referer(self):
        captured = {}

        class FakeSession:
            def post(self, url, **kwargs):
                captured["url"] = url
                captured["headers"] = kwargs.get("headers") or {}
                return SimpleNamespace(url=url, status_code=200, headers={}, text="", json=lambda: {})

        registrar = SimpleNamespace(session=FakeSession(), last_authorize={"state": "state-1"})

        info = reauth._trigger_passwordless_login_otp(registrar)

        self.assertTrue(info["ok"])
        self.assertIn("/log-in/password?state=state-1", captured["headers"]["referer"])


if __name__ == "__main__":
    unittest.main()
