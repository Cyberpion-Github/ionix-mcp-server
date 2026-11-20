"""Hermetic unit tests for the Threat Center / action-item AI tools and fetch() error handling.

No network and no credentials: httpx is pointed at a MockTransport that records every request
and replies with a canned response, so these verify exactly what the tools send to the IONIX API
(path, query params, timeout) and what they hand back to the model.

Run locally:  uv run python -m unittest discover -s tests -p 'test_*.py'
"""

import asyncio
import contextlib
import io
import unittest
from unittest import mock

import httpx

import ionix

_REAL_CLIENT = httpx.Client
API = "https://api.portal.ionix.io/api/v1/"
POST_ID = "65a1b2c3d4e5f6a7b8c9d0e1"
AI_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


class _Recorder:
    """Swaps httpx.Client for one backed by a MockTransport returning `response`."""

    def __init__(self, response=None, exc=None):
        self.requests: list[httpx.Request] = []
        self._response = response or httpx.Response(200, json={"ok": True})
        self._exc = exc

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self._exc is not None:
            raise self._exc
        return self._response

    def __enter__(self):
        transport = httpx.MockTransport(self._handle)
        self._stack = contextlib.ExitStack()
        self._stack.enter_context(
            mock.patch.object(ionix.httpx, "Client", lambda *a, **kw: _REAL_CLIENT(transport=transport))
        )
        self._stack.enter_context(mock.patch.object(ionix, "ACCOUNT_NAME", "test-account"))
        self._stack.enter_context(mock.patch.object(ionix, "api_key", "test-key"))
        return self

    def __exit__(self, *exc_info):
        self._stack.close()

    @property
    def only(self) -> httpx.Request:
        assert len(self.requests) == 1, f"expected 1 request, got {len(self.requests)}"
        return self.requests[0]


def run(coro):
    return asyncio.run(coro)


class ThreatCenterToolsTest(unittest.TestCase):
    def test_posts_defaults_limit_and_encodes_filters(self):
        with _Recorder() as rec:
            run(ionix.get_threat_center_posts(cvss_min=7.5, has_pa=True, has_cf=False, stage=3))
        req = rec.only
        self.assertEqual(str(req.url.copy_with(query=None)), API + "threat-center/")
        params = dict(req.url.params)
        self.assertEqual(
            params,
            {"cvss_min": "7.5", "has_pa": "true", "has_cf": "false", "stage": "3", "limit": "20"},
        )

    def test_posts_clamps_limit_to_api_max(self):
        with _Recorder() as rec:
            run(ionix.get_threat_center_posts(limit=500, offset=40, search="CVE-2025-1234"))
        params = dict(rec.only.url.params)
        self.assertEqual(params["limit"], "100")
        self.assertEqual(params["offset"], "40")
        self.assertEqual(params["search"], "CVE-2025-1234")

    def test_funnel_and_totals_paths_and_params(self):
        with _Recorder() as rec:
            run(ionix.get_threat_center_funnel(include_cve_ids=True, global_filter="EMEA"))
            run(ionix.get_threat_center_totals(stage=4, published_after="2026-01-01"))
        funnel, totals = rec.requests
        self.assertEqual(funnel.url.path, "/api/v1/threat-center/funnel/")
        self.assertEqual(dict(funnel.url.params), {"include_cve_ids": "true", "global_filter": "EMEA"})
        self.assertEqual(totals.url.path, "/api/v1/threat-center/summary/")
        self.assertEqual(dict(totals.url.params), {"stage": "4", "published_after": "2026-01-01"})

    def test_post_detail_normalizes_id_and_drops_image(self):
        body = {"_id": POST_ID, "title": "CVE-X", "image": "data:image/svg+xml;base64,AAAA"}
        with _Recorder(httpx.Response(200, json=body)) as rec:
            out = run(ionix.get_threat_center_post(f"  {POST_ID.upper()} "))
        self.assertEqual(rec.only.url.path, f"/api/v1/threat-center/post/{POST_ID}/")
        self.assertNotIn("image", out)
        self.assertIn("CVE-X", out)

    def test_post_cve_data_path(self):
        with _Recorder(httpx.Response(200, json=[])) as rec:
            out = run(ionix.get_threat_center_post_cve_data(POST_ID))
        self.assertEqual(rec.only.url.path, f"/api/v1/threat-center/raw-data/{POST_ID}/")
        self.assertEqual(out, "[]")

    def test_invalid_post_id_is_rejected_without_a_request(self):
        for tool in (ionix.get_threat_center_post, ionix.get_threat_center_post_cve_data):
            with _Recorder() as rec:
                out = run(tool("CVE-2025-1234"))
            self.assertEqual(rec.requests, [])
            self.assertIn("Invalid post_id", out)


class ActionItemAIToolsTest(unittest.TestCase):
    def test_ai_roles_sends_no_params(self):
        with _Recorder(httpx.Response(200, json={"roles": ["detailed", "executive"]})) as rec:
            out = run(ionix.get_action_item_ai_roles())
        req = rec.only
        self.assertEqual(req.url.path, "/api/v1/remediation/action-items/open/detailed/ai_roles/")
        self.assertEqual(dict(req.url.params), {})
        self.assertIn("executive", out)

    def test_ai_summary_uses_long_timeout_and_returns_text(self):
        with _Recorder(httpx.Response(200, json="## What it is\nAn exposed panel.")) as rec:
            out = run(ionix.get_action_item_ai_summary(AI_ID, role="executive"))
        req = rec.only
        self.assertEqual(req.url.path, f"/api/v1/remediation/action-items/open/detailed/{AI_ID}/ai_summary/")
        self.assertEqual(dict(req.url.params), {"role": "executive"})
        self.assertEqual(req.extensions["timeout"]["read"], ionix.AI_SUMMARY_TIMEOUT_SECONDS)
        self.assertEqual(out, "## What it is\nAn exposed panel.")

    def test_ai_summary_rejects_non_uuid_without_a_request(self):
        with _Recorder() as rec:
            out = run(ionix.get_action_item_ai_summary("not-a-uuid"))
        self.assertEqual(rec.requests, [])
        self.assertIn("expected a UUID", out)


class FetchErrorHandlingTest(unittest.TestCase):
    def test_json_error_body_is_kept(self):
        resp = httpx.Response(429, json={"error": "Query limit exceeded. Please contact support."})
        with _Recorder(resp):
            data = ionix.fetch("x/")
        self.assertEqual(data["status_code"], 429)
        self.assertEqual(data["detail"], {"error": "Query limit exceeded. Please contact support."})
        self.assertIn("HTTP 429", data["error"])

    def test_html_error_body_is_dropped(self):
        resp = httpx.Response(404, text="<html>Not Found</html>", headers={"content-type": "text/html"})
        with _Recorder(resp):
            data = ionix.fetch("x/")
        self.assertEqual(data["status_code"], 404)
        self.assertNotIn("detail", data)

    def test_timeout_message_names_the_limit(self):
        with _Recorder(exc=httpx.ReadTimeout("")):
            data = ionix.fetch("x/", timeout=5)
        self.assertEqual(data, {"error": "Request to the IONIX API timed out after 5s"})

    def test_success_unchanged_and_auth_headers_sent(self):
        with _Recorder(httpx.Response(200, json={"count": 1})) as rec:
            self.assertEqual(ionix.fetch("x/"), {"count": 1})
            self.assertEqual(ionix.fetch("x/", account_name="other"), {"count": 1})
        default, override = rec.requests
        self.assertEqual(default.headers["Authorization"], "Bearer test-key")
        self.assertEqual(default.headers["X-Account-Name"], "test-account")
        self.assertEqual(override.headers["X-Account-Name"], "other")
        self.assertEqual(default.extensions["timeout"]["read"], ionix.DEFAULT_TIMEOUT_SECONDS)

    def test_fetch_never_writes_to_stdout(self):
        # stdout is the MCP stdio transport; any stray print corrupts the JSON-RPC stream.
        stdout = io.StringIO()
        with _Recorder(), contextlib.redirect_stdout(stdout):
            ionix.fetch("x/")
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
