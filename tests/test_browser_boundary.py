"""Real HTTP boundary/route tests; provider and disk mutations are stubbed."""

import ast
import http.client
import json
import sys
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from browser_boundary import BrowserBoundary  # noqa: E402


class BrowserBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.effects = []
        if (ROOT / "app.py").exists():
            import app

            passcode_patch = patch.object(app, "APP_PASSCODE", "")
            write_patch = patch.object(
                app, "add_manual_card", lambda *args: cls.effects.append(args) or {}
            )
            passcode_patch.start()
            write_patch.start()
            cls.addClassCleanup(passcode_patch.stop)
            cls.addClassCleanup(write_patch.stop)
            handler = app.FlashcardHandler
            cls.route = "/api/decks/example/cards"
        else:
            # Compile the real handler without initializing models/providers.
            tree = ast.parse((ROOT / "local_preview/local_api.py").read_text())
            node = next(
                n
                for n in tree.body
                if isinstance(n, ast.ClassDef) and n.name == "Handler"
            )
            scope = dict(
                BrowserBoundary=BrowserBoundary,
                BaseHTTPRequestHandler=BaseHTTPRequestHandler,
                json=json,
                urlparse=urlparse,
                Path=Path,
                SERVICE=SimpleNamespace(
                    ingest=lambda **kwargs: cls.effects.append(kwargs) or {}
                ),
            )
            exec(
                compile(
                    ast.Module(body=[node], type_ignores=[]), "local_api.py", "exec"
                ),
                scope,
            )
            handler = scope["Handler"]
            cls.route = "/v1/ingest/videos"
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.host = "127.0.0.1:" + str(cls.server.server_port)
        cls.origin = "http://" + cls.host

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method="POST", path=None, headers=None, body=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        conn.request(
            method,
            path or self.route,
            body=body if body is not None else ("{}" if method == "POST" else None),
            headers=headers or {},
        )
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def session_headers(self):
        status, headers, body = self.request("GET", "/browser-session")
        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        return {
            "Origin": self.origin,
            "Cookie": headers["Set-Cookie"].split(";", 1)[0],
            "X-CSRF-Token": json.loads(body)["csrf_token"],
            "Content-Type": "application/json",
        }

    def test_attacks_never_dispatch(self):
        headers = self.session_headers()
        mutations = [
            {"Origin": None},
            {"Origin": "null"},
            {"Origin": ""},
            {"Origin": "https://untrusted.example"},
            {"Origin": self.origin + "/"},
            {"Origin": "http://localhost:" + str(self.server.server_port)},
            {"Origin": "http://127.0.0.1:1"},
            {"Origin": "malformed"},
            {"Host": "attacker.example:" + str(self.server.server_port)},
            {"Host": "localhost:1"},
            {"Host": "localhost"},
            {"Host": self.host + "@attacker.example"},
            {"Sec-Fetch-Site": "cross-site"},
            {"Sec-Fetch-Site": "same-site"},
            {"Content-Type": "text/plain"},
            {"Content-Type": None},
            {"Content-Type": "application/x-www-form-urlencoded"},
            {"Content-Type": "multipart/form-data; boundary=x"},
            {"X-CSRF-Token": None},
            {"X-CSRF-Token": "wrong"},
            {"Cookie": None},
            {"Cookie": "local_browser_session=forged"},
            {"Forwarded": "host=localhost"},
            {"X-Forwarded-Host": self.host},
            {"X-Forwarded-For": "127.0.0.1"},
            {"Upgrade": "websocket"},
        ]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                candidate = headers | mutation
                candidate = {k: v for k, v in candidate.items() if v is not None}
                count = len(self.effects)
                self.assertIn(self.request(headers=candidate)[0], (403, 415))
                self.assertEqual(len(self.effects), count)

    def test_valid_session_dispatches_once(self):
        count = len(self.effects)
        self.assertIn(self.request(headers=self.session_headers())[0], (200, 201, 202))
        self.assertEqual(len(self.effects), count + 1)

    def test_login_rejects_invalid_json_and_unicode_wrong_passcode(self):
        import app

        with patch.object(app, "APP_PASSCODE", "test-only-passcode"):
            headers = self.session_headers()
            self.assertEqual(
                self.request(path="/login", headers=headers, body="[")[0], 400
            )
            self.assertEqual(
                self.request(
                    path="/login",
                    headers=headers,
                    body=json.dumps({"passcode": "錯誤"}),
                )[0],
                303,
            )

    def test_bootstrap_and_reads_reject_foreign_authority(self):
        for method in ("GET", "HEAD", "OPTIONS"):
            for headers in (
                {"Origin": "https://untrusted.example"},
                {"Host": "evil.example"},
                {"Sec-Fetch-Site": "cross-site"},
                {"Origin": "null"},
            ):
                self.assertEqual(
                    self.request(method, "/browser-session", headers)[0], 403
                )

    def test_other_mutation_methods_require_boundary(self):
        for method in ("DELETE", "PATCH", "PUT"):
            count = len(self.effects)
            self.assertEqual(self.request(method, headers={"Origin": "null"})[0], 403)
            self.assertEqual(len(self.effects), count)

    def test_token_is_bound_to_issued_session(self):
        first = self.session_headers()
        second = self.session_headers()
        first["X-CSRF-Token"] = second["X-CSRF-Token"]
        self.assertEqual(self.request(headers=first)[0], 403)

    def test_remote_authority_requires_passcode_and_valid_auth(self):
        import app
        from unittest.mock import patch

        remote = "https://cards.example"
        with patch.dict("os.environ", {"APP_TRUSTED_ORIGINS": remote}):
            self.assertEqual(
                self.request("GET", "/browser-session", {"Host": "cards.example"})[0],
                403,
            )
            with patch.object(app, "APP_PASSCODE", "test-only-passcode"):
                status, response_headers, body = self.request(
                    "GET", "/browser-session", {"Host": "cards.example"}
                )
                self.assertEqual(status, 200)
                headers = {
                    "Host": "cards.example",
                    "Origin": remote,
                    "Cookie": response_headers["Set-Cookie"].split(";", 1)[0],
                    "X-CSRF-Token": json.loads(body)["csrf_token"],
                    "Content-Type": "application/json",
                }
                self.assertEqual(self.request(headers=headers)[0], 401)
                headers["Cookie"] += (
                    "; " + app.AUTH_COOKIE + "=" + app.issue_auth_token()
                )
                self.assertEqual(self.request(headers=headers)[0], 201)

    def test_remote_proxy_headers_never_supply_authority_or_authentication(self):
        import app

        remote = "https://cards.example"
        proxy_headers = {
            "Host": "cards.example",
            "X-Forwarded-For": "100.64.0.1",
            "X-Forwarded-Host": "ignored.example",
            "X-Forwarded-Proto": "http",
        }
        with patch.dict("os.environ", {"APP_TRUSTED_ORIGINS": remote}):
            self.assertEqual(
                self.request("GET", "/browser-session", proxy_headers)[0], 403
            )
            with patch.object(app, "APP_PASSCODE", "test-only-passcode"):
                status, response_headers, body = self.request(
                    "GET", "/browser-session", proxy_headers
                )
                self.assertEqual(status, 200)
                self.assertIn("; Secure", response_headers["Set-Cookie"])
                headers = {
                    **proxy_headers,
                    "Origin": remote,
                    "Cookie": response_headers["Set-Cookie"].split(";", 1)[0],
                    "X-CSRF-Token": json.loads(body)["csrf_token"],
                    "Content-Type": "application/json",
                }
                before = len(self.effects)
                self.assertEqual(self.request(headers=headers)[0], 401)
                self.assertEqual(len(self.effects), before)
                headers["Cookie"] += (
                    "; " + app.AUTH_COOKIE + "=" + app.issue_auth_token()
                )
                for hostile in (
                    {"Host": self.host},
                    {"Host": "untrusted.example", "X-Forwarded-Host": "cards.example"},
                    {"Origin": "https://ignored.example"},
                    {"Sec-Fetch-Site": "cross-site"},
                    {"X-CSRF-Token": "wrong"},
                ):
                    self.assertEqual(self.request(headers=headers | hostile)[0], 403)
                    self.assertEqual(len(self.effects), before)
                self.assertEqual(self.request(headers=headers)[0], 201)
                self.assertEqual(len(self.effects), before + 1)

    def test_unrelated_cookies_do_not_block_session(self):
        headers = self.session_headers()
        own_cookie = headers["Cookie"]
        for unrelated in ("pref=dark mode", 'pref=bad"quote', "pref=bad\\slash"):
            for cookie in (f"{unrelated}; {own_cookie}", f"{own_cookie}; {unrelated}"):
                with self.subTest(cookie=cookie):
                    before = len(self.effects)
                    self.assertEqual(
                        self.request(headers=headers | {"Cookie": cookie})[0], 201
                    )
                    self.assertEqual(len(self.effects), before + 1)
        before = len(self.effects)
        self.assertEqual(
            self.request(headers=headers | {"Cookie": own_cookie + "; " + own_cookie})[
                0
            ],
            403,
        )
        self.assertEqual(len(self.effects), before)

    def test_duplicate_security_headers(self):
        for name in ("Host", "Origin", "Content-Type", "X-CSRF-Token"):
            conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
            conn.putrequest("POST", self.route, skip_host=True)
            for key, value in (self.session_headers() | {"Host": self.host}).items():
                conn.putheader(key, value)
            conn.putheader(name, "evil")
            conn.putheader("Content-Length", "2")
            conn.endheaders(b"{}")
            response = conn.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            conn.close()


if __name__ == "__main__":
    unittest.main()
