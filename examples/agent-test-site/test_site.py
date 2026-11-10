"""Exercise the owned RP's HTTP/session boundaries without personal credentials."""

import secrets
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent_test_site import COOKIE, create_app, database
from starlette.testclient import TestClient
from webauthn.helpers.exceptions import WebAuthnException

ORIGIN = "https://agent-test.example.test"


class SiteTests(unittest.TestCase):
    def setUp(self):
        self.runtime = tempfile.TemporaryDirectory()
        self.path = Path(self.runtime.name) / "site.sqlite3"
        self.app = create_app(ORIGIN, self.path)
        self.client = TestClient(self.app, base_url=ORIGIN, follow_redirects=False)
        self.username = "test_" + secrets.token_hex(8)
        self.password = secrets.token_urlsafe(32)
        self.headers = {"Origin": ORIGIN}

    def tearDown(self):
        self.client.close()
        self.runtime.cleanup()

    def test_workspace_requires_login_and_persists_only_this_accounts_note(self):
        self.assertEqual(self.client.get("/workspace").status_code, 303)
        self.assertEqual(
            self.client.post(
                "/workspace", data={"note": "no"}, headers=self.headers
            ).status_code,
            401,
        )
        self.register()
        note = "Nonsecret <test> note"
        response = self.client.post(
            "/workspace", data={"note": note}, headers=self.headers
        )
        self.assertEqual(response.status_code, 303)
        self.assertIn("Nonsecret &lt;test&gt; note", self.client.get("/workspace").text)
        with TestClient(self.app, base_url=ORIGIN, follow_redirects=False) as other:
            response = other.post(
                "/register",
                data={
                    "username": "other_" + secrets.token_hex(6),
                    "password": self.password,
                },
                headers=self.headers,
            )
            self.assertEqual(response.status_code, 303)
            self.assertNotIn(
                "Nonsecret &lt;test&gt; note", other.get("/workspace").text
            )
            self.assertEqual(
                other.post(
                    "/workspace/check", data={"expected": note}, headers=self.headers
                ).status_code,
                409,
            )
        with database(self.path) as db:
            self.assertEqual(
                db.execute("SELECT value FROM workspace_notes").fetchone()[0], note
            )
        response = self.client.post(
            "/workspace/check", data={"expected": note}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn('id="note-matches"', response.text)
        response = self.client.post(
            "/workspace/check", data={"expected": "other note"}, headers=self.headers
        )
        self.assertEqual(response.status_code, 409)
        response = self.client.post(
            "/workspace", data={"note": ""}, headers=self.headers
        )
        self.assertEqual(response.status_code, 303)
        with database(self.path) as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM workspace_notes").fetchone()[0], 0
            )
        response = self.client.post(
            "/workspace/check", data={"expected": ""}, headers=self.headers
        )
        self.assertEqual(response.status_code, 200)

    def test_workspace_rejects_untrusted_origin_and_invalid_data_without_reflection(
        self,
    ):
        self.register()
        sentinel = secrets.token_urlsafe(32)
        response = self.client.post(
            "/workspace",
            json={"note": sentinel},
            headers={"Origin": "https://other.example.test"},
        )
        self.assertEqual(response.status_code, 403)
        for data in [
            {"note": sentinel * 100},
            {"note": {"private": sentinel}},
            {"note": sentinel, "extra": sentinel},
        ]:
            response = self.client.post("/workspace", json=data, headers=self.headers)
            self.assertEqual(response.status_code, 400)
            self.assertNotIn(sentinel, response.text)

    def register(self):
        response = self.client.post(
            "/register",
            data={"username": self.username, "password": self.password},
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 303)
        return response

    def test_password_login_cookie_retention_and_logout(self):
        response = self.register()
        cookie = response.headers["set-cookie"].lower()
        for marker in ["secure", "httponly", "samesite=strict", "path=/"]:
            self.assertIn(marker, cookie)
        self.assertNotIn("domain=", cookie)
        for _ in range(2):
            profile = self.client.get("/profile")
            self.assertEqual(profile.status_code, 200)
            self.assertIn(self.username, profile.text)
            self.assertNotIn(self.password, profile.text)
        self.client.post("/logout", headers=self.headers)
        self.assertEqual(self.client.get("/profile").status_code, 303)
        bad = self.client.post(
            "/login",
            data={"username": self.username, "password": secrets.token_urlsafe(24)},
            headers=self.headers,
        )
        self.assertEqual(bad.status_code, 401)
        self.assertNotIn(self.password, bad.text)
        self.assertEqual(
            self.client.post(
                "/login",
                data={"username": self.username, "password": self.password},
                headers=self.headers,
            ).status_code,
            303,
        )
        self.assertEqual(self.client.get("/profile").status_code, 200)

    def test_state_changes_require_exact_origin(self):
        for origin in [
            None,
            "https://attacker.example.test",
            ORIGIN + ".attacker.test",
        ]:
            response = self.client.post(
                "/register",
                json={"username": self.username, "password": self.password},
                headers={} if origin is None else {"Origin": origin},
            )
            self.assertEqual(response.status_code, 403)
            self.assertNotIn(self.password, response.text)

    def test_registration_is_bound_to_authenticated_user(self):
        self.assertEqual(
            self.client.post("/registration/options", headers=self.headers).status_code,
            401,
        )
        self.register()
        response = self.client.post("/registration/options", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        options = response.json()
        self.assertEqual(options["timeout"], 300000)
        self.assertEqual(options["rp"]["id"], "agent-test.example.test")
        self.assertEqual(options["user"]["name"], self.username)
        self.assertEqual(options["authenticatorSelection"]["residentKey"], "required")
        self.assertEqual(
            options["authenticatorSelection"]["userVerification"], "required"
        )

    def test_challenge_is_consumed_once_even_when_proof_is_invalid(self):
        self.register()
        self.client.post("/registration/options", headers=self.headers)
        invalid = self.client.post(
            "/registration/verification", json={}, headers=self.headers
        )
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.json(), {"verified": False})
        replay = self.client.post(
            "/registration/verification", json={}, headers=self.headers
        )
        self.assertEqual(replay.json(), {"error": "challenge_unavailable"})

    def test_expired_and_foreign_session_challenges_are_rejected(self):
        self.register()
        self.client.post("/registration/options", headers=self.headers)
        with database(self.path) as db:
            db.execute("UPDATE challenges SET expires=0")
        expired = self.client.post(
            "/registration/verification", json={}, headers=self.headers
        )
        self.assertEqual(expired.json(), {"error": "challenge_unavailable"})
        self.client.post("/registration/options", headers=self.headers)
        with TestClient(self.app, base_url=ORIGIN) as stranger:
            result = stranger.post(
                "/registration/verification", json={}, headers=self.headers
            )
            self.assertEqual(result.status_code, 401)

    def test_discoverable_authentication_requires_uv(self):
        response = self.client.post("/authentication/options", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["userVerification"], "required")
        self.assertEqual(response.json()["rpId"], "agent-test.example.test")
        self.assertIn(COOKIE, self.client.cookies)
        bad = self.client.post(
            "/authentication/verification", json={}, headers=self.headers
        )
        self.assertEqual(bad.json(), {"verified": False})
        self.assertEqual(self.client.get("/profile").status_code, 303)

    def test_private_confirmation_window_matches_browser_and_server_expiry(self):
        start = int(time.time())
        clock = SimpleNamespace(time=lambda: start)
        with patch("agent_test_site.time", clock), patch("test_site_state.time", clock):
            options = self.client.post("/authentication/options", headers=self.headers)
            self.assertEqual(options.json()["timeout"], 300000)
            clock.time = lambda: start + 180
            invalid = self.client.post(
                "/authentication/verification", json={}, headers=self.headers
            )
            self.assertEqual(invalid.json(), {"verified": False})
            self.client.post("/authentication/options", headers=self.headers)
            clock.time = lambda: start + 480
            expired = self.client.post(
                "/authentication/verification", json={}, headers=self.headers
            )
            self.assertEqual(expired.json(), {"error": "challenge_unavailable"})

    def test_verifier_errors_do_not_echo_private_values(self):
        self.register()
        self.client.post("/registration/options", headers=self.headers)
        sentinel = secrets.token_urlsafe(40)
        with patch(
            "agent_test_site.verify_registration_response",
            side_effect=WebAuthnException(sentinel),
        ):
            result = self.client.post(
                "/registration/verification",
                json={"id": "fixture", "response": {}},
                headers=self.headers,
            )
        self.assertEqual(result.json(), {"verified": False})
        self.assertNotIn(sentinel, result.text)

    def test_request_size_and_username_are_bounded(self):
        bad = self.client.post(
            "/register",
            json={"username": "<script>", "password": self.password},
            headers=self.headers,
        )
        self.assertEqual(bad.status_code, 400)
        huge = self.client.post("/register", content=b"x" * 65537, headers=self.headers)
        self.assertEqual(huge.status_code, 413)
        self.assertNotIn(self.password, bad.text + huge.text)

    def test_origin_configuration_is_exact_https(self):
        for value in [
            "http://example.test",
            ORIGIN + "/",
            ORIGIN + "?query=1",
            "https://user@example.test",
        ]:
            with self.assertRaises(ValueError):
                create_app(value, self.path)


if __name__ == "__main__":
    unittest.main()
