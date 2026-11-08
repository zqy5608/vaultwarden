"""Check credential boundaries, real DOM guards and the actual MCP stdio transport."""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from browser_broker import (
    _FORM,
    BrokerError,
    BrowserBroker,
    origin,
    read_config,
    validate_config,
)

HERE = Path(__file__).parent


def profile() -> dict:
    return {
        "item_id": "00000000-0000-4000-8000-000000000001",
        "login_url": "https://login.example.test/login",
        "username_selector": "#user",
        "password_selector": "#pass",
        "submit_selector": "#submit",
        "success_selector": "#success",
        "success_path": "/account",
    }


def config() -> dict:
    return {
        "server_url": "http://127.0.0.1:8000",
        "agent_token": "vwagent_" + "a" * 64,
        "fill_token": "vwfill_" + "b" * 64,
        "fill_agent_id": "00000000-0000-4000-8000-000000000002",
        "user_key": base64.b64encode(bytes(range(64))).decode(),
        "headless": True,
        "sites": {"example": profile()},
    }


class ConfigTests(unittest.TestCase):
    def test_valid_config(self):
        validate_config(config())
        self.assertEqual(origin("https://EXAMPLE.com:443/login"), "https://example.com")

    def test_private_file_and_missing_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "config.json"
            self.assertIsNone(read_config(path))
            path.write_text(json.dumps(config()))
            path.chmod(0o600)
            self.assertEqual(read_config(path), config())
            path.chmod(0o644)
            with self.assertRaises(BrokerError):
                read_config(path)
            alias = Path(root) / "link.json"
            alias.symlink_to(path)
            with self.assertRaises(BrokerError):
                read_config(alias)

    def test_untrusted_urls_and_roles(self):
        for url in [
            "http://login.example.test",
            "https://user:password@login.example.test",
            "file:///tmp/vault",
        ]:
            with self.subTest(url=url), self.assertRaises(BrokerError):
                origin(url)
        for field in ["agent_token", "fill_token"]:
            data = config()
            data[field] = data[
                "fill_token" if field == "agent_token" else "agent_token"
            ]
            with self.assertRaises(BrokerError):
                validate_config(data)

    def test_profile_cannot_enable_artifacts_or_supply_query_parameters(self):
        for change in [
            {"record_har_path": "/tmp/trace"},
            {"login_url": "https://example.test/login?secret=x"},
            {"success_path": "/account?token=x"},
        ]:
            data = config()
            data["sites"]["example"].update(change)
            with self.assertRaises(BrokerError):
                validate_config(data)


class CredentialTests(unittest.TestCase):
    def test_binding_and_authenticated_encryption_are_checked(self):
        data = config()
        broker = BrowserBroker(data)
        ticket = "00000000-0000-4000-8000-000000000003"
        response = {
            "ticketId": ticket,
            "itemId": profile()["item_id"],
            "origin": "https://login.example.test",
            "login": {"username": "example", "password": "plaintext"},
            "key": None,
        }

        def request(base, method, path, token, **kwargs):
            if path == "/api/agent/fills":
                self.assertEqual(token, data["agent_token"])
                return {"id": ticket}
            self.assertEqual(token, data["fill_token"])
            if path.endswith("pending"):
                return {"data": [{"id": ticket, "redeemSecret": "one-time"}]}
            return response

        with patch("browser_broker.api_request", request):
            with self.assertRaisesRegex(
                BrokerError, "authenticated_ciphertext_required"
            ):
                broker._credentials(profile())
            response["origin"] = "https://other.example.test"
            with self.assertRaisesRegex(BrokerError, "ticket_binding_failed"):
                broker._credentials(profile())
            response["origin"] = "https://login.example.test"
            response["login"]["password"] = "2.invalid"
            with self.assertRaisesRegex(BrokerError, "decryption_failed"):
                broker._credentials(profile())


class BrowserGuardTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from playwright.async_api import async_playwright

        self.engine = await async_playwright().start()
        self.browser = await self.engine.chromium.launch(
            headless=True, chromium_sandbox=True
        )
        self.context = await self.browser.new_context(service_workers="block")
        self.page = await self.context.new_page()
        self.html = """<form method='post' action='/authenticate'>
          <input id='user' name='username' autocomplete='username'><input id='pass' name='password' type='password'>
          <button id='submit' type='submit'>Log in</button></form>"""

    async def asyncTearDown(self):
        await self.browser.close()
        await self.engine.stop()

    async def load(self, html):
        await self.context.unroute_all()
        await self.context.route(
            "**/*",
            lambda route: route.fulfill(
                status=200, content_type="text/html", body=html
            ),
        )
        await self.page.goto(profile()["login_url"])

    async def guard(self, credentials=None):
        return await self.page.evaluate(
            _FORM,
            {
                "site": profile(),
                "expected": "https://login.example.test",
                "credentials": credentials,
            },
        )

    async def test_valid_form_and_atomic_submission(self):
        received = []
        secret = secrets.token_urlsafe(32)
        await self.load(self.html)
        self.assertTrue(await self.guard())
        self.page.on(
            "request",
            lambda request: (
                received.append(request.post_data) if request.method == "POST" else None
            ),
        )
        self.assertTrue(await self.guard({"username": "example", "password": secret}))
        await self.page.wait_for_url("**/authenticate")
        self.assertTrue(
            any(secret in (value or "") for value in received),
            "Form submission did not contain the synthetic value",
        )

    async def test_unsafe_forms_fail_before_filling(self):
        variants = [
            self.html.replace("method='post'", "method='get'"),
            self.html.replace(
                "action='/authenticate'", "action='https://other.example.test/steal'"
            ),
            self.html.replace("type='password'", "type='text'"),
            self.html.replace("id='pass'", "id='pass' style='display:none'"),
            self.html.replace("id='pass'", "id='pass' style='opacity:0'"),
            self.html.replace(
                "id='submit'",
                "id='submit' formaction='https://other.example.test/steal'",
            ),
            self.html.replace("id='submit'", "id='submit' formmethod='get'"),
            self.html + "<input id='pass' type='password'>",
        ]
        for html in variants:
            with self.subTest(case=variants.index(html)):
                await self.load(html)
                self.assertFalse(
                    await self.guard({"username": "example", "password": "synthetic"})
                )
                self.assertEqual(await self.page.locator("#user").input_value(), "")

    async def test_form_mutated_by_input_handler_is_rejected(self):
        html = (
            self.html
            + """<script>document.querySelector('#user').oninput = () => {
          document.querySelector('form').action='https://other.example.test/steal'; };</script>"""
        )
        await self.load(html)
        self.assertFalse(
            await self.guard({"username": "example", "password": "synthetic"})
        )
        self.assertEqual(await self.page.locator("#pass").input_value(), "")

    async def test_success_requires_origin_path_and_element(self):
        await self.load("<h1 id='success'>Signed in</h1>")
        broker = BrowserBroker(config())
        broker.sessions["example"] = (self.context, self.page)
        self.assertEqual(
            (await broker.status("example"))["status"], "not_authenticated"
        )
        await self.page.goto("https://login.example.test/account")
        self.assertEqual((await broker.status("example"))["status"], "authenticated")
        await self.page.locator("#success").evaluate("element => element.remove()")
        self.assertEqual(
            (await broker.status("example"))["status"], "not_authenticated"
        )
        await self.page.goto("https://other.example.test/account")
        self.assertEqual(
            (await broker.status("example"))["status"], "not_authenticated"
        )

    async def test_closed_private_browser_can_restart(self):
        broker = BrowserBroker(config())
        try:
            await broker._start()
            previous = broker.browser
            await previous.close()
            await broker._start()
            self.assertIsNot(previous, broker.browser)
            self.assertTrue(broker.browser.is_connected())
        finally:
            await broker.close()

    async def test_debug_output_is_rejected_before_browser_start(self):
        broker = BrowserBroker(config())
        with (
            patch.dict(os.environ, {"DEBUG": "pw:api"}),
            self.assertRaisesRegex(BrokerError, "debug_logging_disabled"),
        ):
            await broker._start()
        self.assertIsNone(broker.playwright)

    async def test_reflected_errors_and_cleanup_never_escape(self):
        secret = secrets.token_urlsafe(32)
        await self.load(self.html)
        broker = BrowserBroker(config())
        broker.browser = self.browser
        # Keep the real DOM/browser while isolating navigation from external networks.
        original_new_context = self.browser.new_context

        async def new_context(**kwargs):
            context = await original_new_context(**kwargs)
            original_route = context.route

            async def route(pattern, handler):
                await original_route(
                    pattern,
                    lambda request: request.fulfill(
                        status=200, content_type="text/html", body=self.html
                    ),
                )

            context.route = route
            return context

        async def start():
            return None

        with (
            patch.object(broker, "_start", start),
            patch.object(self.browser, "new_context", new_context),
            patch.object(broker, "_credentials", side_effect=RuntimeError(secret)),
        ):
            result = await broker.login("example")
        self.assertTrue(
            secret not in json.dumps(result),
            "A private exception reached the model boundary",
        )
        self.assertEqual(result["reason"], "vault_unavailable")

    async def test_wrong_login_never_becomes_authenticated(self):
        secret = secrets.token_urlsafe(32)
        broker = BrowserBroker(config())
        broker.browser = self.browser
        original_new_context = self.browser.new_context

        async def new_context(**kwargs):
            context = await original_new_context(**kwargs)
            original_route = context.route

            async def route(pattern, handler):
                await original_route(
                    pattern,
                    lambda request: request.fulfill(
                        status=200, content_type="text/html", body=self.html
                    ),
                )

            context.route = route
            return context

        async def start():
            return None

        with (
            patch.object(broker, "_start", start),
            patch.object(self.browser, "new_context", new_context),
            patch.object(
                broker,
                "_credentials",
                return_value={"username": "example", "password": secret},
            ),
            patch("browser_broker._BROWSER_TIMEOUT_MS", 250),
        ):
            result = await broker.login("example")
        self.assertEqual(result["reason"], "authentication_unconfirmed")
        self.assertFalse(broker.sessions)
        self.assertTrue(
            secret not in json.dumps(result), "A rejected login exposed its credential"
        )


class McpTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_stdio_catalog_and_closed_unconfigured_state(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        with (
            tempfile.TemporaryDirectory() as root,
            tempfile.TemporaryFile(mode="w+") as diagnostics,
        ):
            parameters = StdioServerParameters(
                command=sys.executable,
                args=[
                    str(HERE / "agent_mcp.py"),
                    "--config",
                    str(Path(root) / "absent.json"),
                ],
                env={"PATH": os.environ.get("PATH", "")},
            )
            async with (
                stdio_client(parameters, errlog=diagnostics) as (read, write),
                ClientSession(read, write) as client,
            ):
                await client.initialize()
                catalog = await client.list_tools()
                self.assertEqual(
                    {tool.name for tool in catalog.tools},
                    {"vault_sites", "vault_login", "vault_status"},
                )
                self.assertFalse((await client.list_resources()).resources)
                for tool in catalog.tools:
                    self.assertEqual(
                        set(tool.input_schema.get("properties", {})),
                        set() if tool.name == "vault_sites" else {"site"},
                    )
                result = await client.call_tool("vault_login", {"site": "example"})
                serialized = result.model_dump_json()
                self.assertIn("not_configured", serialized)
                self.assertNotIn("password", serialized)


if __name__ == "__main__":
    unittest.main()
