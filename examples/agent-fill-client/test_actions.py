"""Exercise approved form actions in a real private browser without observable DOM."""

import asyncio
import json
import secrets
import unittest
from html import escape
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from browser_broker import BrokerError, BrowserBroker, validate_config
from test_mcp import config


def action_config():
    data = config()
    data["sites"]["example"]["actions"] = {
        "save-note": {
            "url": "https://login.example.test/workspace",
            "fields": {"note": "#note"},
            "submit_selector": "#save",
            "success_path": "/workspace",
            "success_selector": "#workspace",
        },
        "sign-out": {
            "url": "https://login.example.test/account",
            "fields": {},
            "submit_selector": "#logout",
            "success_path": "/logout",
            "success_selector": "#pass",
        },
    }
    return data


class ActionConfigTests(unittest.TestCase):
    def test_legacy_and_named_action_profiles_remain_valid(self):
        validate_config(config())
        validate_config(action_config())

    def test_proxy_rule_metacharacters_cannot_expand_an_approved_origin(self):
        for host in [
            "*.example.test",
            ".example.test",
            "example.test,other.test",
            "example%2ctest",
        ]:
            data = config()
            data["sites"]["example"]["login_url"] = "https://" + host + "/login"
            with self.subTest(host=host), self.assertRaises(BrokerError):
                validate_config(data)

    def test_unknown_fields_and_cross_origin_action_urls_are_rejected(self):
        for change in [
            {"url": "https://other.example.test/workspace"},
            {"url": "https://login.example.test/workspace?secret=fixture"},
            {"script": "document.cookie"},
            {"fields": {"note": ""}},
            {"fields": {"__proto__": "#note"}},
        ]:
            data = action_config()
            data["sites"]["example"]["actions"]["save-note"].update(change)
            with self.subTest(change=change), self.assertRaises(BrokerError):
                validate_config(data)


class BrowserActionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from playwright.async_api import async_playwright

        self.engine = await async_playwright().start()
        self.browser = await self.engine.chromium.launch(
            headless=True, chromium_sandbox=True
        )
        self.context = await self.browser.new_context()
        self.secret = secrets.token_urlsafe(32)
        self.note = ""
        self.posts = []
        self.authenticated = True
        self.variant = None
        self.broker = BrowserBroker(action_config())
        self.broker.browser = self.browser
        await self.context.route("**/*", self.route)
        self.page = await self.context.new_page()
        self.page.set_default_timeout(1000)
        await self.page.goto("https://login.example.test/account")
        self.broker.sessions["example"] = (self.context, self.page)

    async def asyncTearDown(self):
        await self.broker.close()
        await self.engine.stop()

    async def route(self, route):
        path = urlsplit(route.request.url).path
        if not self.authenticated and path != "/login":
            await route.fulfill(
                status=401,
                content_type="text/html",
                body="<input id='pass' type='password'>",
            )
            return
        if route.request.method == "POST":
            self.posts.append(path)
            if path == "/logout":
                self.authenticated = False
                await route.fulfill(
                    status=200,
                    content_type="text/html",
                    body="<input id='pass' type='password'>",
                )
                return
            self.note = parse_qs(route.request.post_data, keep_blank_values=True)[
                "note"
            ][0]
        if path == "/workspace":
            html = f"""<section id='workspace'><p>{self.secret}</p>
            <form method='post' action='/workspace'><textarea id='note' name='note'>{escape(self.note)}</textarea>
            <input type='hidden' name='csrf' value='{self.secret}'>
            <button id='save' type='submit'>Save</button></form></section>"""
            if self.variant:
                html = self.variant(html)
        elif path == "/login":
            html = "<input id='pass' type='password'>"
        else:
            html = """<h1 id='success'>Signed in</h1><form method='post' action='/logout'>
            <button id='logout' type='submit'>Sign out</button></form>"""
        await route.fulfill(status=200, content_type="text/html", body=html)

    async def test_save_preserves_the_task_page_and_logout_blocks_further_actions(self):
        catalog = self.broker.actions("example")
        self.assertEqual(
            catalog["actions"][0], {"action": "save-note", "fields": ["note"]}
        )
        result = await self.broker.action(
            "example", "save-note", {"note": "A nonsecret test note"}
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.note, "A nonsecret test note")
        self.assertEqual(
            (await self.broker.status("example"))["status"], "authenticated"
        )
        self.assertTrue(self.page.url.endswith("/workspace"))
        result = await self.broker.action("example", "save-note", {"note": ""})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.note, "")
        result = await self.broker.logout("example")
        self.assertEqual(result["server_logout"], "completed")
        self.assertFalse(self.authenticated)
        self.assertNotIn("example", self.broker.sessions)
        result = await self.broker.action(
            "example", "save-note", {"note": "Not permitted"}
        )
        self.assertEqual(result["status"], "not_authenticated")

    async def test_catalog_and_outputs_do_not_return_page_or_input_contents(self):
        results = [self.broker.actions("example")]
        results.append(
            await self.broker.action(
                "example", "save-note", {"note": "nonsecret-input"}
            )
        )
        results.append(await self.broker.status("example"))
        self.assertNotIn(self.secret, json.dumps(results))
        self.assertNotIn("nonsecret-input", json.dumps(results))
        self.assertNotIn("#note", json.dumps(results))

    async def test_unsafe_forms_are_rejected_before_input_or_submission(self):
        for variant in [
            lambda h: h.replace("method='post'", "method='get'"),
            lambda h: h.replace(
                "action='/workspace'", "action='https://other.example.test/'"
            ),
            lambda h: h.replace("id='note'", "id='note' style='display:none'"),
            lambda h: h.replace("<button", "<input type='password'><button"),
            lambda h: h.replace(
                "<button", "<input autocomplete='one-time-code'><button"
            ),
            lambda h: h + "<textarea id='note'></textarea>",
        ]:
            self.variant = variant
            result = await self.broker.action(
                "example", "save-note", {"note": "must-not-be-submitted"}
            )
            self.assertEqual(result["reason"], "unsafe_form")
            self.assertEqual(self.posts, [])
            self.assertEqual(self.note, "")

    async def test_form_action_mutation_after_input_is_rejected(self):
        self.variant = lambda h: (
            h
            + """<script>document.querySelector('#note').oninput=()=>{
        document.querySelector('form').action='https://other.example.test/';};</script>"""
        )
        result = await self.broker.action("example", "save-note", {"note": "nonsecret"})
        self.assertEqual(result["reason"], "unsafe_form")
        self.assertEqual(self.posts, [])

    async def test_unapproved_actions_bad_inputs_and_expired_sessions_fail_closed(self):
        self.assertEqual(
            (await self.broker.action("example", "evaluate", {}))["status"],
            "action_not_allowed",
        )
        self.assertEqual(
            (await self.broker.action("other", "save-note", {}))["status"],
            "site_not_allowed",
        )
        for values in [{}, {"note": "x", "password": "x"}, {"note": "x" * 2049}]:
            result = await self.broker.action("example", "save-note", values)
            self.assertEqual(result["reason"], "invalid_action_input")
        self.authenticated = False
        await self.page.goto("https://login.example.test/login")
        result = await self.broker.action("example", "save-note", {"note": "nonsecret"})
        self.assertEqual(result["status"], "not_authenticated")
        self.assertEqual(self.posts, [])

    async def test_private_errors_are_never_reflected(self):
        with patch.object(self.page, "goto", side_effect=RuntimeError(self.secret)):
            result = await self.broker.action(
                "example", "save-note", {"note": "nonsecret"}
            )
        self.assertEqual(result["reason"], "action_unconfirmed")
        self.assertNotIn(self.secret, json.dumps(result))

    async def test_redirect_cannot_reach_an_unapproved_loopback_service(self):
        reached = []

        async def sink(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            reached.append(True)
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(sink, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        new_context = self.browser.new_context

        async def fixture_context(**options):
            context = await new_context(**options)
            register = context.route

            async def install(pattern, guard):
                async def handle(route):
                    class SourceRoute:
                        request = route.request

                        async def continue_(self):
                            await route.fulfill(
                                status=302,
                                headers={"Location": f"http://127.0.0.1:{port}/sink"},
                            )

                        async def abort(self):
                            await route.abort()

                    await guard(SourceRoute())

                await register(pattern, handle)

            context.route = install
            return context

        self.broker.sessions.clear()
        try:
            with (
                patch.object(self.browser, "new_context", fixture_context),
                patch("browser_broker._BROWSER_TIMEOUT_MS", 500),
            ):
                result = await self.broker.login("example")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(reached, [])
        finally:
            server.close()
            await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
