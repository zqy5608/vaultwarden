"""Verify that independent MCP clients share state without exposing a browser API."""

import asyncio
import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from broker_rpc import call_broker, start_broker


class SessionFixture:
    def __init__(self):
        self.authenticated = False

    def sites(self):
        return {
            "status": "ready",
            "sites": [{"site": "example", "origin": "https://example.test"}],
        }

    async def login(self, site):
        self.authenticated = True
        return await self.status(site)

    async def status(self, site):
        return {
            "status": "authenticated" if self.authenticated else "not_authenticated",
            "site": site,
        }


class BrokerRpcTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime = tempfile.TemporaryDirectory()
        self.path = Path(self.runtime.name) / "broker.sock"
        self.broker = SessionFixture()
        self.server = await start_broker(self.path, self.broker)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.runtime.cleanup()

    async def test_independent_stdio_clients_retain_the_same_session(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        for tool in ["vault_login", "vault_status"]:
            params = StdioServerParameters(
                command=sys.executable,
                args=[
                    str(Path(__file__).with_name("agent_mcp.py")),
                    "--broker-socket",
                    str(self.path),
                ],
            )
            async with (
                stdio_client(params) as (reader, writer),
                ClientSession(reader, writer) as client,
            ):
                await client.initialize()
                result = await client.call_tool(tool, {"site": "example"})
                data = result.structured_content
                if not isinstance(data, dict):
                    data = json.loads(result.content[0].text)
                self.assertEqual(data["status"], "authenticated")
        self.assertTrue(self.broker.authenticated)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    async def test_browser_operations_and_oversized_requests_are_rejected(self):
        for request in [
            {"method": "evaluate", "script": "fetch('https://other.test')"},
            {"method": "login", "site": "a" * 5000},
        ]:
            reader, writer = await asyncio.open_unix_connection(str(self.path))
            writer.write(json.dumps(request).encode() + b"\n")
            await writer.drain()
            result = json.loads(await reader.readline())
            self.assertEqual(
                result, {"status": "failed", "reason": "broker_unavailable"}
            )
            writer.close()
            await writer.wait_closed()
        self.assertFalse(self.broker.authenticated)

    async def test_private_errors_are_not_returned(self):
        sentinel = secrets.token_urlsafe(40)
        with patch.object(self.broker, "login", side_effect=RuntimeError(sentinel)):
            response = await call_broker(self.path, "login", "example")
        self.assertNotIn(sentinel, json.dumps(response))
        self.assertEqual(response["reason"], "broker_unavailable")

    async def test_existing_socket_and_public_parent_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "private_unused_socket_required"):
            await start_broker(self.path, self.broker)
        os.chmod(self.path.parent, 0o755)
        with self.assertRaisesRegex(ValueError, "private_unused_socket_required"):
            await start_broker(self.path.with_name("second.sock"), self.broker)


if __name__ == "__main__":
    unittest.main()
