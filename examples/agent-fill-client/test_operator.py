"""Check the separate confirmation channel, leases, and nonsecret metadata."""

import asyncio
import importlib.util
import json
import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from browser_broker import BrokerError, BrowserBroker, validate_config
from native_operator import approve, start_operator
from test_mcp import config
from test_native import native_config


def operator_config():
    value = native_config()
    value["operator"] = {
        "vault_origin": "https://localhost:18443",
        "email": "native@example.test",
    }
    return value


class OperatorConfigTests(unittest.TestCase):
    def test_metadata_and_mixed_provider_have_no_credentials_or_duplicate_sites(self):
        native = operator_config()
        validate_config(native)
        password = config()
        password["native"] = native
        with self.assertRaisesRegex(BrokerError, "duplicate_site"):
            validate_config(password)
        native["sites"]["native-test"] = native["sites"].pop("example")
        validate_config(password)
        broker = BrowserBroker(password)
        self.assertEqual(len(broker.sites()["sites"]), 2)
        self.assertIs(broker.operator_backend(), broker.child)
        self.assertEqual(broker.actions("native-test")["site"], "native-test")
        for bad in [
            {"vault_origin": "http://localhost:18443", "email": "native@example.test"},
            {
                "vault_origin": "https://localhost:18443/login",
                "email": "native@example.test",
            },
            {"password": "forbidden"},
        ]:
            with self.subTest(bad=bad), self.assertRaises((BrokerError, KeyError)):
                validate_config({**native, "operator": bad})

    def test_native_proxy_uses_exact_site_vault_and_resource_origins(self):
        value = BrowserBroker(operator_config())._native_proxy()["proxy"]
        self.assertEqual(value["server"], "http://127.0.0.1:0")
        self.assertEqual(
            set(value["bypass"].split(",")),
            {
                "<-loopback>",
                "https://login.example.test:443",
                "https://localhost:18443",
                "https://assets.example.test:443",
            },
        )


class OperatorProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runtime = tempfile.TemporaryDirectory()
        self.path = Path(self.runtime.name) / "operator.sock"
        self.broker = BrowserBroker(operator_config())
        self.broker.native_request = secrets.token_urlsafe(32)
        self.broker.pending["example"] = asyncio.get_running_loop().time() + 300
        self.server = await start_operator(self.path, self.broker)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        await self.broker.close()
        self.runtime.cleanup()

    async def lease(self):
        reader, writer = await asyncio.open_unix_connection(self.path)
        writer.write(b'{"method":"pending"}\n')
        await writer.drain()
        value = json.loads(await reader.readline())
        return reader, writer, value

    async def test_only_one_private_connection_leases_confirmation_and_cancel_consumes_it(
        self,
    ):
        reader, writer, value = await self.lease()
        self.assertEqual(value["status"], "needs_approval")
        self.assertEqual(set(value), {"status", "request", "site", "origin"})
        _reader2, writer2, second = await self.lease()
        self.assertEqual(second, {"status": "none"})
        writer2.close()
        await writer2.wait_closed()
        writer.write(
            json.dumps({"request": value["request"], "password": None}).encode() + b"\n"
        )
        await writer.drain()
        self.assertEqual(json.loads(await reader.readline()), {"status": "cancelled"})
        self.assertEqual(
            await approve(self.broker, value["request"], "fixture"),
            {"status": "rejected"},
        )
        self.assertFalse(self.broker.pending)
        writer.close()
        await writer.wait_closed()

    async def test_replay_expiry_and_private_failures_do_not_echo_secrets(self):
        token = self.broker.native_request
        self.assertEqual(
            await approve(self.broker, "wrong", "fixture"), {"status": "rejected"}
        )
        self.broker.pending["example"] = 0
        self.assertEqual(
            (await approve(self.broker, token, "fixture"))["reason"], "approval_expired"
        )
        self.broker.native_request = token
        self.broker.pending["example"] = asyncio.get_running_loop().time() + 300
        sentinel = secrets.token_urlsafe(40)
        result = await approve(self.broker, token, sentinel)
        self.assertEqual(
            result,
            {
                "status": "failed",
                "reason": "native_confirmation_unconfirmed",
                "phase": "provider_login",
            },
        )
        self.assertNotIn(sentinel, json.dumps(result))

    async def test_disconnected_or_malformed_confirmation_is_cancelled(self):
        reader, writer, value = await self.lease()
        writer.write(
            json.dumps(
                {
                    "request": value["request"],
                    "password": "fixture",
                    "extra": "forbidden",
                }
            ).encode()
            + b"\n"
        )
        await writer.drain()
        self.assertEqual(await reader.readline(), b"")
        self.assertFalse(self.broker.pending)
        writer.close()
        await writer.wait_closed()

    async def test_mixed_provider_delegates_model_calls(self):
        value = operator_config()
        value["sites"]["native-test"] = value["sites"].pop("example")
        parent = BrowserBroker({**config(), "native": value})
        for method, args in [
            ("login", ()),
            ("status", ()),
            ("action", ("run", {})),
            ("logout", ()),
        ]:
            with patch.object(
                parent.child, method, AsyncMock(return_value={"status": "fixture"})
            ):
                self.assertEqual(
                    await getattr(parent, method)("native-test", *args),
                    {"status": "fixture"},
                )
        await parent.close()


class ConnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "connect",
            Path(__file__).resolve().parents[2] / "tools/agent-mcp-connect.py",
        )
        cls.connect = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.connect)

    def test_only_fixed_https_metadata_may_name_the_native_dialog(self):
        value = {
            "status": "needs_approval",
            "site": "native-test",
            "request": secrets.token_urlsafe(32),
            "origin": "https://agent-test.bo0lean.com",
        }
        self.assertEqual(self.connect.approval_origin(value), value["origin"])
        for invalid in [
            "http://site.test",
            "https://site.test/path",
            "https://user:pass@site.test",
            "https://site.test?token=fixture",
            "https://site.test\nFake prompt",
        ]:
            self.assertIsNone(
                self.connect.approval_origin({**value, "origin": invalid})
            )
        self.assertIsNone(
            self.connect.approval_origin({**value, "password": "forbidden"})
        )

    def test_confirmation_detects_only_fixed_mcp_status(self):
        self.assertTrue(
            self.connect.needs_confirmation(
                {"result": {"structuredContent": {"status": "needs_approval"}}}
            )
        )
        self.assertTrue(
            self.connect.needs_confirmation(
                {
                    "result": {
                        "content": [
                            {"type": "text", "text": '{"status":"needs_approval"}'}
                        ]
                    }
                }
            )
        )
        self.assertFalse(
            self.connect.needs_confirmation(
                {"result": {"structuredContent": {"status": "authenticated"}}}
            )
        )


class PrivateDialogTests(unittest.IsolatedAsyncioTestCase):
    async def test_password_uses_only_the_private_ssh_pipe_and_cancel_sends_null(self):
        from types import SimpleNamespace
        from unittest.mock import Mock

        connect = ConnectTests.connect
        for cancelled in (False, True):
            secret = secrets.token_urlsafe(40)
            pending = {
                "status": "needs_approval",
                "site": "native-test",
                "request": secrets.token_urlsafe(32),
                "origin": "https://agent-test.bo0lean.com",
            }
            stream = asyncio.StreamReader()
            stream.feed_data(
                json.dumps(pending).encode() + b"\n" + b'{"status":"authenticated"}\n'
            )
            writer = SimpleNamespace(write=Mock(), drain=AsyncMock())
            ssh = SimpleNamespace(stdin=writer, stdout=stream, returncode=0)
            dialog = SimpleNamespace(
                communicate=AsyncMock(return_value=((secret + "\n").encode(), b"")),
                returncode=1 if cancelled else 0,
            )
            with (
                patch.object(connect, "ssh_arguments", return_value=["private-ssh"]),
                patch.object(
                    connect.asyncio,
                    "create_subprocess_exec",
                    AsyncMock(side_effect=[ssh, dialog]),
                ) as create,
            ):
                await connect.confirm(Path("/unused"), "broker@example.test")
            message = json.loads(writer.write.call_args.args[0])
            self.assertEqual(message["password"], None if cancelled else secret)
            self.assertEqual(message["request"], pending["request"])
            # Neither native process argv nor environment carries the input.
            self.assertNotIn(secret, repr(create.call_args_list))


if __name__ == "__main__":
    unittest.main()
