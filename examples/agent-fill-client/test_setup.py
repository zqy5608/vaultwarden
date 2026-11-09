"""Check real account-key unwrapping and non-echoing operator configuration."""

from __future__ import annotations

import base64
import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent_mcp import setup, unlock_user_key
from browser_broker import BrokerError, read_config
from bw_kdf import derive_master_key, master_password_hash, stretch_master_key
from publish_uri import VaultResponse
from test_client import encstring_type2
from test_mcp import config


class SetupTests(unittest.TestCase):
    def test_account_key_is_unwrapped_independently_of_cli_session(self):
        password = "fixture-master-password"
        account_key = bytes(range(64))
        unrelated_session = base64.b64encode(bytes(range(64, 128))).decode()
        email = "operator@example.test"
        master = derive_master_key(password, email, 0, 2)
        wrapping = stretch_master_key(master)
        blob = encstring_type2(wrapping[:32], wrapping[32:], bytes(16), account_key)

        def request(base, method, path, **kwargs):
            self.assertEqual(base, "https://vault.example.test")
            if path.endswith("prelogin"):
                return VaultResponse(200, {"kdf": 0, "kdfIterations": 2})
            self.assertEqual(path, "/identity/connect/token")
            self.assertEqual(
                kwargs["form"]["password"], master_password_hash(master, password)
            )
            self.assertNotEqual(kwargs["form"]["password"], password)
            return VaultResponse(
                200, {"access_token": "fixture-user-token", "Key": blob}
            )

        output = io.StringIO()
        with (
            patch("publish_uri.vault_request", request),
            patch.dict(os.environ, {"BW_SESSION": unrelated_session}),
            redirect_stderr(output),
        ):
            value = unlock_user_key("https://vault.example.test/", email, password)
        self.assertEqual(base64.b64decode(value), account_key)
        self.assertNotEqual(value, unrelated_session)
        self.assertNotIn(password, output.getvalue())
        self.assertNotIn(value, output.getvalue())

    def test_setup_persists_scoped_credentials_and_key_only(self):
        data = config()
        master_password = "fixture-master-password"
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "private/config.json"
            sites = Path(root) / "sites.json"
            sites.write_text(json.dumps(data["sites"]))
            args = [
                "setup",
                "--sites",
                str(sites),
                "--config",
                str(target),
                "--headless",
            ]
            output = io.StringIO()
            with (
                patch("sys.argv", args),
                patch("os.isatty", return_value=True),
                patch(
                    "builtins.input",
                    side_effect=[
                        data["server_url"],
                        "operator@example.test",
                        data["fill_agent_id"],
                    ],
                ),
                patch(
                    "getpass.getpass",
                    side_effect=[
                        master_password,
                        data["agent_token"],
                        data["fill_token"],
                    ],
                ),
                patch(
                    "agent_mcp.unlock_user_key", return_value=data["user_key"]
                ) as unlock,
                redirect_stdout(output),
                redirect_stderr(output),
            ):
                setup()
            unlock.assert_called_once_with(
                data["server_url"], "operator@example.test", master_password
            )
            self.assertEqual(read_config(target), data)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)
            self.assertNotIn(master_password, target.read_text())
            for secret in [
                master_password,
                data["agent_token"],
                data["fill_token"],
                data["user_key"],
            ]:
                self.assertNotIn(secret, output.getvalue())

    def test_existing_config_is_not_overwritten_or_unlocked(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "config.json"
            target.write_text("existing")
            with (
                patch(
                    "sys.argv", ["setup", "--sites", "unused", "--config", str(target)]
                ),
                patch("os.isatty", return_value=True),
                patch("builtins.input") as prompt,
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                setup()
            prompt.assert_not_called()
            self.assertEqual(target.read_text(), "existing")

    def test_private_terminal_is_required(self):
        with (
            patch("sys.argv", ["setup", "--sites", "unused"]),
            patch("os.isatty", return_value=False),
            patch("getpass.getpass") as prompt,
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            setup()
        prompt.assert_not_called()

    def test_reflected_login_errors_do_not_escape(self):
        sentinel = "fixture-reflected-secret"
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "config.json"
            output = io.StringIO()
            with (
                patch(
                    "sys.argv", ["setup", "--sites", "unused", "--config", str(target)]
                ),
                patch("os.isatty", return_value=True),
                patch(
                    "builtins.input",
                    side_effect=["https://vault.example.test", "operator@example.test"],
                ),
                patch("getpass.getpass", return_value=sentinel),
                patch("publish_uri.login", side_effect=RuntimeError(sentinel)),
                redirect_stderr(output),
                self.assertRaises(SystemExit),
            ):
                setup()
            self.assertNotIn(sentinel, output.getvalue())
            self.assertFalse(target.exists())

    def test_server_origin_is_checked_before_authentication(self):
        with patch("publish_uri.login") as login:
            for server in [
                "https://vault.example.test/path",
                "http://vault.example.test",
                "https://user:password@vault.example.test",
            ]:
                with self.subTest(server=server), self.assertRaises(BrokerError):
                    unlock_user_key(server, "operator@example.test", "fixture-password")
            login.assert_not_called()

    def test_ssh_launcher_rejects_requested_commands_without_echoing_them(self):
        launcher = Path(__file__).resolve().parents[2] / "tools/agent-mcp-ssh.sh"
        sentinel = "fixture-command-must-not-be-echoed"
        result = subprocess.run(
            ["/bin/sh", str(launcher)],
            env={"SSH_ORIGINAL_COMMAND": sentinel},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("only supports MCP stdio", result.stderr)
        self.assertNotIn(sentinel, result.stderr)

    def test_ssh_launcher_always_uses_the_shared_broker(self):
        source = Path(__file__).resolve().parents[2] / "tools/agent-mcp-ssh.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable, launcher = (root / name for name in ("mcp", "launcher"))
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            executable.chmod(0o700)
            launcher.write_text(
                source.read_text().replace(
                    "/opt/vaultwarden-agent/venv/bin/vaultwarden-agent-mcp",
                    str(executable),
                )
            )
            result = subprocess.run(
                ["/bin/sh", str(launcher)], capture_output=True, text=True, check=True
            )
            self.assertEqual(
                result.stdout.splitlines(),
                ["--broker-socket", "/run/vaultwarden-agent/broker.sock"],
            )


if __name__ == "__main__":
    unittest.main()
