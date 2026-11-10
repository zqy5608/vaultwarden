"""Check encrypted deployment credentials, rotation and non-reflecting failures."""

import contextlib
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

source = Path(__file__).resolve().parents[2] / "tools/agent-automation-setup.py"
spec = importlib.util.spec_from_file_location("automation", source)
automation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(automation)


class AutomationTests(unittest.TestCase):
    def test_secret_is_piped_to_encryption_and_only_ciphertext_is_saved(self):
        secret = b"fixture-secret-must-stay-private"
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "broker-config.cred"
            with patch.object(automation.subprocess, "run") as process:
                process.return_value.stdout = b"sealed-ciphertext"
                automation.seal("broker-config", secret, target)
            args, kwargs = process.call_args
            self.assertNotIn(secret.decode(), " ".join(args[0]))
            self.assertEqual(kwargs["input"], secret)
            self.assertTrue(kwargs["capture_output"])
            self.assertEqual(target.read_bytes(), b"sealed-ciphertext")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertFalse(target.with_suffix(".next").exists())

    def test_failed_encryption_preserves_previous_credential(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "broker-config.cred"
            target.write_bytes(b"previous-sealed-ciphertext")
            with (
                patch.object(
                    automation,
                    "run",
                    side_effect=subprocess.CalledProcessError(1, "encrypt"),
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                automation.seal("broker-config", b"new-secret", target)
            self.assertEqual(target.read_bytes(), b"previous-sealed-ciphertext")
            self.assertFalse(target.with_suffix(".next").exists())

    def test_rotation_revokes_previous_ids_after_sealing_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"agent": "old-agent", "fill": "old-fill"}))
            events = []

            def issue(opener, metadata):
                metadata.update(agent="new-agent", fill="new-fill")
                return {"agent_token": "new-token"}

            with (
                patch.object(automation, "STATE", state),
                patch.object(automation, "admin_session"),
                patch.object(automation, "run", return_value=b"{}"),
                patch.object(automation, "credentials", issue),
                patch.object(automation, "validate_config"),
                patch.object(
                    automation,
                    "seal",
                    side_effect=lambda *args: events.append("sealed"),
                ),
                patch.object(
                    automation,
                    "request",
                    side_effect=lambda opener, url, *args, **kwargs: events.append(url),
                ),
            ):
                automation.change_credentials("rotate")
            self.assertEqual(
                events,
                [
                    "sealed",
                    automation.BASE + "/admin/agent/tokens/old-agent/revoke",
                    automation.BASE + "/admin/agent/fill-agents/old-fill/revoke",
                ],
            )
            self.assertEqual(
                json.loads(state.read_text()),
                {"agent": "new-agent", "fill": "new-fill"},
            )

    def test_initialization_does_not_replace_existing_state(self):
        with (
            patch.object(automation.STATE.__class__, "exists", return_value=True),
            self.assertRaises(RuntimeError),
        ):
            automation.initialize()

    def test_configure_adds_operations_without_replacing_credentials(self):
        from test_mcp import config

        data = config()
        site = data["sites"].pop("example")
        site["login_url"] = automation.SITE + "/login"
        data["sites"]["agent-test"] = site
        output = io.StringIO()
        with (
            patch.object(automation.os, "geteuid", return_value=0),
            patch.object(
                automation, "run", side_effect=[json.dumps(data).encode(), b""]
            ),
            patch.object(automation, "seal") as seal,
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(automation.main("configure"), 0)
        replacement = json.loads(seal.call_args.args[1])
        for key in ["user_key", "agent_token", "fill_token", "fill_agent_id"]:
            self.assertEqual(replacement[key], data[key])
            self.assertNotIn(data[key], output.getvalue())
        self.assertEqual(
            set(replacement["sites"]["agent-test"]["actions"]),
            {"save-note", "check-note", "sign-out"},
        )

    def test_native_metadata_is_added_without_replacing_machine_credentials(self):
        from test_mcp import config
        from test_operator import operator_config

        data = config()
        data["sites"]["agent-test"] = data["sites"].pop("example")
        data["sites"]["agent-test"]["login_url"] = automation.SITE + "/login"
        native = operator_config()
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "native.json"
            profile.write_text(json.dumps(native))
            profile.chmod(0o600)
            with (
                patch.object(automation.os, "geteuid", return_value=0),
                patch.object(
                    automation, "run", side_effect=[json.dumps(data).encode(), b""]
                ),
                patch.object(automation, "seal") as seal,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(automation.main("configure", profile), 0)
        replacement = json.loads(seal.call_args.args[1])
        self.assertEqual(replacement["native"], native)
        for key in ["user_key", "agent_token", "fill_token", "fill_agent_id"]:
            self.assertEqual(replacement[key], data[key])

    def test_private_exception_is_not_reflected(self):
        output = io.StringIO()
        with (
            patch.object(automation.os, "geteuid", return_value=0),
            patch.object(
                automation,
                "initialize",
                side_effect=RuntimeError("fixture-private-secret"),
            ),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(automation.main("init"), 1)
        self.assertNotIn("fixture-private-secret", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["status"], "failed")


if __name__ == "__main__":
    unittest.main()
