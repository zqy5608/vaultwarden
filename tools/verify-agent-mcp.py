#!/usr/bin/env python3
"""Exercise MCP -> disposable Vaultwarden -> owned HTTPS login, without secret output."""

# Verifier failures are reduced to fixed stages so fixture secrets never enter diagnostics.
# ruff: noqa: BLE001

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import http.cookiejar
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "examples/agent-fill-client"))
from agent_mcp import unlock_user_key
from bw_kdf import derive_master_key, master_password_hash, stretch_master_key
from publish_uri import login_form


def encrypt(key: bytes, value: bytes) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    iv = secrets.token_bytes(16)
    padder = PKCS7(128).padder()
    padded = padder.update(value) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key[:32]), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    mac = hmac.new(key[32:], iv + ciphertext, hashlib.sha256).digest()
    return "2." + "|".join(
        base64.b64encode(part).decode() for part in (iv, ciphertext, mac)
    )


def request(opener, url, method="GET", *, body=None, form=None, token=None):
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        with opener.open(
            urllib.request.Request(url, data=data, headers=headers, method=method),
            timeout=20,
        ) as response:
            raw = response.read(1_048_576)
        try:
            return json.loads(raw) if raw else None
        except ValueError:
            return None
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"http_{exc.code}") from None
    except Exception:
        raise RuntimeError("request_failed") from None


def password_config(
    opener,
    base,
    *,
    user_token,
    item_id,
    email,
    master_password,
    user_key,
    admin,
    site_origin,
    private_values,
    headless=True,
):
    """Provision only the disposable user's scoped password fixture."""
    request(
        opener,
        base + "/api/agent/items/" + item_id + "/uri-index",
        "PUT",
        token=user_token,
        body={"uris": [{"uri": site_origin + "/login", "match": 1}]},
    )
    request(opener, base + "/admin/", "POST", form={"token": admin})
    agent = request(
        opener,
        base + "/admin/agent/tokens",
        "POST",
        body={"userEmail": email, "name": "Owned RP verification"},
    )
    fill = request(
        opener,
        base + "/admin/agent/fill-agents",
        "POST",
        body={"userEmail": email, "name": "Owned RP browser"},
    )
    private_values.extend([agent["token"], fill["token"]])
    config = {
        "server_url": base,
        "agent_token": agent["token"],
        "fill_token": fill["token"],
        "fill_agent_id": fill["id"],
        "user_key": unlock_user_key(base, email, master_password),
        "headless": headless,
        "sites": {
            "agent-test": {
                "item_id": item_id,
                "login_url": site_origin + "/login",
                "username_selector": "#input-email",
                "password_selector": "#password",
                "submit_selector": "#password-submit",
                "success_selector": "#profile",
                "success_path": "/profile",
                "actions": workspace_actions(site_origin),
            }
        },
    }
    assert config["user_key"] == base64.b64encode(user_key).decode(), (
        "account_unlock_failed"
    )
    return config


def workspace_actions(site_origin):
    """Public operation metadata shared by owned-site provisioning and acceptance."""
    return {
        "save-note": {
            "url": site_origin + "/workspace",
            "fields": {"note": "#note"},
            "submit_selector": "#save-note",
            "success_path": "/workspace",
            "success_selector": "#workspace",
        },
        "check-note": {
            "url": site_origin + "/workspace",
            "fields": {"expected": "#expected-note"},
            "submit_selector": "#check-note",
            "success_path": "/workspace/check",
            "success_selector": "#note-matches",
        },
        "sign-out": {
            "url": site_origin + "/profile",
            "fields": {},
            "submit_selector": "#logout",
            "success_path": "/login",
            "success_selector": "#password",
        },
    }


async def call_mcp(config_path, diagnostics, secret_values):
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    parameters = StdioServerParameters(
        command=str(Path(sys.executable).with_name("vaultwarden-agent-mcp")),
        args=["--config", str(config_path)],
        env={
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(Path.home()),
            "PYTHONDONTWRITEBYTECODE": "1",
            **{
                name: os.environ[name]
                for name in (
                    "DISPLAY",
                    "XAUTHORITY",
                    "PLAYWRIGHT_BROWSERS_PATH",
                    "XDG_CONFIG_HOME",
                )
                if name in os.environ
            },
        },
    )
    transcripts = []
    results = {}

    def view(result):
        data = result.structured_content
        if isinstance(data, dict) and "status" in data:
            return data
        return json.loads(
            next(block.text for block in result.content if block.type == "text")
        )

    async with (
        stdio_client(parameters, errlog=diagnostics) as (read, write),
        ClientSession(read, write, read_timeout_seconds=90) as client,
    ):
        initialized = await client.initialize()
        transcripts.append(initialized.model_dump_json())
        catalog = await client.list_tools()
        transcripts.append(catalog.model_dump_json())
        assert {tool.name for tool in catalog.tools} == {
            "vault_sites",
            "vault_login",
            "vault_status",
            "vault_actions",
            "vault_action",
            "vault_logout",
        }
        for tool, arguments in [
            ("vault_sites", {}),
            ("vault_status", {"site": "agent-test"}),
            ("vault_login", {"site": "agent-test"}),
            ("vault_status", {"site": "agent-test"}),
            ("vault_login", {"site": "not-approved"}),
        ]:
            result = await client.call_tool(tool, arguments)
            transcripts.append(result.model_dump_json())
            results[
                tool + ("-denied" if arguments.get("site") == "not-approved" else "")
            ] = view(result)
        if results["vault_login"]["status"] != "authenticated":
            raise RuntimeError(
                results["vault_login"].get("reason", "external_login_not_confirmed")
            )
        assert results["vault_status"]["status"] == "authenticated", (
            "retained_session_not_confirmed"
        )
        assert results["vault_login-denied"]["status"] == "site_not_allowed"
        concurrent = await asyncio.gather(
            client.call_tool("vault_login", {"site": "agent-test"}),
            client.call_tool("vault_login", {"site": "agent-test"}),
        )
        for result in concurrent:
            transcripts.append(result.model_dump_json())
            assert view(result)["status"] == "authenticated", (
                "concurrent_session_not_confirmed"
            )
        for tool, arguments, expected in [
            ("vault_actions", {"site": "agent-test"}, "ready"),
            (
                "vault_action",
                {
                    "site": "agent-test",
                    "action": "save-note",
                    "values": {"note": "MCP workspace acceptance"},
                },
                "completed",
            ),
            ("vault_status", {"site": "agent-test"}, "authenticated"),
            (
                "vault_action",
                {
                    "site": "agent-test",
                    "action": "check-note",
                    "values": {"expected": "MCP workspace acceptance"},
                },
                "completed",
            ),
            (
                "vault_action",
                {"site": "agent-test", "action": "save-note", "values": {"note": ""}},
                "completed",
            ),
            (
                "vault_action",
                {
                    "site": "agent-test",
                    "action": "check-note",
                    "values": {"expected": ""},
                },
                "completed",
            ),
            ("vault_logout", {"site": "agent-test"}, "not_authenticated"),
            (
                "vault_action",
                {
                    "site": "agent-test",
                    "action": "save-note",
                    "values": {"note": "not authorized"},
                },
                "not_authenticated",
            ),
            ("vault_login", {"site": "agent-test"}, "authenticated"),
        ]:
            result = await client.call_tool(tool, arguments)
            transcripts.append(result.model_dump_json())
            assert view(result)["status"] == expected, "workspace_flow_not_confirmed"
    wire = "\n".join(transcripts)
    diagnostics.flush()
    diagnostics.seek(0)
    captured = diagnostics.read()
    assert all(value not in wire + captured for value in secret_values), (
        "secret_output_detected"
    )
    return {
        "mcp_transport": "stdio",
        "tool_count": len(catalog.tools),
        "real_https_login": "passed",
        "retained_session": "passed",
        "concurrent_session_calls": "passed",
        "post_login_persisted_operation": "passed",
        "logout_and_reauthentication": "passed",
        "unapproved_site": "denied",
        "secret_output_scan": "passed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--vaultwarden-binary", type=Path, default=ROOT / "target/debug/vaultwarden"
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument("--site-origin", default="https://agent-test.bo0lean.com")
    args = parser.parse_args()
    runtime = Path(tempfile.mkdtemp(prefix="vaultwarden-mcp-verification-")).resolve()
    runtime.chmod(0o700)
    process = None
    stage = "owned_test_account"
    private_values = []
    report = {"status": "failed"}
    log_path = runtime / "vaultwarden.log"
    try:
        site_origin = args.site_origin
        parsed_origin = urllib.parse.urlsplit(site_origin)
        assert parsed_origin.scheme == "https" and parsed_origin.hostname in {
            "agent-test.bo0lean.com",
            "localhost",
        }
        assert (
            not parsed_origin.path
            and not parsed_origin.query
            and not parsed_origin.fragment
            and not parsed_origin.username
        )
        username = "password-" + secrets.token_hex(8)
        password = secrets.token_urlsafe(32)
        admin = secrets.token_urlsafe(48)
        master_password = secrets.token_urlsafe(48)
        user_key = secrets.token_bytes(64)
        item_key = secrets.token_bytes(64)
        private_values = [
            password,
            admin,
            master_password,
            base64.b64encode(user_key).decode(),
        ]
        site_opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        site_opener.addheaders = [("Origin", site_origin)]
        request(
            site_opener,
            site_origin + "/register",
            "POST",
            body={"username": username, "password": password},
        )
        stage = "local_vaultwarden_start"
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        environment = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": str(runtime),
            "DATA_FOLDER": str(runtime / "data"),
            "ROCKET_ADDRESS": "127.0.0.1",
            "ROCKET_PORT": str(port),
            "DOMAIN": base,
            "ADMIN_TOKEN": admin,
            "WEB_VAULT_ENABLED": "false",
            "SIGNUPS_ALLOWED": "true",
            "AGENT_API_ENABLED": "true",
            "AGENT_REQUIRE_FOLDER_ACL": "false",
            "LOG_LEVEL": "error",
        }
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as log:
            process = subprocess.Popen(
                [str(args.vaultwarden_binary.resolve())],
                cwd=runtime,
                env=environment,
                stdout=log,
                stderr=log,
            )
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
        )
        deadline = time.monotonic() + 30
        while True:
            try:
                request(opener, base + "/alive")
                break
            except RuntimeError:
                assert process.poll() is None and time.monotonic() < deadline, (
                    "local_server_unavailable"
                )
                time.sleep(0.2)
        stage = "encrypted_item_setup"
        email = "mcp-verification@example.test"
        master = derive_master_key(master_password, email, 0, 600_000)
        password_hash = master_password_hash(master, master_password)
        stage = "registration_verification"
        verification = request(
            opener,
            base + "/identity/accounts/register/send-verification-email",
            "POST",
            body={"email": email, "name": "MCP verification"},
        )
        assert isinstance(verification, str), "registration_verification_missing"
        private_values.append(verification)
        stage = "register_disposable_user"
        request(
            opener,
            base + "/identity/accounts/register/finish",
            "POST",
            body={
                "email": email,
                "masterPasswordHash": password_hash,
                "key": encrypt(stretch_master_key(master), user_key),
                "kdf": 0,
                "kdfIterations": 600_000,
                "emailVerificationToken": verification,
            },
        )
        stage = "authenticate_disposable_user"
        login = request(
            opener,
            base + "/identity/connect/token",
            "POST",
            form=login_form(email, password_hash),
        )
        user_token = login["access_token"]
        private_values.append(user_token)
        claims = json.loads(base64.urlsafe_b64decode(user_token.split(".")[1] + "=="))
        stage = "create_encrypted_cipher"
        cipher = request(
            opener,
            base + "/api/ciphers",
            "POST",
            token=user_token,
            body={
                "type": 1,
                "name": encrypt(item_key, b"Public login verification"),
                "encryptedFor": claims["sub"],
                "key": encrypt(user_key, item_key),
                "login": {
                    "username": encrypt(item_key, username.encode()),
                    "password": encrypt(item_key, password.encode()),
                    "uris": [
                        {
                            "uri": encrypt(item_key, (site_origin + "/login").encode()),
                            "match": 1,
                        }
                    ],
                },
            },
        )
        item_id = cipher["id"]
        stage = "scoped_password_setup"
        config = password_config(
            opener,
            base,
            user_token=user_token,
            item_id=item_id,
            email=email,
            master_password=master_password,
            user_key=user_key,
            admin=admin,
            site_origin=site_origin,
            private_values=private_values,
        )
        config_path = runtime / "config.json"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(config, handle)
        stage = "mcp_browser_login"
        with open(
            runtime / "mcp.log",
            "w+",
            opener=lambda path, flags: os.open(path, flags, 0o600),
        ) as diagnostics:
            result = asyncio.run(call_mcp(config_path, diagnostics, private_values))
        report = {
            "status": "passed",
            "vaultwarden": "real disposable server",
            "encrypted_item": "type-2 with wrapped item key",
            "uri_index": "published through user API",
            "account_key_unlock": "normal authentication and local unwrap",
            "target": site_origin,
            **result,
        }
    except Exception as exc:
        # Raw failures can include response bodies or credentials; expose the stage only.
        report = {
            "status": "failed",
            "stage": stage,
            "private_diagnostics": str(runtime),
        }
        safe_reasons = {
            "browser_unavailable",
            "page_unavailable",
            "vault_unavailable",
            "submission_unconfirmed",
            "authentication_unconfirmed",
            "unsafe_form",
            "ticket_unavailable",
            "ticket_binding_failed",
            "authenticated_ciphertext_required",
            "decryption_failed",
            "external_login_not_confirmed",
            "retained_session_not_confirmed",
            "concurrent_session_not_confirmed",
            "secret_output_detected",
        }
        if re.fullmatch(r"http_[0-9]{3}", str(exc)) or str(exc) in safe_reasons:
            report["reason"] = str(exc)
    finally:
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    if log_path.exists() and any(
        value.encode() in log_path.read_bytes() for value in private_values
    ):
        report = {
            "status": "failed",
            "stage": "server_log_secret_scan",
            "private_diagnostics": str(runtime),
        }
    if report["status"] == "passed":
        report["server_log_secret_scan"] = "passed"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
