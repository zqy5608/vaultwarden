#!/usr/bin/env python3
"""Provision only the owned test identity; never print credentials or private errors."""

import argparse
import base64
import http.cookiejar
import json
import os
import resource
import runpy
import secrets
import ssl
import subprocess
import time
import urllib.request
from pathlib import Path

from agent_mcp import unlock_user_key
from browser_broker import validate_config

HELPERS = runpy.run_path(str(Path(__file__).with_name("verify-agent-mcp.py")))
request, encrypt = HELPERS["request"], HELPERS["encrypt"]
ROOT = Path("/etc/vaultwarden-agent")
STATE = ROOT / "automation-state.json"
SEALED = ROOT / "broker-config.cred"
ADMIN = Path("/run/vaultwarden-agent-automation/admin-token")
BASE = "https://localhost:18444"
SITE = "https://agent-test.bo0lean.com"
stage = "preflight"


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, capture_output=True, **kwargs).stdout


def seal(name, payload, target):
    ciphertext = run(
        [
            "/usr/bin/systemd-creds",
            "encrypt",
            "--with-key=host",
            "--name=" + name,
            "-",
            "-",
        ],
        input=payload,
    )
    pending = target.with_suffix(".next")
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(ciphertext)
    os.replace(pending, target)


def admin_session():
    context = ssl.create_default_context(cafile=ROOT / "automation-ca.crt")
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=context),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
    )
    request(opener, BASE + "/admin/", "POST", form={"token": ADMIN.read_text()})
    return opener


def credentials(opener, state):
    agent = request(
        opener,
        BASE + "/admin/agent/tokens",
        "POST",
        body={
            "userEmail": state["email"],
            "name": "Agent automation",
            "folderIds": [state["folder"]],
        },
    )
    fill = request(
        opener,
        BASE + "/admin/agent/fill-agents",
        "POST",
        body={"userEmail": state["email"], "name": "Agent automation browser"},
    )
    state.update(agent=agent["id"], fill=fill["id"])
    return {
        "agent_token": agent["token"],
        "fill_token": fill["token"],
        "fill_agent_id": fill["id"],
    }


def initialize():
    global stage
    if STATE.exists() or SEALED.exists():
        raise RuntimeError("already_configured")
    stage = "private_vault_start"
    if not (ROOT / "automation-admin.cred").exists():
        seal(
            "admin-token",
            secrets.token_urlsafe(48).encode(),
            ROOT / "automation-admin.cred",
        )
    run(["/usr/bin/systemctl", "start", "vaultwarden-agent-automation.service"])
    deadline = time.monotonic() + 60
    while True:
        try:
            certificate = run(
                [
                    "/usr/bin/docker",
                    "exec",
                    "vaultwarden-agent-automation-api-tls-1",
                    "cat",
                    "/data/caddy/pki/authorities/local/root.crt",
                ]
            )
            (ROOT / "automation-ca.crt").write_bytes(certificate)
            (ROOT / "automation-ca.crt").chmod(0o644)
            opener = admin_session()
            break
        except (OSError, subprocess.SubprocessError, RuntimeError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.5)
    stage = "machine_account_registration"
    email = "agent-automation@example.test"
    master_password = secrets.token_urlsafe(48)
    user_key, item_key = secrets.token_bytes(64), secrets.token_bytes(64)
    master = HELPERS["derive_master_key"](master_password, email, 0, 600000)
    password_hash = HELPERS["master_password_hash"](master, master_password)
    request(opener, BASE + "/admin/invite", "POST", body={"email": email})
    verification = request(
        opener,
        BASE + "/identity/accounts/register/send-verification-email",
        "POST",
        body={"email": email},
    )
    request(
        opener,
        BASE + "/identity/accounts/register/finish",
        "POST",
        body={
            "email": email,
            "masterPasswordHash": password_hash,
            "key": encrypt(HELPERS["stretch_master_key"](master), user_key),
            "kdf": 0,
            "kdfIterations": 600000,
            "emailVerificationToken": verification,
        },
    )
    token = request(
        opener,
        BASE + "/identity/connect/token",
        "POST",
        form=HELPERS["login_form"](email, password_hash),
    )["access_token"]
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    folder = request(
        opener,
        BASE + "/api/folders",
        "POST",
        token=token,
        body={"name": encrypt(user_key, b"Agent automation")},
    )["id"]
    stage = "owned_site_registration"
    username, password = (
        "agent-automation-" + secrets.token_hex(8),
        secrets.token_urlsafe(32),
    )
    site = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    site.addheaders = [("Origin", SITE)]
    request(
        site,
        SITE + "/register",
        "POST",
        body={"username": username, "password": password},
    )
    stage = "encrypted_login_creation"
    cipher = request(
        opener,
        BASE + "/api/ciphers",
        "POST",
        token=token,
        body={
            "type": 1,
            "encryptedFor": claims["sub"],
            "folderId": folder,
            "name": encrypt(item_key, b"Owned Agent test site"),
            "key": encrypt(user_key, item_key),
            "login": {
                "username": encrypt(item_key, username.encode()),
                "password": encrypt(item_key, password.encode()),
                "uris": [
                    {"uri": encrypt(item_key, (SITE + "/login").encode()), "match": 1}
                ],
            },
        },
    )
    item = cipher["id"]
    request(
        opener,
        BASE + "/api/agent/items/" + item + "/uri-index",
        "PUT",
        token=token,
        body={"uris": [{"uri": SITE + "/login", "match": 1}]},
    )
    stage = "scoped_broker_credentials"
    state = {"email": email, "folder": folder, "item": item, "username": username}
    os.environ["SSL_CERT_FILE"] = str(ROOT / "automation-ca.crt")
    key = unlock_user_key(BASE, email, master_password)
    assert key == base64.b64encode(user_key).decode()
    config = {
        "server_url": BASE,
        **credentials(opener, state),
        "user_key": key,
        "headless": True,
        "sites": {
            "agent-test": {
                "item_id": item,
                "login_url": SITE + "/login",
                "username_selector": "#input-email",
                "password_selector": "#password",
                "submit_selector": "#password-submit",
                "success_path": "/profile",
                "actions": HELPERS["workspace_actions"](SITE),
                "success_selector": "html:has(meta[name='agent-test-user'][content='"
                + username
                + "']) #profile",
            }
        },
    }
    validate_config(config)
    seal("broker-config", json.dumps(config).encode(), SEALED)
    STATE.write_text(json.dumps(state))


def change_credentials(action):
    state = json.loads(STATE.read_text())
    previous = dict(state)
    opener = admin_session()
    if action == "rotate":
        config = json.loads(
            run(
                [
                    "/usr/bin/systemd-creds",
                    "decrypt",
                    "--name=broker-config",
                    str(SEALED),
                    "-",
                ]
            )
        )
        config.update(credentials(opener, state))
        validate_config(config)
        seal("broker-config", json.dumps(config).encode(), SEALED)
        STATE.write_text(json.dumps(state))
    for kind, identifier in (("tokens", "agent"), ("fill-agents", "fill")):
        request(
            opener,
            BASE + "/admin/agent/" + kind + "/" + previous[identifier] + "/revoke",
            "POST",
            body={},
        )


def main(action, native_profile=None):
    global stage
    stage = action
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if os.geteuid() != 0:
            raise PermissionError("administrator_required")
        if native_profile is not None and action != "configure":
            raise ValueError("configure_required")
        if action == "init":
            initialize()
        elif action == "configure":
            config = json.loads(
                run(
                    [
                        "/usr/bin/systemd-creds",
                        "decrypt",
                        "--name=broker-config",
                        str(SEALED),
                        "-",
                    ]
                )
            )
            config["sites"]["agent-test"]["actions"] = HELPERS["workspace_actions"](
                SITE
            )
            if native_profile is not None:
                from browser_broker import read_config

                config["native"] = read_config(native_profile)
            validate_config(config)
            seal("broker-config", json.dumps(config).encode(), SEALED)
        else:
            change_credentials(action)
        stage = "broker_restart"
        run(["/usr/bin/systemctl", "restart", "vaultwarden-agent-broker.service"])
        print(
            json.dumps(
                {
                    "status": "ready" if action != "revoke" else "revoked",
                    "site": "agent-test",
                    "mode": "isolated_browser",
                }
            )
        )
        return 0
    except Exception as error:  # noqa: BLE001 -- Private errors must never reach MCP diagnostics.
        print(
            json.dumps(
                {
                    "status": "failed",
                    "stage": stage,
                    "failure_type": type(error).__name__,
                }
            )
        )
        return 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["init", "revoke", "rotate", "configure"])
    parser.add_argument("--native-profile", type=Path)
    arguments = parser.parse_args()
    raise SystemExit(main(arguments.action, arguments.native_profile))
