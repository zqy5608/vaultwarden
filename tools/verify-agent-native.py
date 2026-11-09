#!/usr/bin/env python3
"""Calibrate the official passkey provider with disposable credentials only."""

# Fixture failures may contain credentials; only fixed stages cross the output boundary.
# ruff: noqa: BLE001

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import http.cookiejar
import json
import os
import re
import runpy
import secrets
import signal
import ssl
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = runpy.run_path(str(ROOT / "tools/verify-agent-mcp.py"))
VAULT_IMAGE = "ghcr.io/zqy5608/vaultwarden@sha256:204fab05736a444dc851413e0e4e33c3ad120c7fa68d379f1ccb68dca06c3387"
TLS_IMAGE = (
    "caddy@sha256:0bbb055bda6793c999bde78b1b5ce3e89f829fb031af2cf50056ea1246559fee"
)
EXTENSION_URL = "https://github.com/bitwarden/clients/releases/download/browser-v2026.10.0/dist-chrome-2026.10.0.zip"
EXTENSION_SHA256 = "7b9ec650b87dd8975e87a0e0bdd0c1f1a0fcf5b0a8da5ae759ec14cdffaad35d"
HTTP = "http://127.0.0.1:18081"
HTTPS = "https://localhost:18443"
stage = "start"
private_values: list[str] = []
network_statuses: list[dict] = []
tls_error: dict = {}
native_ui: dict = {}


def command(args: list[str]) -> bytes:
    return subprocess.run(args, check=True, capture_output=True, timeout=120).stdout


def progress(value: str) -> None:
    global stage
    stage = value
    print(json.dumps({"stage": value}), flush=True)


def seed_vault() -> tuple[str, str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    email = "native-" + secrets.token_hex(8) + "@example.test"
    password = secrets.token_urlsafe(48)
    username = "vw-native-" + secrets.token_hex(10)
    key = secrets.token_bytes(64)
    private_values.extend([password, base64.b64encode(key).decode()])
    master = FIXTURE["derive_master_key"](password, email, 0, 600000)
    password_hash = FIXTURE["master_password_hash"](master, password)
    keypair = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_der = keypair.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_der = keypair.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_values.append(base64.b64encode(private_der).decode())
    request = FIXTURE["request"]
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )
    verification = request(
        opener,
        HTTP + "/identity/accounts/register/send-verification-email",
        "POST",
        body={"email": email, "name": "Native calibration"},
    )
    private_values.extend([password_hash, verification])
    request(
        opener,
        HTTP + "/identity/accounts/register/finish",
        "POST",
        body={
            "email": email,
            "masterPasswordHash": password_hash,
            "key": FIXTURE["encrypt"](FIXTURE["stretch_master_key"](master), key),
            "kdf": 0,
            "kdfIterations": 600000,
            "emailVerificationToken": verification,
            "keys": {
                "publicKey": base64.b64encode(public_der).decode(),
                "encryptedPrivateKey": FIXTURE["encrypt"](key, private_der),
            },
        },
    )
    login = request(
        opener,
        HTTP + "/identity/connect/token",
        "POST",
        form=FIXTURE["login_form"](email, password_hash),
    )
    token = login["access_token"]
    private_values.append(token)
    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    encrypt = FIXTURE["encrypt"]
    request(
        opener,
        HTTP + "/api/ciphers",
        "POST",
        token=token,
        body={
            "type": 1,
            "name": encrypt(key, b"Native passkey calibration"),
            "encryptedFor": claims["sub"],
            "reprompt": 1,
            "login": {
                "username": encrypt(key, username.encode()),
                "uris": [{"uri": encrypt(key, b"https://webauthn.io"), "match": 1}],
            },
        },
    )
    return email, password, username


async def native_flow(runtime: Path, extension: Path, home: Path) -> dict:
    from playwright.async_api import async_playwright

    email, password, username = seed_vault()
    progress("native_browser_launch")
    async with async_playwright() as engine:
        context = await engine.chromium.launch_persistent_context(
            str(runtime / "profile"),
            channel="chromium",
            headless=False,
            chromium_sandbox=True,
            service_workers="block",
            accept_downloads=False,
            env={
                **os.environ,
                "HOME": str(home),
                "XDG_CONFIG_HOME": str(home / "config"),
            },
            ignore_default_args=["--disable-extensions"],
            args=[
                f"--disable-extensions-except={extension}",
                f"--load-extension={extension}",
            ],
        )
        try:

            def observe(response):
                path = urlsplit(response.url).path
                if response.url.startswith(
                    (HTTPS + "/", "https://webauthn.io/")
                ) and path in {
                    "/api/config",
                    "/identity/accounts/prelogin",
                    "/identity/connect/token",
                    "/api/sync",
                    "/registration/options",
                    "/registration/verification",
                    "/authentication/options",
                    "/authentication/verification",
                }:
                    network_statuses.append(
                        {"endpoint": path, "status": response.status}
                    )

            context.on("response", observe)
            worker = (
                context.service_workers[0]
                if context.service_workers
                else await context.wait_for_event("serviceworker")
            )
            extension_id = worker.url.split("/")[2]
            page = await context.new_page()
            page.set_default_timeout(20000)
            progress("native_environment")
            await page.goto(
                f"chrome-extension://{extension_id}/popup/index.html#/intro-carousel"
            )
            await page.get_by_role("button", name="Log in", exact=True).click()
            await page.wait_for_url(
                re.compile(r"#/(default-password-manager-prompt|login)$")
            )
            if "default-password-manager-prompt" in page.url:
                await page.get_by_role("button", name="Skip", exact=True).click()
            await page.locator("environment-selector").get_by_role("button").click()
            await page.get_by_role("menuitem", name="self-hosted").click()
            await page.locator("#self_hosted_env_settings_form_input_base_url").fill(
                HTTPS
            )
            await page.locator("[bit-dialog] button[type=submit]").click()
            progress("native_unlock")
            await page.locator("#email").fill(email)
            await page.get_by_role("button", name="Continue", exact=True).click()
            progress("native_master_password")
            await page.locator("#masterPassword").fill(password)
            await page.get_by_role("button", name="Log in", exact=True).click()
            progress("native_sync")
            await page.wait_for_url(
                f"chrome-extension://{extension_id}/popup/index.html#/tabs/vault"
            )
            progress("native_registration")
            rp = await context.new_page()
            rp.set_default_timeout(20000)
            await rp.goto(
                "https://webauthn.io/?authUserVerification=required",
                wait_until="domcontentloaded",
            )
            await rp.locator("#input-email").fill(username)
            progress("registration_request")
            async with context.expect_page() as opened:
                await rp.locator("#register-button").click()
            prompt = await opened.value
            await prompt.wait_for_url(f"chrome-extension://{extension_id}/**")
            progress("registration_native_item")
            async with rp.expect_response("**/registration/verification") as verified:
                await (
                    prompt.locator("app-fido2-cipher-row")
                    .filter(has_text="Native passkey calibration")
                    .get_by_role("button")
                    .click()
                )
                progress("registration_confirmation")
                await prompt.locator("#masterPassword").fill(password)
                progress("registration_verification")
                await prompt.locator("[bit-dialog] button[type=submit]").click()
            assert (await (await verified.value).json())["verified"] is True
            progress("native_registration_verified")
            progress("native_reprompt_cancel")
            authentication_requests = []
            rp.on(
                "request",
                lambda request: (
                    authentication_requests.append(True)
                    if urlsplit(request.url).path == "/authentication/verification"
                    else None
                ),
            )

            async def choose_passkey():
                async with context.expect_page() as opened:
                    await rp.locator("#login-button").click()
                window = await opened.value
                await window.wait_for_url(f"chrome-extension://{extension_id}/**")
                await (
                    window.locator("app-fido2-cipher-row")
                    .filter(has_text="Native passkey calibration")
                    .get_by_role("button")
                    .click()
                )
                await window.locator("#masterPassword").wait_for()
                return window

            prompt = await choose_passkey()
            await prompt.get_by_role("button", name="Cancel", exact=True).click()
            await rp.wait_for_timeout(1000)
            assert not authentication_requests and urlsplit(rp.url).path != "/profile"
            if not prompt.is_closed():
                await prompt.close()
            progress("native_assertion")
            prompt = await choose_passkey()
            await prompt.locator("#masterPassword").fill(password)
            async with rp.expect_response("**/authentication/verification") as verified:
                await prompt.locator("[bit-dialog] button[type=submit]").click()
            assert (await (await verified.value).json())["verified"] is True
            await rp.wait_for_url("https://webauthn.io/profile")
            assert username in await rp.locator("body").inner_text()
            await rp.reload(wait_until="domcontentloaded")
            assert urlsplit(rp.url).path == "/profile"
            return {
                "native_registration": "passed",
                "native_assertion": "passed",
                "master_reprompt_cancel": "passed",
                "retained_session": "passed",
                "tls_validation": "enabled",
            }
        except Exception:
            if stage in {"native_unlock", "native_master_password", "native_sync"}:
                native_ui.update(
                    {
                        "route": urlsplit(page.url).fragment.split("?")[0],
                        "inputs": await page.locator("input").evaluate_all(
                            "xs => xs.map(x => ({id: x.id, type: x.type}))"
                        ),
                        "buttons": await page.get_by_role("button").all_text_contents(),
                    }
                )
                assert not any(
                    value in json.dumps(native_ui) for value in private_values
                )
            raise
        finally:
            await context.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    runtime = Path(
        tempfile.mkdtemp(prefix="vaultwarden-native-verification-")
    ).resolve()
    containers: list[str] = []
    report = {"status": "failed"}

    def interrupted(signum, frame):
        raise SystemExit(1)

    for signum in (signal.SIGHUP, signal.SIGTERM):
        signal.signal(signum, interrupted)
    try:
        progress("pinned_extension")
        archive = runtime / "extension.zip"
        urllib.request.urlretrieve(EXTENSION_URL, archive)
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == EXTENSION_SHA256
        extension = runtime / "extension"
        extension.mkdir()
        with zipfile.ZipFile(archive) as package:
            assert all(
                (extension / name).resolve().is_relative_to(extension)
                for name in package.namelist()
            )
            package.extractall(extension)
        suffix = secrets.token_hex(5)
        vault, proxy = "vw-native-" + suffix, "vw-native-tls-" + suffix
        caddyfile = runtime / "Caddyfile"
        caddyfile.write_text(
            "{\n admin off\n skip_install_trust\n auto_https disable_redirects\n}\nhttps://localhost:18443 {\n bind 127.0.0.1\n tls internal\n reverse_proxy 127.0.0.1:18081\n}\n"
        )
        progress("disposable_vault_tls")
        containers.append(vault)
        command(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                vault,
                "--network",
                "host",
                "--read-only",
                "--tmpfs",
                "/data:rw,nosuid,nodev",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--env",
                "ROCKET_ADDRESS=127.0.0.1",
                "--env",
                "ROCKET_PORT=18081",
                "--env",
                "DOMAIN=" + HTTPS,
                "--env",
                "SIGNUPS_ALLOWED=true",
                "--env",
                "WEB_VAULT_ENABLED=false",
                "--env",
                "LOG_LEVEL=error",
                VAULT_IMAGE,
            ]
        )
        containers.append(proxy)
        command(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                proxy,
                "--network",
                "host",
                "--read-only",
                "--tmpfs",
                "/data:rw,nosuid,nodev",
                "--tmpfs",
                "/config:rw,nosuid,nodev",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--volume",
                str(caddyfile) + ":/etc/caddy/Caddyfile:ro",
                TLS_IMAGE,
            ]
        )
        ca = runtime / "ca.crt"
        deadline = time.monotonic() + 30
        while True:
            try:
                # Docker's archive copy cannot read tmpfs; export only the public CA.
                ca.write_bytes(
                    command(
                        [
                            "docker",
                            "exec",
                            proxy,
                            "cat",
                            "/data/caddy/pki/authorities/local/root.crt",
                        ]
                    )
                )
                with urllib.request.urlopen(
                    HTTPS + "/alive",
                    context=ssl.create_default_context(cafile=str(ca)),
                    timeout=5,
                ) as response:
                    assert response.status == 200
                break
            except (OSError, subprocess.CalledProcessError) as error:
                tls_error.update(
                    {
                        "type": type(error).__name__,
                        "reason_type": type(getattr(error, "reason", None)).__name__,
                        "http_status": getattr(error, "code", None),
                    }
                )
                assert time.monotonic() < deadline
                time.sleep(0.2)
        home = runtime / "home"
        nss = home / ".local/share/pki/nssdb"
        nss.mkdir(parents=True, mode=0o700)
        (home / "config").mkdir(mode=0o700)
        command(["certutil", "-N", "--empty-password", "-d", "sql:" + str(nss)])
        command(
            [
                "certutil",
                "-A",
                "-d",
                "sql:" + str(nss),
                "-t",
                "C,,",
                "-n",
                "Native fixture CA",
                "-i",
                str(ca),
            ]
        )
        result = asyncio.run(native_flow(runtime, extension, home))
        report = {"status": "passed", **result}
    except Exception:
        report = {"status": "failed", "stage": stage, "api_statuses": network_statuses}
        if native_ui:
            report["synthetic_ui_controls"] = native_ui
        if stage == "disposable_vault_tls":
            report["tls_error"] = tls_error
    finally:
        captured = [
            subprocess.run(["docker", "logs", name], check=False, capture_output=True)
            for name in containers
        ]
        diagnostics = b"".join(result.stdout + result.stderr for result in captured)
        if stage == "disposable_vault_tls" and not private_values:
            inspected = [
                subprocess.run(
                    [
                        "docker",
                        "inspect",
                        "--format",
                        "{{.State.Status}}:{{.State.ExitCode}}:{{.State.OOMKilled}}",
                        name,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                )
                for name in containers
            ]
            report["fixture_container_states"] = [
                result.stdout.strip() if result.returncode == 0 else "unavailable"
                for result in inspected
            ]
        if any(value.encode() in diagnostics for value in private_values):
            report = {"status": "failed", "stage": "diagnostic_secret_scan"}
        stopped = [
            subprocess.run(
                ["docker", "stop", "--time", "10", name],
                check=False,
                capture_output=True,
            ).returncode
            == 0
            for name in containers
        ]
        report["test_containers_stopped"] = all(stopped)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report), flush=True)
    return (
        0 if report["status"] == "passed" and report["test_containers_stopped"] else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
