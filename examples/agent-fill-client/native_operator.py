"""Private operator confirmation; this protocol is never exposed as an MCP tool."""

# Provider errors and input values must never enter diagnostics.
# ruff: noqa: BLE001, S110

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

from browser_broker import BrokerError, origin


async def provider_login(page, metadata: dict, password: str) -> None:
    """Drive the pinned provider's normal setup and login, without reading values."""
    await page.bring_to_front()
    for _ in range(4):
        panel = page.locator(
            "environment-selector, app-intro-carousel, autofill-default-password-manager-prompt"
        )
        await panel.first.wait_for(state="visible")
        if await page.locator("environment-selector").is_visible():
            break
        intro = page.locator("app-intro-carousel")
        if await intro.is_visible():
            await intro.get_by_role("button", name="Log in", exact=True).click()
        else:
            await page.locator(
                "#default-password-manager-prompt_button_skip-for-now"
            ).click()
        # Only nonsecret onboarding controls may be retried while Angular initializes.
        try:
            await page.locator("environment-selector").wait_for(
                state="visible", timeout=1500
            )
        except Exception:
            pass
    await page.locator("environment-selector").get_by_role("button").click()
    await page.get_by_role("menuitem", name="self-hosted").click()
    await page.locator("#self_hosted_env_settings_form_input_base_url").fill(
        metadata["vault_origin"]
    )
    await page.locator("[bit-dialog] button[type=submit]").click()
    await page.locator("#email").fill(metadata["email"])
    await page.get_by_role("button", name="Continue", exact=True).click()
    await page.locator("#masterPassword[type=password]").fill(password)
    await page.get_by_role("button", name="Log in", exact=True).click()
    await page.wait_for_url("**/popup/index.html#/tabs/vault")


async def approve(broker, request: str, password: str | None) -> dict:
    """Consume a request once. A fresh human input is used only for this ceremony."""
    async with broker.lock:
        if (
            not broker.native
            or "operator" not in broker.config
            or not request
            or request != broker.native_request
            or len(broker.pending) != 1
        ):
            return {"status": "rejected"}
        name = next(iter(broker.pending))
        broker.native_request = None
        if time.monotonic() >= broker.pending[name]:
            await broker.close()
            return {"status": "failed", "reason": "approval_expired"}
        if password is None:
            await broker.close()
            return {"status": "cancelled"}
        if not isinstance(password, str) or not 1 <= len(password) <= 4096:
            await broker.close()
            return {"status": "rejected"}
        phase = "provider_login"
        try:
            async with asyncio.timeout(60):
                context, rp = broker.sessions[name]
                provider = next(
                    page
                    for page in context.pages
                    if page.url.startswith(broker.native_extension_origin + "/")
                )
                await provider_login(provider, broker.config["operator"], password)
                phase = "passkey_request"
                await rp.bring_to_front()
                site = broker.config["sites"][name]
                if origin(rp.url) != origin(site["login_url"]):
                    raise BrokerError("unsafe_form")
                async with context.expect_page() as opened:
                    await rp.locator(site["passkey_selector"]).click()
                prompt = await opened.value
                await prompt.wait_for_url(broker.native_extension_origin + "/**")
                phase = "passkey_choice"
                candidates = prompt.locator("app-fido2-cipher-row")
                await candidates.first.wait_for(state="visible")
                if await candidates.count() != 1:
                    raise BrokerError("ambiguous_passkey")
                await candidates.get_by_role("button").click()
                phase = "master_reprompt"
                master = prompt.locator("input#masterPassword[type=password]")
                await master.wait_for(state="visible")
                if time.monotonic() >= broker.pending[name]:
                    raise BrokerError("approval_expired")
                await master.fill(password)
                broker.native_verified.add(name)
                await prompt.locator("[bit-dialog] button[type=submit]").click()
                password = ""
                phase = "account_verification"
                await rp.wait_for_url(origin(site["login_url"]) + site["success_path"])
                result = await broker._native_status(name, site)
                if result["status"] == "authenticated":
                    return {"status": "authenticated"}
        except Exception:
            pass
        finally:
            password = ""
        await broker.close()
        return {
            "status": "failed",
            "reason": "native_confirmation_unconfirmed",
            "phase": phase,
        }


async def start_operator(path: Path, broker) -> asyncio.Server:
    """Lease one pending ceremony to one private connection, with a bounded lifetime."""
    backend = broker.operator_backend()
    metadata = path.parent.stat()
    if (
        path.parent.is_symlink()
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
        or path.exists()
    ):
        raise ValueError("private_unused_socket_required")
    leased: set[str] = set()

    async def handle(reader, writer):
        request = None
        claimed = False
        try:
            async with asyncio.timeout(300):
                if json.loads(await reader.readline()) != {"method": "pending"}:
                    return
                async with backend.lock:
                    request = backend.native_request
                    if not request or request in leased:
                        writer.write(b'{"status":"none"}\n')
                        await writer.drain()
                        return
                    leased.add(request)
                    claimed = True
                    name = next(iter(backend.pending))
                    message = {
                        "status": "needs_approval",
                        "request": request,
                        "site": name,
                        "origin": origin(backend.config["sites"][name]["login_url"]),
                    }
                writer.write(json.dumps(message).encode() + b"\n")
                await writer.drain()
                answer = json.loads(await reader.readline())
                if (
                    not isinstance(answer, dict)
                    or set(answer) != {"request", "password"}
                    or answer["request"] != request
                ):
                    return
                password = answer.pop("password")
                result = await approve(backend, request, password)
                password = None
                writer.write(json.dumps(result).encode() + b"\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            if claimed:
                leased.discard(request)
                if backend.native_request == request:
                    await approve(backend, request, None)
            writer.close()

    server = await asyncio.start_unix_server(handle, str(path), limit=32768)
    path.chmod(0o600)
    return server


async def stdio(path: Path) -> None:
    """Restricted SSH bridge for one private operator exchange, never general RPC."""
    writer = None
    try:
        async with asyncio.timeout(310):
            reader, writer = await asyncio.open_unix_connection(str(path), limit=32768)
            writer.write(b'{"method":"pending"}\n')
            await writer.drain()
            pending = await reader.readline()
            value = json.loads(pending)
            if not isinstance(value, dict):
                return
            sys.stdout.buffer.write(pending)
            sys.stdout.buffer.flush()
            if value.get("status") != "needs_approval":
                return
            answer = await asyncio.to_thread(sys.stdin.buffer.readline, 32768)
            writer.write(answer)
            await writer.drain()
            answer = None
            response = await reader.readline()
            # The broker has fixed responses. Never reflect operator input on failure.
            if json.loads(response).get("status") in {
                "authenticated",
                "failed",
                "rejected",
                "cancelled",
            }:
                sys.stdout.buffer.write(response)
                sys.stdout.buffer.flush()
    except Exception:
        pass
    finally:
        if writer is not None:
            writer.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Private native confirmation bridge")
    parser.add_argument("--socket", type=Path, required=True)
    asyncio.run(stdio(parser.parse_args().socket))
