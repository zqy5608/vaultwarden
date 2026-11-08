"""Trusted, deliberately non-observable browser login for operator-approved sites."""

# Third-party exceptions can contain credentials; these boundaries must not log them.
# ruff: noqa: BLE001, S110

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

from agent_http import api_request
from bw_crypto import decrypt_fill, load_user_key


class BrokerError(Exception):
    """Only fixed, non-sensitive reason codes cross the MCP boundary."""


_REASONS = {
    "debug_logging_disabled",
    "ticket_unavailable",
    "ticket_binding_failed",
    "authenticated_ciphertext_required",
    "decryption_failed",
    "unsafe_form",
    "authentication_unconfirmed",
}
_BROWSER_TIMEOUT_MS = 15_000


def origin(url: str, *, local: bool = False) -> str:
    parsed = urlsplit(url)
    if parsed.username or parsed.password or not parsed.hostname:
        raise BrokerError("invalid_origin")
    if parsed.scheme != "https" and not (
        local
        and parsed.scheme == "http"
        and parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    ):
        raise BrokerError("https_required")
    port = parsed.port
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    suffix = (
        f":{port}" if port and port != (443 if parsed.scheme == "https" else 80) else ""
    )
    return f"{parsed.scheme}://{host}{suffix}"


def read_config(path: Path) -> dict | None:
    if not path.exists():
        return None
    metadata = path.lstat()
    parent = path.parent.stat()
    if (
        path.is_symlink()
        or path.parent.is_symlink()
        or metadata.st_uid != os.getuid()
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or stat.S_IMODE(parent.st_mode) & 0o077
    ):
        raise BrokerError("private_config_required")
    if metadata.st_size > 65_536 or not stat.S_ISREG(metadata.st_mode):
        raise BrokerError("invalid_config")
    try:
        config = json.loads(path.read_text())
        validate_config(config)
        return config
    except BrokerError:
        raise
    except Exception:
        raise BrokerError("invalid_config") from None


def validate_config(config: dict) -> None:
    allowed = {
        "server_url",
        "agent_token",
        "fill_token",
        "fill_agent_id",
        "user_key",
        "sites",
        "headless",
    }
    if not isinstance(config, dict) or set(config) - allowed:
        raise BrokerError("invalid_config")
    server = config["server_url"]
    if server.rstrip("/") != origin(server, local=True):
        raise BrokerError("invalid_server")
    for field, prefix in (("agent_token", "vwagent_"), ("fill_token", "vwfill_")):
        if not re.fullmatch(prefix + r"[a-fA-F0-9]{64}", config[field]):
            raise BrokerError("invalid_credential")
    UUID(config["fill_agent_id"])
    if len(load_user_key(config["user_key"])) != 64:
        raise BrokerError("authenticated_key_required")
    if type(config.get("headless", False)) is not bool or not isinstance(
        config["sites"], dict
    ):
        raise BrokerError("invalid_config")
    for name, site in config["sites"].items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
            raise BrokerError("invalid_site")
        if set(site) != {
            "item_id",
            "login_url",
            "username_selector",
            "password_selector",
            "submit_selector",
            "success_selector",
            "success_path",
        }:
            raise BrokerError("invalid_site")
        UUID(site["item_id"])
        origin(site["login_url"])
        parsed = urlsplit(site["login_url"])
        if parsed.query or parsed.fragment or not site["success_path"].startswith("/"):
            raise BrokerError("invalid_site")
        if "?" in site["success_path"] or "#" in site["success_path"]:
            raise BrokerError("invalid_site")
        if any(
            not isinstance(value, str) or not value or len(value) > 2048
            for value in site.values()
        ):
            raise BrokerError("invalid_site")


# One browser operation checks the target again before exposing credentials to it.
_FORM = """({site, expected, credentials}) => {
  const user = document.querySelector(site.username_selector);
  const pass = document.querySelector(site.password_selector);
  const submit = document.querySelector(site.submit_selector);
  const visible = element => element && element.getBoundingClientRect().width > 0 &&
    element.getBoundingClientRect().height > 0 && getComputedStyle(element).visibility !== 'hidden' &&
    Number(getComputedStyle(element).opacity) > 0 && !element.disabled;
  const valid = () => location.origin === expected &&
    [site.username_selector, site.password_selector, site.submit_selector].every(s => document.querySelectorAll(s).length === 1) &&
    user instanceof HTMLInputElement && pass instanceof HTMLInputElement &&
    (submit instanceof HTMLButtonElement || submit instanceof HTMLInputElement) && submit.type === 'submit' &&
    ['text', 'email'].includes(user.type) && pass.type === 'password' &&
    visible(user) && visible(pass) && visible(submit) && !user.readOnly && !pass.readOnly &&
    user.form && user.form === pass.form && submit.form === pass.form &&
    pass.form.method.toLowerCase() === 'post' &&
    ['', '_self'].includes(pass.form.target) && ['', '_self'].includes(submit.formTarget) &&
    (!submit.hasAttribute('formmethod') || submit.formMethod.toLowerCase() === 'post') &&
    new URL(submit.hasAttribute('formaction') ? submit.formAction : pass.form.action).origin === expected;
  if (!valid()) return false;
  if (!credentials) return true;
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
  for (const [field, value] of [[user, credentials.username], [pass, credentials.password]]) {
    set.call(field, value);
    field.dispatchEvent(new Event('input', {bubbles: true}));
    field.dispatchEvent(new Event('change', {bubbles: true}));
  }
  if (!valid()) { set.call(pass, ''); return false; }
  pass.form.requestSubmit(submit);
  return true;
}"""


class BrowserBroker:
    """Own the private browser; return an allowlist of states rather than browser data."""

    def __init__(self, config: dict | None) -> None:
        self.config = config
        self.lock = asyncio.Lock()
        self.playwright = None
        self.browser = None
        self.sessions: dict[str, tuple] = {}

    def sites(self) -> dict:
        if self.config is None:
            return {"status": "not_configured", "sites": []}
        return {
            "status": "ready",
            "sites": [
                {"site": name, "origin": origin(site["login_url"])}
                for name, site in self.config["sites"].items()
            ],
        }

    async def status(self, name: str) -> dict:
        async with self.lock:
            site = self._site(name)
            if site is None:
                return {
                    "status": "not_configured"
                    if self.config is None
                    else "site_not_allowed"
                }
            session = self.sessions.get(name)
            try:
                authenticated = bool(
                    session and await self._authenticated(session[1], site)
                )
            except Exception:
                authenticated = False
            return {
                "status": "authenticated" if authenticated else "not_authenticated",
                "site": name,
            }

    def _site(self, name: str) -> dict | None:
        return (
            self.config["sites"].get(name)
            if self.config and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name)
            else None
        )

    async def _quiet_close(self, target) -> None:
        try:
            await target.close()
        except Exception:
            pass

    async def _start(self) -> None:
        if self.browser is not None and self.browser.is_connected():
            return
        if self.playwright is not None:
            await self.close()
        if os.environ.get("DEBUG") or os.environ.get("PWDEBUG"):
            raise BrokerError("debug_logging_disabled")
        from playwright.async_api import async_playwright

        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=self.config.get("headless", False), chromium_sandbox=True
        )

    async def _authenticated(self, page, site: dict) -> bool:
        return (
            not page.is_closed()
            and origin(page.url) == origin(site["login_url"])
            and urlsplit(page.url).path == site["success_path"]
            and await page.locator(site["success_selector"]).count() == 1
            and await page.locator(site["success_selector"]).is_visible()
        )

    def _credentials(self, site: dict) -> dict:
        config = self.config
        base = config["server_url"].rstrip("/")
        expected = origin(site["login_url"])
        ticket = api_request(
            base,
            "POST",
            "/api/agent/fills",
            config["agent_token"],
            body={
                "itemId": site["item_id"],
                "origin": expected,
                "fillAgentId": config["fill_agent_id"],
            },
            timeout=10,
        )
        ticket_id = str(UUID(ticket["id"]))
        pending = api_request(
            base,
            "GET",
            "/api/agent/fill-agent/pending",
            config["fill_token"],
            timeout=10,
        )
        matching = [row for row in pending["data"] if row.get("id") == ticket_id]
        if len(matching) != 1:
            raise BrokerError("ticket_unavailable")
        payload = api_request(
            base,
            "POST",
            "/api/agent/fill-agent/redeem",
            config["fill_token"],
            body={
                "ticketId": ticket_id,
                "secret": matching[0]["redeemSecret"],
            },
            timeout=10,
        )
        if (
            payload.get("ticketId") != ticket_id
            or payload.get("itemId") != site["item_id"]
            or payload.get("origin") != expected
        ):
            raise BrokerError("ticket_binding_failed")
        login = payload["login"]
        if not isinstance(login.get("password"), str) or not login[
            "password"
        ].startswith("2."):
            raise BrokerError("authenticated_ciphertext_required")
        if payload.get("key") and not payload["key"].startswith("2."):
            raise BrokerError("authenticated_ciphertext_required")
        decrypted = decrypt_fill(
            login.get("username"),
            login["password"],
            None,
            payload.get("key"),
            load_user_key(config["user_key"]),
        )
        if (
            not decrypted.ok
            or decrypted.password.state != "decrypted"
            or not decrypted.username.value
            or not decrypted.password.value
        ):
            raise BrokerError("decryption_failed")
        return {
            "username": decrypted.username.value,
            "password": decrypted.password.value,
        }

    async def login(self, name: str) -> dict:
        async with self.lock:
            site = self._site(name)
            if site is None:
                return {
                    "status": "not_configured"
                    if self.config is None
                    else "site_not_allowed"
                }
            context = None
            failure = "browser_unavailable"
            try:
                existing = self.sessions.get(name)
                if existing and await self._authenticated(existing[1], site):
                    return {"status": "authenticated", "site": name}
                if existing:
                    await self._quiet_close(existing[0])
                    self.sessions.pop(name, None)
                await self._start()
                expected = origin(site["login_url"])
                context = await self.browser.new_context(
                    accept_downloads=False, service_workers="block"
                )
                context.set_default_timeout(_BROWSER_TIMEOUT_MS)

                async def route(request_route):
                    try:
                        allowed = origin(request_route.request.url) == expected
                    except Exception:
                        allowed = False
                    await (
                        request_route.continue_() if allowed else request_route.abort()
                    )

                await context.route("**/*", route)
                await context.route_web_socket("**/*", lambda ws: ws.close())
                page = await context.new_page()
                page.on(
                    "popup", lambda popup: asyncio.create_task(self._quiet_close(popup))
                )

                async def dismiss(dialog):
                    try:
                        await dialog.dismiss()
                    except Exception:
                        pass

                page.on("dialog", dismiss)
                failure = "page_unavailable"
                await page.goto(site["login_url"], wait_until="domcontentloaded")
                await page.locator(site["password_selector"]).wait_for(state="visible")
                arguments = {"site": site, "expected": expected, "credentials": None}
                if not await page.evaluate(_FORM, arguments):
                    raise BrokerError("unsafe_form")
                failure = "vault_unavailable"
                arguments["credentials"] = await asyncio.to_thread(
                    self._credentials, site
                )
                failure = "submission_unconfirmed"
                submitted = await page.evaluate(_FORM, arguments)
                arguments["credentials"] = None
                if not submitted:
                    raise BrokerError("unsafe_form")
                failure = "authentication_unconfirmed"
                await page.wait_for_url(
                    lambda url: (
                        origin(str(url)) == expected
                        and urlsplit(str(url)).path == site["success_path"]
                    ),
                    timeout=_BROWSER_TIMEOUT_MS,
                )
                await page.locator(site["success_selector"]).wait_for(state="visible")
                if not await self._authenticated(page, site):
                    raise BrokerError("authentication_unconfirmed")
                self.sessions[name] = (context, page)
                return {"status": "authenticated", "site": name}
            except BrokerError as exc:
                reason = str(exc) if str(exc) in _REASONS else "login_unconfirmed"
                return {"status": "failed", "reason": reason, "site": name}
            except Exception:
                # Playwright/API error text can contain a password or a reflected response.
                return {"status": "failed", "reason": failure, "site": name}
            finally:
                if context is not None and name not in self.sessions:
                    await self._quiet_close(context)

    async def close(self) -> None:
        if self.browser is not None:
            await self._quiet_close(self.browser)
        if self.playwright is not None:
            try:
                await self.playwright.stop()
            except Exception:
                pass
        self.browser = None
        self.playwright = None
        self.sessions.clear()
