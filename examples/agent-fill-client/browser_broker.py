"""Trusted, deliberately non-observable browser login for operator-approved sites."""

# Third-party exceptions can contain credentials; these boundaries must not log them.
# ruff: noqa: BLE001, S110

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import tempfile
import time
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
_NATIVE_PROVIDER = "bitwarden-extension"
_APPROVAL_SECONDS = 300


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
    if isinstance(config, dict) and config.get("provider") == _NATIVE_PROVIDER:
        _validate_native(config)
        return
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


def _validate_native(config: dict) -> None:
    if set(config) != {
        "provider",
        "extension_path",
        "profile_path",
        "sites",
    }:
        raise BrokerError("invalid_config")
    for key in ("extension_path", "profile_path"):
        if not isinstance(config[key], str) or not Path(config[key]).is_absolute():
            raise BrokerError("invalid_config")
    # shortcut: one native site binds confirmation; use separate runtimes for more sites.
    if not isinstance(config["sites"], dict) or len(config["sites"]) != 1:
        raise BrokerError("invalid_config")
    for name, site in config["sites"].items():
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name) or set(site) != {
            "login_url",
            "passkey_selector",
            "success_selector",
            "success_path",
            "account_selector",
            "resource_origins",
        }:
            raise BrokerError("invalid_site")
        if any(
            not isinstance(v, str) or not v or len(v) > 2048
            for k, v in site.items()
            if k != "resource_origins"
        ):
            raise BrokerError("invalid_site")
        login = urlsplit(site["login_url"])
        origin(site["login_url"])
        if (
            login.query
            or login.fragment
            or not site["success_path"].startswith("/")
            or any(c in site["success_path"] for c in "?#")
        ):
            raise BrokerError("invalid_site")
        if not isinstance(site["resource_origins"], list) or any(
            v != origin(v) for v in site["resource_origins"]
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
        self.native = bool(config and config.get("provider") == _NATIVE_PROVIDER)
        self.native_context = None
        self.native_extension_origin = ""
        self.pending: dict[str, float] = {}
        self.native_verified: set[str] = set()

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
                if self.native:
                    return await self._native_status(name, site)
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
        if self.native:
            await self._start_native()
            return
        self.browser = await self.playwright.chromium.launch(
            headless=self.config.get("headless", False), chromium_sandbox=True
        )

    async def _authenticated(self, page, site: dict) -> bool:
        authenticated = (
            not page.is_closed()
            and origin(page.url) == origin(site["login_url"])
            and urlsplit(page.url).path == site["success_path"]
            and await page.locator(site["success_selector"]).count() == 1
            and await page.locator(site["success_selector"]).is_visible()
        )
        if authenticated and self.native:
            authenticated = await page.locator(site["account_selector"]).count() == 1
        return authenticated

    async def _start_native(self) -> None:
        config = self.config
        extension, profile = (
            Path(config[k]) for k in ("extension_path", "profile_path")
        )
        if extension.resolve() != extension or any(
            p.stat().st_uid != 0 or p.stat().st_mode & 0o022
            for p in (extension, *extension.parents)
        ):
            raise BrokerError("trusted_native_files_required")
        parent = profile.parent
        if (
            os.getuid() == 0
            or parent.resolve() != parent
            or parent.stat().st_uid != os.getuid()
            or parent.stat().st_mode & 0o077
        ):
            raise BrokerError("private_native_runtime_required")
        profile.mkdir(mode=0o700, exist_ok=True)
        if (
            profile.is_symlink()
            or profile.stat().st_uid != os.getuid()
            or profile.stat().st_mode & 0o077
        ):
            raise BrokerError("private_native_runtime_required")
        # Reopening an extension cache can retain account state after failed approval.
        # shortcut: closed profiles remain volatile; restart the service to reclaim space.
        profile = Path(tempfile.mkdtemp(prefix="browser-", dir=profile))
        self.native_context = await self.playwright.chromium.launch_persistent_context(
            str(profile),
            channel="chromium",
            headless=False,
            no_viewport=True,
            chromium_sandbox=True,
            accept_downloads=False,
            service_workers="block",
            ignore_default_args=["--disable-extensions"],
            args=[
                f"--disable-extensions-except={extension}",
                f"--load-extension={extension}",
            ],
        )
        self.browser = self.native_context.browser
        await self.native_context.clear_cookies()
        worker = (
            self.native_context.service_workers[0]
            if self.native_context.service_workers
            else await self.native_context.wait_for_event("serviceworker")
        )
        self.native_extension_origin = (
            "chrome-extension://" + urlsplit(worker.url).netloc
        )
        await self.native_context.route("**/*", self._native_route)
        await self.native_context.route_web_socket("**/*", lambda ws: ws.close())
        self.native_context.on(
            "page",
            lambda page: asyncio.create_task(self._watch_native_verification(page)),
        )
        operator = await self.native_context.new_page()
        for page in self.native_context.pages:
            if page is not operator:
                await self._quiet_close(page)
        await operator.goto(self.native_extension_origin + "/popup/index.html#/login")

    async def _watch_native_verification(self, page) -> None:
        try:
            await page.wait_for_url(
                self.native_extension_origin + "/**", timeout=_BROWSER_TIMEOUT_MS
            )
            if not self.pending:
                return
            name = next(iter(self.pending))
            # Observe presence only; the trusted provider handles and verifies the value.
            await page.locator("input#masterPassword[type=password]").wait_for(
                state="visible", timeout=_APPROVAL_SECONDS * 1000
            )
            if name in self.pending:
                self.native_verified.add(name)
        except Exception:
            pass

    async def _native_route(self, route) -> None:
        request = route.request
        allowed = request.url.startswith(self.native_extension_origin + "/")
        if allowed:
            await route.continue_()
            return
        try:
            worker = request.service_worker
            if worker is not None:
                allowed = worker.url.startswith(self.native_extension_origin + "/")
            else:
                frame = request.frame
                if frame.url.startswith(self.native_extension_origin + "/"):
                    # The native provider owns vault authentication; MCP never handles it.
                    allowed = True
                else:
                    target = origin(request.url)
                    for site in self.config["sites"].values():
                        expected = origin(site["login_url"])
                        # Private enrollment also uses operator-opened approved pages.
                        if (
                            frame.parent_frame is None
                            and request.is_navigation_request()
                            and target == expected
                        ) or origin(frame.page.url) == expected:
                            allowed = target == expected or (
                                target in site["resource_origins"]
                                and request.method == "GET"
                                and request.resource_type
                                in {"script", "stylesheet", "font", "image"}
                            )
                            break
        except Exception:
            allowed = False
        await (route.continue_() if allowed else route.abort())

    async def _native_status(self, name: str, site: dict) -> dict:
        if name in self.pending and time.monotonic() >= self.pending[name]:
            await self.close()
            return {"status": "failed", "reason": "approval_expired", "site": name}
        session = self.sessions.get(name)
        if session and await self._authenticated(session[1], site):
            if name not in self.native_verified:
                await self.close()
                return {
                    "status": "failed",
                    "reason": "provider_verification_unconfirmed",
                    "site": name,
                }
            self.pending.pop(name, None)
            return {"status": "authenticated", "site": name}
        if name in self.pending:
            return {"status": "needs_approval", "site": name}
        return {"status": "not_authenticated", "site": name}

    async def _native_login(self, name: str, site: dict) -> dict:
        try:
            if name in self.pending or (
                name in self.sessions
                and await self._authenticated(self.sessions[name][1], site)
            ):
                return await self._native_status(name, site)
            await self._start()
            previous = self.sessions.pop(name, None)
            if previous:
                await self._quiet_close(previous[1])
            page = await self.native_context.new_page()
            page.set_default_timeout(_BROWSER_TIMEOUT_MS)
            self.sessions[name] = (self.native_context, page)
            self.native_verified.discard(name)
            page.on(
                "popup", lambda popup: asyncio.create_task(self._quiet_close(popup))
            )
            await page.goto(site["login_url"], wait_until="domcontentloaded")
            # The native provider waits for document focus before opening confirmation.
            await page.bring_to_front()
            button = page.locator(site["passkey_selector"])
            await button.wait_for(state="visible")
            if (
                origin(page.url) != origin(site["login_url"])
                or await button.count() != 1
                or not await button.is_visible()
            ):
                raise BrokerError("unsafe_form")
            self.pending[name] = time.monotonic() + _APPROVAL_SECONDS
            await button.click()
            return await self._native_status(name, site)
        except Exception:
            await self.close()
            return {
                "status": "failed",
                "reason": "native_login_unconfirmed",
                "site": name,
            }

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
            if self.native:
                return await self._native_login(name, site)
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
        if self.native_context is not None:
            await self._quiet_close(self.native_context)
        elif self.browser is not None:
            await self._quiet_close(self.browser)
        if self.playwright is not None:
            try:
                await self.playwright.stop()
            except Exception:
                pass
        self.browser = None
        self.playwright = None
        self.sessions.clear()
        self.native_context = None
        self.pending.clear()
        self.native_verified.clear()
