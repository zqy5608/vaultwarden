"""MCP exposes site-bound actions only; the trusted broker owns every secret."""

# Configuration errors may contain private values; expose only an unconfigured state.
# ruff: noqa: BLE001

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from broker_rpc import call_broker
from browser_broker import (
    BrokerError,
    BrowserBroker,
    origin,
    read_config,
    validate_config,
)

DEFAULT_CONFIG = Path.home() / ".config/vaultwarden-agent/config.json"


def create_server(config_path: Path, broker_socket: Path | None = None):
    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations

    broker = None
    if broker_socket is None:
        try:
            broker = BrowserBroker(read_config(config_path))
        except Exception:
            broker = BrowserBroker(None)

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield
        finally:
            if broker is not None:
                await broker.close()

    server = MCPServer(
        "Vaultwarden trusted login",
        instructions=(
            "Use approved site names only. Call vault_login; needs_approval opens a "
            "private operator confirmation. Never request a password, code, key or VNC "
            "setup in chat. Poll vault_status for completion; do not retry a failed or "
            "cancelled login without the operator. After authentication use vault_actions "
            "and vault_action with nonsecret inputs in the same session. Use vault_logout "
            "when finished. No arbitrary URLs, scripts, page contents or session exports."
        ),
        lifespan=lifespan,
        log_level="WARNING",
    )

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def vault_sites() -> dict:
        """List operator-approved login sites and origins. Returns no vault credentials."""
        if broker_socket is not None:
            return await call_broker(broker_socket, "sites")
        return broker.sites()

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def vault_login(site: str) -> dict:
        """Log in to an approved site in the private browser; return only a fixed status.

        The operator must configure the site first. This tool never returns passwords,
        page contents, cookies or screenshots. It cannot access arbitrary URLs.
        """
        if broker_socket is not None:
            return await call_broker(broker_socket, "login", site)
        return await broker.login(site)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def vault_status(site: str) -> dict:
        """Check the approved post-login path and element without returning browser data."""
        if broker_socket is not None:
            return await call_broker(broker_socket, "status", site)
        return await broker.status(site)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def vault_actions(site: str) -> dict:
        """List operator-approved action and input names; never return page contents or selectors."""
        if broker_socket is not None:
            return await call_broker(broker_socket, "actions", site)
        return broker.actions(site)

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=False,
            openWorldHint=True,
        )
    )
    async def vault_action(site: str, action: str, values: dict[str, str]) -> dict:
        """Run a configured same-origin form action in the authenticated private session.

        Supply only the listed nonsecret input fields. This tool accepts no URLs,
        selectors or scripts, and returns no page contents or input values.
        """
        if broker_socket is not None:
            return await call_broker(
                broker_socket, "action", site, action=action, values=values
            )
        return await broker.action(site, action, values)

    @server.tool(
        annotations=ToolAnnotations(
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=True,
        )
    )
    async def vault_logout(site: str) -> dict:
        """Run the approved sign-out when configured, then discard the private browser session."""
        if broker_socket is not None:
            return await call_broker(broker_socket, "logout", site)
        return await broker.logout(site)

    return server


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the trusted Vaultwarden MCP server over stdio."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--broker-socket", type=Path)
    args = parser.parse_args()
    create_server(args.config, args.broker_socket).run(transport="stdio")


def unlock_user_key(server: str, email: str, password: str) -> str:
    """Authenticate privately and unwrap the account key; never use BW_SESSION."""
    from publish_uri import login

    if server.rstrip("/") != origin(server, local=True):
        raise BrokerError("invalid_server")
    session = login(
        server.rstrip("/"), email.strip().lower(), password, 15, need_key=True
    )
    return base64.b64encode(session["user_key"]).decode("ascii")


def setup() -> None:
    parser = argparse.ArgumentParser(
        description="Privately configure credentials; never run inside an AI transcript."
    )
    parser.add_argument(
        "--sites", type=Path, required=True, help="operator-approved site profiles JSON"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--headless", action="store_true", help="run without a display")
    args = parser.parse_args()
    if not os.isatty(0) or not os.isatty(2):
        parser.error("setup requires your own interactive terminal")
    try:
        if args.config.exists() or args.config.is_symlink():
            raise BrokerError("config_already_exists")
        server = input("Vaultwarden HTTPS origin: ").strip().rstrip("/")
        email = input("Vault account email: ").strip().lower()
        user_key = unlock_user_key(server, email, getpass.getpass("Master password: "))
        config = {
            "server_url": server,
            "agent_token": getpass.getpass("AI-scoped token: ").strip(),
            "fill_token": getpass.getpass("Fill-scoped token: ").strip(),
            "fill_agent_id": input("Fill agent UUID: ").strip(),
            "user_key": user_key,
            "sites": json.loads(args.sites.read_text()),
            "headless": args.headless,
        }
        validate_config(config)
        args.config.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if args.config.parent.is_symlink():
            raise BrokerError("private_config_required")
        if (
            args.config.parent.stat().st_mode & 0o077
            or args.config.parent.stat().st_uid != os.getuid()
        ):
            raise BrokerError("private_config_required")
        encoded = json.dumps(config)
        if len(encoded.encode()) > 65_536:
            raise BrokerError("invalid_config")
        fd = os.open(args.config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(encoded)
    except Exception:
        parser.error(
            "configuration was not saved; check vault authentication, the profile and private destination"
        )
    print("Private configuration saved. Restart the MCP connection to load it.")


if __name__ == "__main__":
    main()
