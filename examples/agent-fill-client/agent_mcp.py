"""MCP exposes site-bound actions only; the trusted broker owns every secret."""

# Configuration errors may contain private values; expose only an unconfigured state.
# ruff: noqa: BLE001

from __future__ import annotations

import argparse
import getpass
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

from browser_broker import BrokerError, BrowserBroker, read_config, validate_config

DEFAULT_CONFIG = Path.home() / ".config/vaultwarden-agent/config.json"


def create_server(config_path: Path):
    from mcp.server import MCPServer
    from mcp.types import ToolAnnotations

    try:
        config = read_config(config_path)
        broker = BrowserBroker(config)
    except Exception:
        broker = BrowserBroker(None)

    @asynccontextmanager
    async def lifespan(server):
        try:
            yield
        finally:
            await broker.close()

    server = MCPServer(
        "Vaultwarden trusted login", lifespan=lifespan, log_level="WARNING"
    )

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def vault_sites() -> dict:
        """List operator-approved login sites and origins. Returns no vault credentials."""
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
        return await broker.login(site)

    @server.tool(annotations=ToolAnnotations(readOnlyHint=True, openWorldHint=False))
    async def vault_status(site: str) -> dict:
        """Check the approved post-login path and element without returning browser data."""
        return await broker.status(site)

    return server


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the trusted Vaultwarden MCP server over stdio."
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    create_server(args.config).run(transport="stdio")


def setup() -> None:
    parser = argparse.ArgumentParser(
        description="Privately configure credentials; never run inside an AI transcript."
    )
    parser.add_argument(
        "--sites", type=Path, required=True, help="operator-approved site profiles JSON"
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    args = parser.parse_args()
    if not os.isatty(0) or not os.isatty(2):
        parser.error("setup requires your own interactive terminal")
    config = {
        "server_url": input("Vaultwarden HTTPS origin: ").strip(),
        "agent_token": getpass.getpass("AI-scoped token: ").strip(),
        "fill_token": getpass.getpass("Fill-scoped token: ").strip(),
        "fill_agent_id": input("Fill agent UUID: ").strip(),
        "user_key": getpass.getpass("Unlocked user symmetric key: ").strip(),
        "sites": json.loads(args.sites.read_text()),
    }
    try:
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
            "configuration was not saved; check the profile and private destination"
        )
    print("Private configuration saved. Restart the MCP connection to load it.")


if __name__ == "__main__":
    main()
