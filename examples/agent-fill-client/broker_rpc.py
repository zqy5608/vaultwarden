"""Share one trusted browser across restricted stdio MCP connections."""

# Backend exceptions may contain private browser details; return only fixed states.
# ruff: noqa: BLE001

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
from pathlib import Path

from browser_broker import BrowserBroker, read_config

_UNAVAILABLE = {"status": "failed", "reason": "broker_unavailable"}


async def call_broker(
    path: Path,
    method: str,
    site: str | None = None,
    *,
    action: str | None = None,
    values: dict[str, str] | None = None,
) -> dict:
    """Send approved operations only; never carry credentials or arbitrary browser code."""
    writer = None
    try:
        async with asyncio.timeout(45):
            reader, writer = await asyncio.open_unix_connection(str(path), limit=65536)
            request = {"method": method}
            if site is not None:
                request["site"] = site
            if method == "action":
                request.update(action=action, values=values)
            writer.write(json.dumps(request).encode() + b"\n")
            await writer.drain()
            response = json.loads(await reader.readline())
            return response if isinstance(response, dict) else dict(_UNAVAILABLE)
    except Exception:
        return dict(_UNAVAILABLE)
    finally:
        if writer is not None:
            writer.close()


async def start_broker(path: Path, broker: BrowserBroker) -> asyncio.Server:
    metadata = path.parent.stat()
    if (
        path.parent.is_symlink()
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o077
        or path.exists()
    ):
        raise ValueError("private_unused_socket_required")

    async def handle(reader, writer):
        response = dict(_UNAVAILABLE)
        try:
            async with asyncio.timeout(45):
                request = json.loads(await reader.readline())
                if request == {"method": "sites"}:
                    response = broker.sites()
                elif (
                    isinstance(request, dict)
                    and set(request)
                    in ({"method", "site"}, {"method", "site", "action", "values"})
                    and isinstance(request["site"], str)
                    and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", request["site"])
                ):
                    if (
                        request["method"] == "action"
                        and set(request) == {"method", "site", "action", "values"}
                        and isinstance(request["action"], str)
                        and isinstance(request["values"], dict)
                    ):
                        response = await broker.action(
                            request["site"], request["action"], request["values"]
                        )
                    elif set(request) != {"method", "site"}:
                        response = dict(_UNAVAILABLE)
                    elif request["method"] == "login":
                        response = await broker.login(request["site"])
                    elif request["method"] == "status":
                        response = await broker.status(request["site"])
                    elif request["method"] == "actions":
                        response = broker.actions(request["site"])
                    elif request["method"] == "logout":
                        response = await broker.logout(request["site"])
        except Exception:
            response = dict(_UNAVAILABLE)
        try:
            writer.write(json.dumps(response).encode() + b"\n")
            await writer.drain()
        finally:
            writer.close()

    server = await asyncio.start_unix_server(handle, str(path), limit=32768)
    path.chmod(0o600)
    return server


async def serve(config_path: Path, socket_path: Path) -> None:
    broker = BrowserBroker(read_config(config_path))
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    try:
        if broker.native:
            await broker._start()
        server = await start_broker(socket_path, broker)
        async with server:
            await stopped.wait()
    finally:
        await broker.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--socket", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(serve(args.config, args.socket))
