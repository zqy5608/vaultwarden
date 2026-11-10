#!/usr/bin/env python3
"""Relay MCP and offer a private macOS confirmation outside its wire and logs."""

# Nothing from a provider, SSH exception or native dialog may be logged here.
# ruff: noqa: BLE001, S110

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import signal
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

_DIALOG = """on run argv
set targetOrigin to item 1 of argv
set reply to display dialog "Approve the pending passkey login to " & targetOrigin & ". Enter the dedicated Vaultwarden master password. It is used only for this request." with title "Vaultwarden private confirmation" default answer "" with hidden answer buttons {"Cancel", "Approve"} default button "Approve" cancel button "Cancel" giving up after 240
if gave up of reply then error number -128
return text returned of reply
end run"""


def ssh_arguments(directory: Path, host: str, identity: str) -> list[str]:
    """Keep both identities restricted; always authenticate the known host."""
    key = directory / identity
    for path in (directory, key, directory / "known_hosts"):
        metadata = path.lstat()
        if (
            path.is_symlink()
            or metadata.st_uid != os.getuid()
            or (path == directory and (not path.is_dir() or metadata.st_mode & 0o077))
            or (path != directory and not stat.S_ISREG(metadata.st_mode))
            or (path == key and metadata.st_mode & 0o077)
        ):
            raise ValueError("private_connection_files_required")
    if not re.fullmatch(r"[a-z0-9.-]+@[a-z0-9.-]+", host):
        raise ValueError("invalid_host")
    return [
        "/usr/bin/ssh",
        "-T",
        "-F",
        "/dev/null",
        "-i",
        str(key),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=" + str(directory / "known_hosts"),
        "-o",
        "ConnectTimeout=10",
        host,
    ]


def approval_origin(value: dict) -> str | None:
    if (
        not isinstance(value, dict)
        or set(value) != {"status", "request", "site", "origin"}
        or value["status"] != "needs_approval"
        or not isinstance(value["request"], str)
        or not re.fullmatch(r"[a-zA-Z0-9_-]{40,64}", value["request"])
        or not isinstance(value["site"], str)
        or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["site"])
        or not isinstance(value["origin"], str)
    ):
        return None
    parsed = urlsplit(value["origin"])
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"https://[a-zA-Z0-9.-]+(?::[0-9]{1,5})?", value["origin"])
    ):
        return None
    return value["origin"]


async def confirm(directory: Path, host: str) -> None:
    child = dialog = None
    try:
        child = await asyncio.create_subprocess_exec(
            *ssh_arguments(directory, host, "operator_identity"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=32768,
        )
        async with asyncio.timeout(305):
            pending = json.loads(await child.stdout.readline())
            target = approval_origin(pending)
            if target is None:
                return
            dialog = await asyncio.create_subprocess_exec(
                "/usr/bin/osascript",
                "-e",
                _DIALOG,
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            result, _ = await dialog.communicate()
            password = (
                result.decode().removesuffix("\n") if dialog.returncode == 0 else None
            )
            result = None
            child.stdin.write(
                json.dumps(
                    {"request": pending["request"], "password": password}
                ).encode()
                + b"\n"
            )
            password = None
            await child.stdin.drain()
            # Status is private and fixed. MCP status remains the source for the model.
            await child.stdout.readline()
    except Exception:
        pass
    finally:
        for process in (dialog, child):
            if process is not None and process.returncode is None:
                process.terminate()
                await process.wait()


def needs_confirmation(message: dict) -> bool:
    result = message.get("result", {})
    value = result.get("structuredContent")
    if isinstance(value, dict):
        return value.get("status") == "needs_approval"
    for block in result.get("content", []):
        if block.get("type") == "text":
            try:
                if json.loads(block["text"]).get("status") == "needs_approval":
                    return True
            except Exception:
                pass
    return False


async def connect(directory: Path, host: str) -> None:
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for signum in (signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(signum, task.cancel)
    child = None
    input_transport = None
    approvals = set()
    login_ids = set()
    try:
        child = await asyncio.create_subprocess_exec(
            *ssh_arguments(directory, host, "mcp_identity"),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            limit=1024 * 1024,
        )
        source = asyncio.StreamReader(limit=1024 * 1024)
        input_transport, _ = await loop.connect_read_pipe(
            lambda: asyncio.StreamReaderProtocol(source), sys.stdin.buffer
        )

        async def upstream():
            while line := await source.readline():
                try:
                    request = json.loads(line)
                    if (
                        request.get("method") == "tools/call"
                        and request.get("params", {}).get("name") == "vault_login"
                    ):
                        login_ids.add(request["id"])
                except Exception:
                    pass
                child.stdin.write(line)
                await child.stdin.drain()
            child.stdin.close()

        async def downstream():
            async for line in child.stdout:
                try:
                    message = json.loads(line)
                    if message.get("id") in login_ids:
                        login_ids.discard(message["id"])
                        if needs_confirmation(message):
                            task = asyncio.create_task(confirm(directory, host))
                            approvals.add(task)
                            task.add_done_callback(approvals.discard)
                except Exception:
                    pass
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()

        pumps = [asyncio.create_task(upstream()), asyncio.create_task(downstream())]
        try:
            await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
    except Exception:
        pass
    finally:
        if input_transport is not None:
            input_transport.close()
        for task in list(approvals):
            task.cancel()
        if approvals:
            await asyncio.gather(*list(approvals), return_exceptions=True)
        if child is not None and child.returncode is None:
            child.terminate()
            await child.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--host", required=True)
    arguments = parser.parse_args()
    asyncio.run(connect(arguments.directory, arguments.host))


if __name__ == "__main__":
    main()
