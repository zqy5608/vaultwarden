#!/usr/bin/env python3
"""AI side of the fill-only Agent API.

Uses VW_AGENT_TOKEN (vwagent_) to list login metadata and create a fill
ticket. Prints the ticket id and status only. This process does not call
pending or redeem, and it does not read VW_FILL_TOKEN or BW_USER_KEY.

The fill agent id is the public UUID from /admin/agents, not the vwfill_
secret. Create fill returns "Origin not allowed" until that item has a
published URI index. This script does not publish the index.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

from agent_http import ApiError, api_request, die, eprint, print_json, require_base_url, require_token

_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_CIPHERTEXT_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=|"
)
_ITEM_KEYS = ("object", "id", "name", "folderId", "folderName", "uris", "username", "reprompt")
_LIST_KEYS = ("object", "data", "truncated")
_TICKET_KEYS = ("object", "id", "status", "expiresAt", "fillAgentId")
_STATUS_KEYS = ("object", "id", "status", "expiresAt")

_HINTS = {
    "Origin not allowed": (
        "This item has no published URI index entry for that origin. "
        "Publish one with the vault user's access token (not the vwagent_ token): "
        "PUT /api/agent/items/<item-id>/uri-index "
        '{"uris":[{"uri":"https://host/path","match":1}]}. '
        "This client does not publish the index."
    ),
    "Invalid origin": "Pass an http or https origin, for example https://example.com.",
    "Fill agent not available": (
        "fillAgentId must be the UUID in the Id column on /admin/agents for an "
        "active fill agent of this user. It is not the vwfill_ secret."
    ),
    "Item not available": (
        "The item is missing, outside this token's folder allowlist, or marked "
        "for password reprompt. Reprompt items can be listed but cannot be filled."
    ),
    "Ticket not available": "The ticket id is unknown or belongs to another AI token.",
    "Agent API is disabled": "The server has AGENT_API_ENABLED unset or false.",
    "Unauthorized": "VW_AGENT_TOKEN was rejected. Create a new vwagent_ token on /admin/agents.",
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_agent.py",
        description=(
            "List vault metadata and create a fill ticket with a vwagent_ token. "
            "Does not redeem tickets or print login secrets."
        ),
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    sub = parser.add_subparsers(dest="command", required=True)

    items = sub.add_parser("items", help="list login metadata")
    items.add_argument("--url", help="only items whose URI index matches this URL")
    items.add_argument("--q", help="case-insensitive substring match")
    items.set_defaults(func=cmd_items)

    fill = sub.add_parser("fill", help="create a fill ticket")
    fill.add_argument("--item", required=True, help="cipher UUID from items")
    fill.add_argument("--origin", required=True, help="page origin, for example https://example.com")
    fill.add_argument(
        "--fill-agent-id",
        help="fill agent UUID (default: FILL_AGENT_ID). Not the vwfill_ secret",
    )
    fill.set_defaults(func=cmd_fill)

    status = sub.add_parser("status", help="read ticket id and status")
    status.add_argument("--ticket", required=True, help="ticket UUID returned by fill")
    status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    if args.timeout <= 0:
        die("--timeout must be positive")
    try:
        args.func(args)
    except ApiError as exc:
        eprint(f"ai_agent: {exc}")
        hint = _HINTS.get(exc.message)
        if hint:
            eprint(hint)
        return 1
    except KeyboardInterrupt:
        eprint("ai_agent: stopped")
        return 130
    return 0


def cmd_items(args: argparse.Namespace) -> None:
    payload = api_request(
        require_base_url(),
        "GET",
        "/api/agent/items",
        require_token("VW_AGENT_TOKEN", "agent"),
        query={"url": args.url, "q": args.q},
        timeout=args.timeout,
    )
    data = payload.get("data")
    if not isinstance(data, list):
        die("items response is missing data")
    items = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            die(f"items response data[{index}] was not an object")
        items.append(_drop_ciphertext_labels(_project(item, _ITEM_KEYS, "item")))
    listed = _project(payload, _LIST_KEYS, "item list")
    listed["data"] = items
    if "object" not in listed:
        listed = {"object": "agentItemList", **listed}
    print_json(listed)


def cmd_fill(args: argparse.Namespace) -> None:
    item_id = _require_uuid(args.item, "item id")
    fill_agent_id = _require_uuid(_fill_agent_id(args), "fill agent id")
    origin = args.origin.strip()
    if not origin:
        die("--origin is required")
    payload = api_request(
        require_base_url(),
        "POST",
        "/api/agent/fills",
        require_token("VW_AGENT_TOKEN", "agent"),
        body={"itemId": item_id, "origin": origin, "fillAgentId": fill_agent_id},
        timeout=args.timeout,
    )
    ticket = _project(payload, _TICKET_KEYS, "fill ticket")
    if not ticket.get("id") or not ticket.get("status"):
        die("fill response is missing id or status")
    print_json(ticket)


def cmd_status(args: argparse.Namespace) -> None:
    ticket_id = _require_uuid(args.ticket, "ticket id")
    payload = api_request(
        require_base_url(),
        "GET",
        "/api/agent/fills/" + ticket_id,
        require_token("VW_AGENT_TOKEN", "agent"),
        timeout=args.timeout,
    )
    ticket = _project(payload, _STATUS_KEYS, "fill status")
    if not ticket.get("id") or not ticket.get("status"):
        die("status response is missing id or status")
    print_json(ticket)


def _fill_agent_id(args: argparse.Namespace) -> str:
    value = args.fill_agent_id or os.environ.get("FILL_AGENT_ID", "")
    if not value.strip():
        die("Set --fill-agent-id or FILL_AGENT_ID to the fill agent UUID from /admin/agents.")
    return value


def _require_uuid(value: str, what: str) -> str:
    text = value.strip()
    if text.startswith("vwfill_") or text.startswith("vwagent_"):
        prefix = text.split("_", 1)[0]
        die(f"{what} must be the public UUID from /admin/agents, not a {prefix}_ secret.")
    if not _UUID.fullmatch(text):
        die(f"{what} must be a UUID.")
    return text


def _drop_ciphertext_labels(item: dict) -> dict:
    """Username and folder name are plaintext on this API. Drop EncString lookalikes."""

    for key in ("username", "folderName"):
        if _looks_like_ciphertext(item.get(key)):
            eprint(f"ai_agent: dropped ciphertext {key} from item")
            del item[key]
    return item


def _looks_like_ciphertext(value: object) -> bool:
    if not isinstance(value, str):
        return False
    text = value.strip()
    if len(text) < 8 or text[1:2] != "." or not text[0].isdigit():
        return False
    rest = text[2:]
    if any(char not in _CIPHERTEXT_CHARS for char in rest):
        return False
    return "|" in rest or len(rest) >= 16


def _project(obj: dict, allowed: tuple[str, ...], context: str) -> dict:
    allowed_set = set(allowed)
    projected = {key: obj[key] for key in allowed if key in obj}
    for key in obj:
        if key not in allowed_set:
            eprint(f"ai_agent: dropped unexpected field {key!r} from {context}")
    return projected


if __name__ == "__main__":
    sys.exit(main())
