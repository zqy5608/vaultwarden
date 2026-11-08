#!/usr/bin/env python3
"""Fill side of the fill-only Agent API.

Uses VW_FILL_TOKEN (vwfill_) to read pending tickets and redeem one. The
redeem body stays in this process. Passwords and TOTP seeds are printed only
with --reveal or VW_REVEAL_PLAINTEXT=1.

Decryption is local. Set BW_USER_KEY to the unlocked user symmetric key
(the decrypted account encryption key, not BW_SESSION). The server cannot decrypt,
and this script never sends the key anywhere.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from agent_http import ApiError, api_request, die, eprint, print_json, require_base_url, require_token
from bw_crypto import BitwardenCryptoError, DecryptedFill, FieldText, decrypt_fill, load_user_key, locked_field

_HINTS = {
    "Ticket not available": (
        "The ticket may be expired, already redeemed, or the secret does not "
        "match. Tickets last AGENT_FILL_TICKET_TTL_SECS (default 60 seconds) "
        "and redeem is single-use."
    ),
    "Item not available": (
        "The item changed, is outside the AI token's folder allowlist, or is "
        "marked for password reprompt."
    ),
    "Origin not allowed": (
        "The ticket origin no longer matches the item's published URI index."
    ),
    "Agent API is disabled": "The server has AGENT_API_ENABLED unset or false.",
    "Unauthorized": (
        "VW_FILL_TOKEN was rejected. Use the vwfill_ secret from /admin/agents. "
        "The Id column is not the secret."
    ),
}
_PENDING_KEYS = {"object", "id", "itemId", "origin", "expiresAt", "redeemSecret"}
_LOGIN_KEYS = {"username", "password", "totp"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fill_agent.py",
        description=(
            "Poll and redeem one fill ticket with a vwfill_ token. "
            "Decrypts Bitwarden ciphertext locally when BW_USER_KEY is set."
        ),
    )
    parser.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout in seconds")
    sub = parser.add_subparsers(dest="command", required=True)

    pending = sub.add_parser("pending", help="list tickets waiting for this fill agent")
    pending.add_argument(
        "--show-secret",
        action="store_true",
        help="print each one-time redeem secret (default hides it)",
    )
    pending.set_defaults(func=cmd_pending)

    redeem = sub.add_parser("redeem", help="redeem one pending ticket")
    redeem.add_argument("--ticket", help="ticket UUID (default: soonest expiry)")
    redeem.add_argument("--secret", help="redeem secret, if you already have it")
    _add_output_flags(redeem)
    redeem.set_defaults(func=cmd_redeem)

    poll = sub.add_parser("poll", help="wait for one ticket, then redeem it")
    poll.add_argument("--ticket", help="wait for this ticket UUID only")
    poll.add_argument("--interval", type=float, default=2.0, help="seconds between polls")
    poll.add_argument("--wait", type=float, default=90.0, help="give up after this many seconds")
    _add_output_flags(poll)
    poll.set_defaults(func=cmd_poll)

    args = parser.parse_args(argv)
    if args.timeout <= 0:
        die("--timeout must be positive")
    try:
        return args.func(args)
    except ApiError as exc:
        eprint(f"fill_agent: {exc}")
        hint = _HINTS.get(exc.message)
        if hint:
            eprint(hint)
        return 1
    except KeyboardInterrupt:
        eprint("fill_agent: stopped")
        return 130


def _add_output_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--reveal",
        action="store_true",
        help="print decrypted password and TOTP (or set VW_REVEAL_PLAINTEXT=1)",
    )


def cmd_pending(args: argparse.Namespace) -> int:
    tickets = _fetch_pending(args)
    print_json(
        {
            "object": "fillAgentTicketList",
            "data": [_public_ticket(ticket, args.show_secret) for ticket in tickets],
        }
    )
    return 0


def cmd_redeem(args: argparse.Namespace) -> int:
    if args.secret and not args.ticket:
        die("redeem --secret requires --ticket")
    if args.secret:
        ticket_id = args.ticket.strip()
        secret = args.secret
    else:
        chosen = _select_ticket(_fetch_pending(args), args.ticket)
        ticket_id = chosen["id"]
        secret = chosen["redeemSecret"]
    payload = _redeem(args, ticket_id, secret)
    return _emit_result(args, payload)


def cmd_poll(args: argparse.Namespace) -> int:
    if args.interval <= 0:
        die("--interval must be positive")
    if args.wait < 0:
        die("--wait must be >= 0")
    deadline = time.monotonic() + args.wait
    announced = False
    while True:
        chosen = _select_ticket(_fetch_pending(args), args.ticket, missing_ok=True)
        if chosen is not None:
            payload = _redeem(args, chosen["id"], chosen["redeemSecret"])
            eprint(f"fill_agent: redeemed {chosen['id']}")
            return _emit_result(args, payload)
        if time.monotonic() >= deadline:
            die("no pending fill ticket")
        if not announced:
            eprint("fill_agent: waiting for a fill ticket")
            announced = True
        time.sleep(min(args.interval, max(0.0, deadline - time.monotonic())))


def _fetch_pending(args: argparse.Namespace) -> list[dict]:
    payload = api_request(
        require_base_url(),
        "GET",
        "/api/agent/fill-agent/pending",
        require_token("VW_FILL_TOKEN", "fill"),
        timeout=args.timeout,
    )
    data = payload.get("data")
    if not isinstance(data, list):
        die("pending response is missing data")
    tickets = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            die(f"pending response data[{index}] was not an object")
        for key in item:
            if key not in _PENDING_KEYS:
                eprint(f"fill_agent: dropped unexpected field {key!r} from pending ticket")
        ticket_id = item.get("id")
        secret = item.get("redeemSecret")
        if not isinstance(ticket_id, str) or not ticket_id:
            die("pending ticket is missing id")
        if not isinstance(secret, str) or not secret:
            die("pending ticket is missing redeemSecret")
        tickets.append(item)
    return tickets


def _select_ticket(tickets: list[dict], ticket_id: str | None, missing_ok: bool = False) -> dict | None:
    if ticket_id:
        matches = [ticket for ticket in tickets if ticket.get("id") == ticket_id]
        if not matches:
            if missing_ok:
                return None
            die(f"ticket {ticket_id} is not pending")
        return matches[0]
    if not tickets:
        if missing_ok:
            return None
        die("no pending fill ticket")
    return sorted(tickets, key=lambda ticket: (str(ticket.get("expiresAt") or ""), str(ticket.get("id") or "")))[0]


def _public_ticket(ticket: dict, show_secret: bool) -> dict:
    view = {
        "object": "fillAgentTicket",
        "id": ticket.get("id"),
        "itemId": ticket.get("itemId"),
        "origin": ticket.get("origin"),
        "expiresAt": ticket.get("expiresAt"),
    }
    if show_secret:
        view["redeemSecret"] = ticket.get("redeemSecret")
    else:
        view["hasRedeemSecret"] = bool(ticket.get("redeemSecret"))
    return view


def _redeem(args: argparse.Namespace, ticket_id: str, secret: str) -> dict:
    payload = api_request(
        require_base_url(),
        "POST",
        "/api/agent/fill-agent/redeem",
        require_token("VW_FILL_TOKEN", "fill"),
        body={"ticketId": ticket_id, "secret": secret},
        timeout=args.timeout,
    )
    for key in payload:
        if key not in {"object", "ticketId", "itemId", "origin", "key", "login"}:
            eprint(f"fill_agent: dropped unexpected field {key!r} from redeem response")
    login = payload.get("login")
    if not isinstance(login, dict):
        die("redeem response is missing login")
    for key in login:
        if key not in _LOGIN_KEYS:
            eprint(f"fill_agent: dropped unexpected field {key!r} from redeem login")
    return payload


def _emit_result(args: argparse.Namespace, payload: dict) -> int:
    reveal = _want_reveal(args)
    try:
        user_key = _optional_user_key()
    except BitwardenCryptoError as exc:
        die(f"BW_USER_KEY: {exc}")
    login = payload["login"]
    if user_key is None:
        decrypted = DecryptedFill(
            username=locked_field(login.get("username")),
            password=locked_field(login.get("password")),
            totp=locked_field(login.get("totp")),
            item_key="skipped" if payload.get("key") else "none",
        )
        user_key_state = "missing"
    else:
        decrypted = decrypt_fill(
            login.get("username"),
            login.get("password"),
            login.get("totp"),
            payload.get("key"),
            user_key,
        )
        user_key_state = "present"
    if decrypted.error:
        eprint(f"fill_agent: decryption failed: {decrypted.error}")
    elif user_key is None and _ciphertext_secrets(decrypted):
        eprint(
            "fill_agent: password or TOTP is still ciphertext. "
            "Set BW_USER_KEY to decrypt it. The received ciphertext is in this result "
            "because redeem is single-use. Pass --reveal to print plaintext."
        )
    result = _result_json(payload, decrypted, user_key_state, reveal)
    print_json(result)
    if decrypted.error:
        return 1
    return 0


def _ciphertext_secrets(decrypted: DecryptedFill) -> bool:
    return decrypted.password.state == "ciphertext" or decrypted.totp.state == "ciphertext"


def _result_json(
    payload: dict,
    decrypted: DecryptedFill,
    user_key_state: str,
    reveal: bool,
) -> dict:
    # Plaintext passwords require --reveal. The received object always keeps
    # the server fields: redeem cannot be repeated if decryption is declined.
    show_plain = reveal and decrypted.ok
    login = payload.get("login") if isinstance(payload.get("login"), dict) else {}
    key = payload.get("key")
    result = {
        "object": "fillResult",
        "ticketId": payload.get("ticketId"),
        "itemId": payload.get("itemId"),
        "origin": payload.get("origin"),
        "revealed": show_plain,
        "login": {
            "username": _shown(decrypted.username, secret=False, reveal=show_plain),
            "password": _shown(decrypted.password, secret=True, reveal=show_plain),
            "totp": _shown(decrypted.totp, secret=True, reveal=show_plain),
        },
        "received": {
            "key": key if isinstance(key, str) and key else None,
            "username": _received_text(login.get("username")),
            "password": _received_text(login.get("password")),
            "totp": _received_text(login.get("totp")),
        },
        "decryption": {
            "userKey": user_key_state,
            "itemKey": decrypted.item_key,
            "username": decrypted.username.state,
            "password": decrypted.password.state,
            "totp": decrypted.totp.state,
        },
    }
    if decrypted.error:
        result["error"] = decrypted.error
    return result


def _shown(field: FieldText, *, secret: bool, reveal: bool) -> str | None:
    if field.state not in {"plaintext", "decrypted", "empty"}:
        return None
    if field.state == "empty":
        return "" if reveal or not secret else None
    if secret and not reveal:
        return None
    return field.value


def _received_text(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _want_reveal(args: argparse.Namespace) -> bool:
    if args.reveal:
        return True
    return os.environ.get("VW_REVEAL_PLAINTEXT", "").strip().lower() in {"1", "true", "yes", "on"}


def _optional_user_key() -> bytes | None:
    raw = os.environ.get("BW_USER_KEY")
    if raw is None or raw.strip() == "":
        return None
    return load_user_key(raw)


if __name__ == "__main__":
    sys.exit(main())
