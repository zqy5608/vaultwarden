#!/usr/bin/env python3
"""Publish website origins for the fill-only Agent API.

The vault user runs this. It signs in with the account email and master
password, or it uses a one-shot user access token. It decrypts login names
and website fields locally and sends those websites to uri-index.

It does not decrypt passwords, TOTP, notes, or card data, and it does not
print them. vwagent_ and vwfill_ tokens are rejected.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import platform
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

from agent_http import die, eprint, print_json, require_base_url

_MAX_BODY = 8 * 1024 * 1024
_USER_AGENT = "vaultwarden-agent-uri/1.0"
_UUID = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_DEVICE_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")
_PROVIDER_LABELS = {
    "0": "authenticator",
    "1": "email",
    "3": "YubiKey",
    "8": "recovery code",
}


class VaultFailure(Exception):
    """A publish step failed with a message that is safe to print."""


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise VaultFailure("refusing to follow a redirect")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="publish_uri.py",
        description=(
            "Publish https origins for a personal login. Uses the vault user's "
            "own login. Does not decrypt or send passwords."
        ),
    )
    parser.add_argument("--timeout", type=float, default=60.0, help="HTTP timeout in seconds")
    sub = parser.add_subparsers(dest="command", required=True)

    publish = sub.add_parser(
        "publish",
        help="decrypt websites from the vault and publish them",
    )
    publish.add_argument("--email", help="account email (or VW_USER_EMAIL)")
    publish.add_argument("--item", action="append", default=[], help="cipher UUID to publish")
    publish.add_argument(
        "--name",
        action="append",
        default=[],
        help="case-insensitive substring of the decrypted login name",
    )
    publish.add_argument(
        "--all",
        action="store_true",
        help="publish every personal login that has an http(s) website",
    )
    publish.add_argument(
        "--uri",
        action="append",
        default=[],
        help="publish these websites instead of the ones stored on the login",
    )
    publish.add_argument(
        "--match",
        type=int,
        choices=(0, 1, 2, 3),
        help="URI match for every published website (default: the login's match, or strict host)",
    )
    publish.add_argument(
        "--dry-run",
        action="store_true",
        help="print the websites that would be published and do not call uri-index",
    )
    publish.set_defaults(func=cmd_publish)

    put = sub.add_parser("put", help="publish websites you already know")
    put.add_argument("--email", help="account email, when VW_USER_TOKEN is not set")
    put.add_argument("--item", required=True, help="cipher UUID")
    put.add_argument("--uri", action="append", required=True, help="website to publish")
    put.add_argument("--match", type=int, choices=(0, 1, 2, 3))
    put.add_argument("--dry-run", action="store_true")
    put.set_defaults(func=cmd_put)

    clear = sub.add_parser("clear", help="remove published websites for a login")
    clear.add_argument("--email", help="account email, when VW_USER_TOKEN is not set")
    clear.add_argument("--item", action="append", required=True, help="cipher UUID")
    clear.add_argument("--dry-run", action="store_true")
    clear.set_defaults(func=cmd_clear)

    args = parser.parse_args(argv)
    if args.timeout <= 0:
        die("--timeout must be positive")
    try:
        return args.func(args)
    except VaultFailure as exc:
        eprint(f"publish_uri: {exc}")
        return 1
    except KeyboardInterrupt:
        eprint("publish_uri: stopped")
        return 130


def cmd_put(args: argparse.Namespace) -> int:
    check_uuid(args.item)
    uris = explicit_uris(args.uri, args.match)
    if args.dry_run:
        return emit(
            [{"id": args.item, "name": None, "uris": [entry["uri"] for entry in uris], "reprompt": False}],
            [],
            dry_run=True,
        )
    token = user_token(args)
    published, skipped = send_index(require_base_url(), token, args.item, None, uris, args.timeout)
    return emit(published, skipped, dry_run=False)


def cmd_clear(args: argparse.Namespace) -> int:
    cleared: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    if args.dry_run:
        for item_id in args.item:
            check_uuid(item_id)
            cleared.append({"id": item_id, "uris": []})
        print_json({"object": "agentUriPublish", "dryRun": True, "cleared": cleared, "skipped": []})
        eprint("Dry run: no index update.")
        return 0
    token = user_token(args)
    base = require_base_url()
    for item_id in args.item:
        check_uuid(item_id)
        response = vault_request(
            base,
            "DELETE",
            f"/api/agent/items/{item_id}/uri-index",
            token=token,
            timeout=args.timeout,
        )
        if response.status >= 400:
            skipped.append({"id": item_id, "name": None, "reason": error_message(response), "error": True})
            continue
        cleared.append({"id": item_id, "uris": response.body.get("uris") or []})
    print_json({"object": "agentUriPublish", "dryRun": False, "cleared": cleared, "skipped": skipped})
    if skipped or not cleared:
        eprint("No website index was cleared.")
        return 1
    return 0


def cmd_publish(args: argparse.Namespace) -> int:
    if not args.all and not args.item and not args.name and not args.uri:
        raise VaultFailure(
            "Pass --item, --name, or --all. --all publishes every personal login that has an http(s) website."
        )
    for item_id in args.item:
        check_uuid(item_id)
    if args.uri:
        return publish_explicit(args)
    session = open_vault(args)
    eprint("Reading logins.")
    sync = vault_request(
        session["base"],
        "GET",
        "/api/sync",
        token=session["token"],
        timeout=args.timeout,
    )
    if sync.status >= 400:
        raise VaultFailure(error_message(sync))
    ciphers = sync.body.get("ciphers")
    if ciphers is None:
        ciphers = sync.body.get("Ciphers")
    if not isinstance(ciphers, list):
        raise VaultFailure("sync response did not include ciphers")
    from bw_crypto import BitwardenCryptoError, decrypt_fill

    published: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen: set[str] = set()
    for cipher in ciphers:
        if not isinstance(cipher, dict) or not personal_login(cipher):
            continue
        item_id = cipher.get("id")
        if not isinstance(item_id, str):
            continue
        seen.add(item_id)
        if args.item and item_id not in args.item:
            continue
        try:
            name = decrypt_text(cipher.get("name"), session["user_key"], cipher.get("key"), decrypt_fill)
        except BitwardenCryptoError as exc:
            raise VaultFailure(f"could not decrypt login names: {exc}") from exc
        if args.name and not name_matches(name, args.name):
            continue
        uris, uri_error = decrypted_uris(cipher, session["user_key"], args.match, decrypt_fill)
        if uri_error:
            skipped.append({"id": item_id, "name": name, "reason": uri_error, "error": True})
            continue
        if not uris:
            skipped.append({"id": item_id, "name": name, "reason": "no http(s) website"})
            continue
        if args.dry_run:
            published.append(row(item_id, name, uris, cipher))
            continue
        done, failed = send_index(session["base"], session["token"], item_id, name, uris, args.timeout)
        published.extend(done)
        skipped.extend(failed)
        if published and published[-1]["id"] == item_id:
            published[-1]["reprompt"] = is_reprompt(cipher)
    if args.item:
        for item_id in args.item:
            if item_id not in seen:
                skipped.append({"id": item_id, "name": None, "reason": "not an active personal login"})
    return emit(published, skipped, dry_run=args.dry_run)


def publish_explicit(args: argparse.Namespace) -> int:
    if not args.item:
        raise VaultFailure("Pass --item when publishing websites with --uri.")
    uris = explicit_uris(args.uri, args.match)
    preview = [
        {"id": item_id, "name": None, "uris": [entry["uri"] for entry in uris], "reprompt": False}
        for item_id in args.item
    ]
    if args.dry_run:
        return emit(preview, [], dry_run=True)
    token = user_token(args)
    base = require_base_url()
    published: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for item_id in args.item:
        done, failed = send_index(base, token, item_id, None, uris, args.timeout)
        published.extend(done)
        skipped.extend(failed)
    return emit(published, skipped, dry_run=False)


def open_vault(args: argparse.Namespace) -> dict[str, Any]:
    """Return base URL, user access token, and unlocked user key."""

    base = require_base_url()
    token = os.environ.get("VW_USER_TOKEN", "").strip()
    raw_key = os.environ.get("BW_USER_KEY", "").strip()
    if token and raw_key:
        reject_agent_token(token)
        from bw_crypto import BitwardenCryptoError, load_user_key

        try:
            user_key = load_user_key(raw_key)
        except BitwardenCryptoError as exc:
            raise VaultFailure(str(exc)) from exc
        return {"base": base, "token": token, "user_key": user_key}
    if token and not raw_key:
        raise VaultFailure(
            "VW_USER_TOKEN is set without BW_USER_KEY. Sign in with --email and the master "
            "password, or publish known websites with: publish_uri.py put --item ID --uri https://example.com"
        )
    email = (args.email or os.environ.get("VW_USER_EMAIL", "")).strip().lower()
    if not email or "@" not in email:
        raise VaultFailure("Pass --email or set VW_USER_EMAIL. This is the vault account, not an agent token.")
    password = read_secret("VW_MASTER_PASSWORD", "Master password: ")
    try:
        return login(base, email, password, args.timeout, need_key=True)
    finally:
        password = ""


def login(base: str, email: str, password: str, timeout: float, *, need_key: bool) -> dict[str, Any]:
    from bw_kdf import KdfError, derive_master_key, master_password_hash, unwrap_account_key

    eprint(f"Signing in as {email}.")
    pre = vault_request(
        base,
        "POST",
        "/identity/accounts/prelogin",
        json_body={"email": email},
        timeout=timeout,
    )
    if pre.status >= 400:
        raise VaultFailure(error_message(pre))
    try:
        kdf = int(pre.body.get("kdf") or 0)
        iterations = int(pre.body.get("kdfIterations"))
    except (TypeError, ValueError) as exc:
        raise VaultFailure("prelogin did not include KDF settings") from exc
    memory = _optional_int(pre.body.get("kdfMemory"))
    parallel = _optional_int(pre.body.get("kdfParallelism"))
    try:
        master = derive_master_key(password, email, kdf, iterations, memory, parallel)
        password_hash = master_password_hash(master, password)
    except KdfError as exc:
        raise VaultFailure(str(exc)) from exc
    form = login_form(email, password_hash)
    token_response = vault_request(base, "POST", "/identity/connect/token", form=form, timeout=timeout)
    if needs_two_factor(token_response):
        provider = choose_provider(token_response.body.get("TwoFactorProviders") or [])
        if should_send_email(provider, os.environ.get("VW_TWO_FACTOR_CODE", "")):
            send_email_code(base, email, password_hash, form["deviceIdentifier"], timeout)
            eprint("Sent a two-step code by email.")
        if provider == "8":
            eprint("A recovery code turns off two-step login on this account.")
        code = read_secret("VW_TWO_FACTOR_CODE", f"Two-step code ({_PROVIDER_LABELS.get(provider, provider)}): ")
        form["twoFactorProvider"] = provider
        form["twoFactorToken"] = code.strip()
        token_response = vault_request(base, "POST", "/identity/connect/token", form=form, timeout=timeout)
    if token_response.status >= 400:
        raise VaultFailure(error_message(token_response))
    token = token_response.body.get("access_token")
    if not isinstance(token, str) or not token:
        raise VaultFailure("login response did not include an access token")
    reject_agent_token(token)
    user_key = None
    if need_key:
        from bw_crypto import BitwardenCryptoError

        blob = account_key_blob(token_response.body)
        if blob is None:
            raise VaultFailure(
                "This login has no master-password account key. Unlock the web vault and use Agent sites, "
                "or set VW_USER_TOKEN and BW_USER_KEY."
            )
        try:
            user_key = unwrap_account_key(blob, master)
        except (BitwardenCryptoError, KdfError) as exc:
            raise VaultFailure("the account key did not unwrap with this master password") from exc
    return {"base": base, "token": token, "user_key": user_key}


def login_form(email: str, password_hash: str) -> dict[str, str]:
    system = platform.system()
    device_type = {"Linux": "25", "Darwin": "24", "Windows": "23"}.get(system, "14")
    device_id = os.environ.get("VW_DEVICE_ID", "").strip() or str(
        uuid.uuid5(_DEVICE_NS, f"vaultwarden-agent-uri\n{email}\n{platform.node()}")
    )
    if not _UUID.match(device_id):
        raise VaultFailure("VW_DEVICE_ID must be a UUID")
    return {
        "grant_type": "password",
        "username": email,
        "password": password_hash,
        "scope": "api offline_access",
        "client_id": "cli",
        "deviceType": device_type,
        "deviceName": "vaultwarden-agent-uri",
        "deviceIdentifier": device_id,
    }


def send_email_code(base: str, email: str, password_hash: str, device_id: str, timeout: float) -> None:
    response = vault_request(
        base,
        "POST",
        "/api/two-factor/send-email-login",
        json_body={
            "email": email,
            "masterPasswordHash": password_hash,
            "deviceIdentifier": device_id,
        },
        timeout=timeout,
    )
    if response.status >= 400:
        raise VaultFailure(error_message(response))


def user_token(args: argparse.Namespace) -> str:
    token = os.environ.get("VW_USER_TOKEN", "").strip()
    if token:
        reject_agent_token(token)
        return token
    email = (getattr(args, "email", None) or os.environ.get("VW_USER_EMAIL", "")).strip().lower()
    if not email or "@" not in email:
        raise VaultFailure(
            "Set VW_USER_TOKEN to a vault user access token, or pass --email and the master password. "
            "Do not use a vwagent_ or vwfill_ token."
        )
    password = read_secret("VW_MASTER_PASSWORD", "Master password: ")
    try:
        session = login(require_base_url(), email, password, args.timeout, need_key=False)
    finally:
        password = ""
    return session["token"]


def reject_agent_token(token: str) -> None:
    if token.startswith(("vwagent_", "vwfill_")):
        raise VaultFailure(
            "uri-index needs the vault user's access token. vwagent_ and vwfill_ cannot publish websites."
        )


def explicit_uris(values: list[str], match: int | None) -> list[dict[str, Any]]:
    uris: list[dict[str, Any]] = []
    for value in values:
        cleaned = publishable_uri(value)
        if cleaned is None:
            raise VaultFailure("a website was not an http or https URL")
        entry: dict[str, Any] = {"uri": cleaned}
        if match is not None:
            entry["match"] = match
        uris.append(entry)
    if not uris:
        raise VaultFailure("pass at least one --uri")
    if len(uris) > 20:
        raise VaultFailure("a login can publish at most 20 websites")
    return uris


def decrypted_uris(
    cipher: dict[str, Any],
    user_key: bytes,
    match_override: int | None,
    decrypt_fill: Any,
) -> tuple[list[dict[str, Any]], str | None]:
    from bw_crypto import BitwardenCryptoError

    uris: list[dict[str, Any]] = []
    seen: set[tuple[str, int | None]] = set()
    try:
        for raw, match in login_uri_fields(cipher):
            text = decrypt_text(raw, user_key, cipher.get("key"), decrypt_fill)
            if text is None:
                if isinstance(raw, str) and raw.startswith(("0.", "2.")):
                    return [], "a website could not be decrypted"
                continue
            cleaned = publishable_uri(text)
            if cleaned is None:
                continue
            match_type = match_override if match_override is not None else usable_match(match)
            if match_type is False:
                continue
            key = (cleaned, match_type)
            if key in seen:
                continue
            seen.add(key)
            entry: dict[str, Any] = {"uri": cleaned}
            if match_type is not None:
                entry["match"] = match_type
            uris.append(entry)
            if len(uris) == 20:
                break
    except BitwardenCryptoError as exc:
        return [], f"a website could not be decrypted: {exc}"
    return uris, None


def login_uri_fields(cipher: dict[str, Any]) -> list[tuple[Any, Any]]:
    login = cipher.get("login")
    if not isinstance(login, dict):
        return []
    found: list[tuple[Any, Any]] = []
    uris = login.get("uris")
    if isinstance(uris, list):
        for entry in uris:
            if isinstance(entry, dict):
                found.append((entry.get("uri", entry.get("Uri")), entry.get("match", entry.get("Match"))))
            elif isinstance(entry, str):
                found.append((entry, None))
    if not found and isinstance(login.get("uri"), str):
        found.append((login["uri"], None))
    return found


def decrypt_text(value: Any, user_key: bytes, cipher_key: Any, decrypt_fill: Any) -> str | None:
    if not isinstance(value, str) or value == "":
        return None
    wrapped = cipher_key if isinstance(cipher_key, str) and cipher_key else None
    result = decrypt_fill(value, None, None, wrapped, user_key)
    if not result.ok or result.username.value is None:
        return None
    if result.username.state in {"ciphertext", "failed", "invalid"}:
        return None
    return result.username.value


def publishable_uri(value: str) -> str | None:
    """Return an http(s) URL without userinfo, query, or fragment."""

    text = value.strip()
    if not text or len(text) > 2048 or any(char.isspace() or ord(char) < 32 or char == "\\" for char in text):
        return None
    if "://" not in text:
        if "@" in text.split("/", 1)[0]:
            return None
        text = "https://" + text
    parts = urllib.parse.urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        return None
    host = parts.hostname
    ip_like = ":" in host or host.replace(".", "").isdigit()
    if "." not in host and not ip_like:
        return None
    if ":" in host:
        host = f"[{host}]"
    netloc = host
    if parts.port:
        netloc = f"{host}:{parts.port}"
    path = parts.path or ""
    return urllib.parse.urlunsplit((parts.scheme, netloc, path, "", ""))


def usable_match(value: Any) -> int | None | bool:
    """Return a match type, None for the default, or False to skip the URI."""

    if value is None:
        return None
    if isinstance(value, bool):
        return False
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        value = int(value)
    if isinstance(value, int) and value in {0, 1, 2, 3}:
        return value
    if isinstance(value, int) and value in {4, 5}:
        return False
    return None


def personal_login(cipher: dict[str, Any]) -> bool:
    if cipher.get("organizationId"):
        return False
    if cipher.get("type") not in (1, "1"):
        return False
    return not cipher.get("deletedDate")


def is_reprompt(cipher: dict[str, Any]) -> bool:
    return cipher.get("reprompt") in (1, "1")


def name_matches(name: str | None, needles: list[str]) -> bool:
    if not name:
        return False
    folded = name.casefold()
    return any(needle.casefold() in folded for needle in needles if needle)


def row(item_id: str, name: str | None, uris: list[dict[str, Any]], cipher: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item_id,
        "name": name,
        "uris": [entry["uri"] for entry in uris],
        "reprompt": is_reprompt(cipher),
    }


def send_index(
    base: str,
    token: str,
    item_id: str,
    name: str | None,
    uris: list[dict[str, Any]],
    timeout: float,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    check_uuid(item_id)
    response = vault_request(
        base,
        "PUT",
        f"/api/agent/items/{item_id}/uri-index",
        token=token,
        json_body={"uris": uris},
        timeout=timeout,
    )
    if response.status >= 400:
        return [], [{"id": item_id, "name": name, "reason": error_message(response), "error": True}]
    stored = response.body.get("uris")
    if not isinstance(stored, list):
        stored = [entry["uri"] for entry in uris]
    return [{"id": item_id, "name": name, "uris": stored, "reprompt": False}], []


def emit(published: list[dict[str, Any]], skipped: list[dict[str, Any]], *, dry_run: bool) -> int:
    print_json(
        {
            "object": "agentUriPublish",
            "dryRun": dry_run,
            "published": published,
            "skipped": [{key: value for key, value in item.items() if key != "error"} for item in skipped],
        }
    )
    failed = any(item.get("error") for item in skipped)
    if dry_run and published and not failed:
        eprint(f"Dry run: {len(published)} login(s), no index update.")
        return 0
    if failed:
        eprint("Some logins were not published." if published else "No website was published.")
        return 1
    if not published:
        eprint("No website was published.")
        return 1
    return 0


def needs_two_factor(response: "VaultResponse") -> bool:
    return (
        response.status == 400
        and response.body.get("error") == "invalid_grant"
        and isinstance(response.body.get("TwoFactorProviders"), list)
    )


def choose_provider(providers: list[Any]) -> str:
    available = {str(provider) for provider in providers}
    explicit = os.environ.get("VW_TWO_FACTOR_PROVIDER", "").strip()
    if explicit:
        if explicit not in {"0", "1", "3", "8"}:
            raise VaultFailure(
                "VW_TWO_FACTOR_PROVIDER must be 0 (authenticator), 1 (email), 3 (YubiKey), or 8 (recovery code)."
            )
        if explicit != "8" and explicit not in available:
            raise VaultFailure("That two-step method is not enabled on this account.")
        return explicit
    for candidate in ("0", "1", "3"):
        if candidate in available:
            return candidate
    raise VaultFailure(
        "This account uses WebAuthn or Duo. Unlock the web vault and use Agent sites, "
        "or pass a one-shot user access token to put."
    )


def should_send_email(provider: str, code_from_env: str) -> bool:
    return provider == "1" and not code_from_env.strip()


def account_key_blob(payload: dict[str, Any]) -> str | None:
    key = payload.get("Key")
    if isinstance(key, str) and key:
        return key
    options = payload.get("UserDecryptionOptions")
    if not isinstance(options, dict):
        return None
    unlock = options.get("MasterPasswordUnlock")
    if not isinstance(unlock, dict):
        return None
    for field in ("MasterKeyWrappedUserKey", "MasterKeyEncryptedUserKey"):
        value = unlock.get(field)
        if isinstance(value, str) and value:
            return value
    return None


def read_secret(env_name: str, prompt: str) -> str:
    value = os.environ.get(env_name, "")
    if value:
        return value
    if not sys.stdin.isatty():
        raise VaultFailure(f"Set {env_name}, or run in a terminal and type it when asked.")
    typed = getpass.getpass(prompt)
    if not typed:
        raise VaultFailure(f"{prompt.strip()} was empty")
    return typed


def check_uuid(value: str) -> None:
    if not _UUID.match(value):
        raise VaultFailure("item id must be a UUID")


def error_message(response: "VaultResponse") -> str:
    message = response.body.get("message")
    if isinstance(message, str) and message.strip():
        return message.strip()
    description = response.body.get("error_description")
    if isinstance(description, str) and description.strip():
        return description.strip()
    error = response.body.get("error")
    if isinstance(error, str) and error.strip():
        return error.strip()
    return f"HTTP {response.status}"


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


class VaultResponse:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self.body = body


def vault_request(
    base_url: str,
    method: str,
    path: str,
    *,
    token: str | None = None,
    json_body: dict[str, Any] | None = None,
    form: dict[str, str] | None = None,
    timeout: float = 60.0,
) -> VaultResponse:
    if token:
        reject_agent_token(token)
    if not path.startswith("/"):
        raise VaultFailure("internal error: path must start with /")
    headers = {"Accept": "application/json", "User-Agent": _USER_AGENT}
    data = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if json_body is not None and form is not None:
        raise VaultFailure("internal error: json and form set together")
    if json_body is not None:
        data = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    request = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_RefuseRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read(_MAX_BODY + 1)
    except VaultFailure:
        raise
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read(_MAX_BODY + 1)
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise VaultFailure(f"request failed: {reason}") from None
    if len(raw) > _MAX_BODY:
        raise VaultFailure("response is too large")
    if not raw:
        if 200 <= status < 300:
            return VaultResponse(status, {})
        raise VaultFailure(f"HTTP {status}")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VaultFailure(f"HTTP {status} was not JSON") from exc
    if not isinstance(parsed, dict):
        raise VaultFailure(f"HTTP {status} JSON was not an object")
    return VaultResponse(status, parsed)


if __name__ == "__main__":
    sys.exit(main())
