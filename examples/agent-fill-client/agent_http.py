"""HTTP helpers for the fill-only Agent API example.

Bearer tokens are sent only to ``VW_BASE_URL``. Redirects are refused so a
30x response cannot carry the token to another host. Requests are not
retried: redeem is single-use.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import NoReturn

_MAX_BODY = 1_048_576
_USER_AGENT = "vaultwarden-agent-fill-example/1.0"
_HEX = frozenset("0123456789abcdefABCDEF")


class ApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message

    def __str__(self) -> str:
        if self.status:
            return f"HTTP {self.status}: {self.message}"
        return self.message


class _RefuseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ApiError(code, "refusing to follow a redirect with a bearer token")


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def die(message: str) -> NoReturn:
    eprint(message)
    raise SystemExit(1)


def print_json(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def require_base_url() -> str:
    base = os.environ.get("VW_BASE_URL", "").strip().rstrip("/")
    if not base:
        die("VW_BASE_URL is not set")
    parsed = urllib.parse.urlparse(base)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        die("VW_BASE_URL must be an http or https origin, without a path")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        die("VW_BASE_URL must be the server origin only, for example https://vault.example.com")
    if parsed.username or parsed.password:
        die("VW_BASE_URL must not include userinfo")
    return base


def require_token(env_name: str, expected: str) -> str:
    """Return a well-formed vwagent_ or vwfill_ token.

    ``expected`` is ``agent`` or ``fill``. The other prefix is rejected so
    the fill secret cannot be used from the AI process by mistake.
    """

    token = os.environ.get(env_name, "").strip()
    if not token:
        die(f"{env_name} is not set")
    if expected == "agent" and token.startswith("vwfill_"):
        die(
            f"{env_name} is a vwfill_ secret. The AI process must use a "
            "vwagent_ token. Do not put the fill secret in this process."
        )
    if expected == "fill" and token.startswith("vwagent_"):
        die(
            f"{env_name} is a vwagent_ token. The fill process must use a "
            "vwfill_ secret."
        )
    prefix = "vwagent_" if expected == "agent" else "vwfill_"
    body = token[len(prefix) :] if token.startswith(prefix) else ""
    if len(body) != 64 or any(char not in _HEX for char in body):
        die(f"{env_name} must be a {prefix} token whose body is 64 hex characters.")
    return token


def api_request(
    base_url: str,
    method: str,
    path: str,
    token: str,
    *,
    query: dict[str, str] | None = None,
    body: dict | None = None,
    timeout: float = 30.0,
) -> dict:
    """Call one Agent API route and return a JSON object."""

    if not path.startswith("/"):
        die("internal error: API path must start with /")
    url = base_url + path
    if query:
        pairs = [(key, value) for key, value in query.items() if value is not None]
        if pairs:
            url += "?" + urllib.parse.urlencode(pairs)
    data = None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
        "User-Agent": _USER_AGENT,
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_RefuseRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            raw = response.read(_MAX_BODY + 1)
    except ApiError:
        raise
    except urllib.error.HTTPError as exc:
        raw = exc.read(_MAX_BODY + 1)
        raise ApiError(exc.code, _error_message(exc.code, raw)) from None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", exc)
        raise ApiError(0, f"request failed: {reason}") from None
    if len(raw) > _MAX_BODY:
        raise ApiError(status, "response is too large")
    if not raw:
        raise ApiError(status, "response was empty")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ApiError(status, "response was not JSON") from None
    if not isinstance(parsed, dict):
        raise ApiError(status, "response JSON was not an object")
    return parsed


def _error_message(status: int, raw: bytes) -> str:
    if len(raw) > _MAX_BODY:
        return f"HTTP {status} error body is too large"
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return f"HTTP {status}"
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict):
        message = parsed.get("message")
        if isinstance(message, str) and message.strip():
            return message.strip()
    if len(text) > 300:
        text = text[:300] + "…"
    return text
