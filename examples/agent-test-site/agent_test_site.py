"""An isolated relying party for password and real WebAuthn acceptance tests."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route
from test_site_pages import CSS, SCRIPT, render
from test_site_state import (
    CHALLENGE_SECONDS,
    COOKIE,
    SCHEMA,
    consume_challenge,
    current_session,
    database,
    new_session,
    password_hash,
    require_user,
)
from webauthn import (
    base64url_to_bytes,
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


async def body_data(request: Request) -> dict:
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 65536:
            raise HTTPException(413, "request_too_large")
    try:
        if request.headers.get("content-type", "").startswith("application/json"):
            value = json.loads(body)
            if isinstance(value, dict):
                return value
        else:
            form = parse_qs(body.decode(), strict_parsing=True, keep_blank_values=True)
            if all(len(values) == 1 for values in form.values()):
                return {key: values[0] for key, values in form.items()}
    except (ValueError, UnicodeError):
        pass
    raise HTTPException(400, "invalid_request")


async def page(request: Request) -> Response:
    path = request.url.path
    if path == "/health":
        return JSONResponse({"status": "ok"})
    if path in {"/static/site.css", "/static/site.js"}:
        css = path.endswith(".css")
        return Response(
            CSS if css else SCRIPT, media_type="text/css" if css else "text/javascript"
        )
    session = current_session(request)
    logged_in = session is not None and session["user_id"] is not None
    if path in {"/profile", "/workspace"}:
        if not logged_in:
            return RedirectResponse("/login", status_code=303)
        if path == "/workspace":
            with database(request.app.state.database) as db:
                row = db.execute(
                    "SELECT value FROM workspace_notes WHERE user_id=?",
                    (session["user_id"],),
                ).fetchone()
            return HTMLResponse(
                render(
                    "workspace",
                    username=session["username"],
                    note=row["value"] if row else "",
                )
            )
        return HTMLResponse(render("profile", username=session["username"]))
    if logged_in:
        return RedirectResponse("/profile", status_code=303)
    return HTMLResponse(render("register" if path == "/register" else "login"))


async def password_login(request: Request) -> Response:
    data = await body_data(request)
    username, password = data.get("username"), data.get("password")
    if not isinstance(username, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{3,64}", username
    ):
        raise HTTPException(400, "invalid_test_account")
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        raise HTTPException(400, "invalid_test_password")
    with database(request.app.state.database) as db:
        if request.url.path == "/register":
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM users").fetchone()[0] >= 64:
                raise HTTPException(429, "test_capacity_reached")
            salt, user_id = secrets.token_bytes(16), secrets.token_bytes(16)
            try:
                db.execute(
                    "INSERT INTO users VALUES (?, ?, ?, ?)",
                    (user_id, username, salt, password_hash(password, salt)),
                )
            except sqlite3.IntegrityError:
                raise HTTPException(409, "test_account_exists") from None
        else:
            user = db.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
            if user is None or not hmac.compare_digest(
                password_hash(password, user["salt"]), user["password_hash"]
            ):
                return HTMLResponse(
                    render("login", error="Sign-in could not be verified."),
                    status_code=401,
                )
            user_id = user["id"]
    response = RedirectResponse("/profile", status_code=303)
    new_session(request, response, user_id)
    return response


async def logout(request: Request) -> Response:
    session = current_session(request)
    if session:
        with database(request.app.state.database) as db:
            db.execute("DELETE FROM sessions WHERE id=?", (session["id"],))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(
        COOKIE, path="/", secure=True, httponly=True, samesite="strict"
    )
    return response


async def save_workspace(request: Request) -> Response:
    session = require_user(request)
    data = await body_data(request)
    note = data.get("note")
    if set(data) != {"note"} or not isinstance(note, str) or len(note) > 2048:
        raise HTTPException(400, "invalid_workspace_note")
    with database(request.app.state.database) as db:
        if note:
            db.execute(
                "INSERT INTO workspace_notes VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET value=excluded.value",
                (session["user_id"], note),
            )
        else:
            db.execute(
                "DELETE FROM workspace_notes WHERE user_id=?", (session["user_id"],)
            )
    return RedirectResponse("/workspace", status_code=303)


async def check_workspace(request: Request) -> Response:
    session = require_user(request)
    data = await body_data(request)
    expected = data.get("expected")
    if (
        set(data) != {"expected"}
        or not isinstance(expected, str)
        or len(expected) > 2048
    ):
        raise HTTPException(400, "invalid_workspace_note")
    with database(request.app.state.database) as db:
        row = db.execute(
            "SELECT value FROM workspace_notes WHERE user_id=?", (session["user_id"],)
        ).fetchone()
    if (row["value"] if row else "") != expected:
        raise HTTPException(409, "workspace_note_mismatch")
    return HTMLResponse(
        render("workspace", username=session["username"], note=expected, verified=True)
    )


async def options(request: Request) -> Response:
    registration = request.url.path.startswith("/registration/")
    session = require_user(request) if registration else current_session(request)
    if registration:
        with database(request.app.state.database) as db:
            existing = db.execute(
                "SELECT id FROM credentials WHERE user_id=?", (session["user_id"],)
            ).fetchall()
        if len(existing) >= 4:
            raise HTTPException(429, "test_capacity_reached")
        value = generate_registration_options(
            rp_id=request.app.state.rp_id,
            rp_name="Agent Auth Test",
            user_id=session["user_id"],
            user_name=session["username"],
            timeout=CHALLENGE_SECONDS * 1000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.REQUIRED,
            ),
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=row["id"]) for row in existing
            ],
        )
    else:
        value = generate_authentication_options(
            rp_id=request.app.state.rp_id,
            timeout=CHALLENGE_SECONDS * 1000,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
    response = JSONResponse(json.loads(options_to_json(value)))
    session_id = (
        session["id"] if session is not None else new_session(request, response)
    )
    with database(request.app.state.database) as db:
        db.execute(
            "INSERT OR REPLACE INTO challenges VALUES (?, ?, ?, ?)",
            (
                session_id,
                "register" if registration else "authenticate",
                value.challenge,
                int(time.time()) + CHALLENGE_SECONDS,
            ),
        )
    return response


async def verify(request: Request) -> Response:
    registration = request.url.path.startswith("/registration/")
    session = require_user(request) if registration else current_session(request)
    if session is None:
        raise HTTPException(400, "challenge_unavailable")
    challenge = consume_challenge(
        request, session["id"], "register" if registration else "authenticate"
    )
    credential = await body_data(request)
    if not isinstance(credential.get("id"), str) or not isinstance(
        credential.get("response"), dict
    ):
        return JSONResponse({"verified": False}, status_code=400)
    expected = {
        "credential": credential,
        "expected_challenge": challenge,
        "expected_rp_id": request.app.state.rp_id,
        "expected_origin": request.app.state.origin,
        "require_user_verification": True,
    }
    # Library errors can reflect assertion contents; only a fixed verdict leaves this boundary.
    try:
        if registration:
            result = verify_registration_response(**expected)
            with database(request.app.state.database) as db:
                db.execute(
                    "INSERT INTO credentials VALUES (?, ?, ?, ?)",
                    (
                        result.credential_id,
                        session["user_id"],
                        result.credential_public_key,
                        result.sign_count,
                    ),
                )
            return JSONResponse({"verified": True})
        credential_id = base64url_to_bytes(credential["id"])
        with database(request.app.state.database) as db:
            saved = db.execute(
                "SELECT * FROM credentials WHERE id=?", (credential_id,)
            ).fetchone()
        if saved is None:
            raise ValueError("unknown_credential")
        handle = credential.get("response", {}).get("userHandle")
        if handle is not None and (
            not isinstance(handle, str)
            or base64url_to_bytes(handle) != saved["user_id"]
        ):
            raise ValueError("wrong_user_handle")
        result = verify_authentication_response(
            **expected,
            credential_public_key=saved["public_key"],
            credential_current_sign_count=saved["sign_count"],
        )
        with database(request.app.state.database) as db:
            updated = db.execute(
                "UPDATE credentials SET sign_count=? WHERE id=? AND sign_count=?",
                (result.new_sign_count, saved["id"], saved["sign_count"]),
            )
            if updated.rowcount != 1:
                raise ValueError("stale_counter")
        response = JSONResponse({"verified": True})
        new_session(request, response, saved["user_id"])
        return response
    except (WebAuthnException, ValueError, KeyError, TypeError, sqlite3.IntegrityError):
        return JSONResponse({"verified": False}, status_code=400)


async def error_response(request: Request, error: Exception) -> Response:
    status = error.status_code if isinstance(error, HTTPException) else 500
    detail = error.detail if isinstance(error, HTTPException) else "server_error"
    return JSONResponse({"error": detail}, status_code=status)


def create_app(origin: str, path: Path) -> Starlette:
    url = urlsplit(origin)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.username
        or url.password
        or url.path
        or url.query
        or url.fragment
        or origin != f"https://{url.netloc}"
    ):
        raise ValueError("exact_https_origin_required")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with database(path) as db:
        db.executescript(SCHEMA)
    routes = [
        Route(p, page)
        for p in [
            "/",
            "/login",
            "/register",
            "/profile",
            "/workspace",
            "/health",
            "/static/site.css",
            "/static/site.js",
        ]
    ]
    routes += [
        Route(p, password_login, methods=["POST"]) for p in ["/login", "/register"]
    ]
    routes += [Route("/logout", logout, methods=["POST"])]
    routes += [Route("/workspace", save_workspace, methods=["POST"])]
    routes += [Route("/workspace/check", check_workspace, methods=["POST"])]
    routes += [
        Route(f"/{kind}/options", options, methods=["POST"])
        for kind in ["registration", "authentication"]
    ]
    routes += [
        Route(f"/{kind}/verification", verify, methods=["POST"])
        for kind in ["registration", "authentication"]
    ]
    app = Starlette(
        routes=routes,
        exception_handlers={HTTPException: error_response, Exception: error_response},
    )
    app.state.origin, app.state.rp_id, app.state.database = origin, url.hostname, path

    async def boundaries(request: Request, call_next):
        if request.method == "POST" and request.headers.get("origin") != origin:
            return JSONResponse({"error": "origin_rejected"}, status_code=403)
        response = await call_next(request)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                # Preserve the Origin of native same-origin form POSTs; never refer externally.
                "Referrer-Policy": "same-origin",
                "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'",
            }
        )
        return response

    app.add_middleware(BaseHTTPMiddleware, dispatch=boundaries)
    return app


def main() -> None:
    import uvicorn

    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18082)
    args = parser.parse_args()
    app = create_app(args.origin, args.database)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        access_log=False,
        log_config=None,
        limit_concurrency=16,
    )


if __name__ == "__main__":
    main()
