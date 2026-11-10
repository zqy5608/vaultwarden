"""Private session and one-use challenge storage for the owned test RP."""

import hashlib
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import Response

COOKIE = "__Host-agent-test-session"

SESSION_SECONDS = 900

CHALLENGE_SECONDS = 300

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id BLOB PRIMARY KEY, username TEXT UNIQUE NOT NULL,
 salt BLOB NOT NULL, password_hash BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
 id BLOB PRIMARY KEY, user_id BLOB NOT NULL REFERENCES users(id),
 public_key BLOB NOT NULL, sign_count INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 id BLOB PRIMARY KEY, user_id BLOB REFERENCES users(id), expires INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
 session_id BLOB NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
 kind TEXT NOT NULL, challenge BLOB NOT NULL, expires INTEGER NOT NULL,
 PRIMARY KEY(session_id, kind)
);
CREATE TABLE IF NOT EXISTS workspace_notes (
 user_id BLOB PRIMARY KEY REFERENCES users(id),
 value TEXT NOT NULL CHECK(length(value)<=2048)
);
"""


@contextmanager
def database(path: Path):
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def password_hash(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000)


def current_session(request: Request):
    token = request.cookies.get(COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
        return None
    with database(request.app.state.database) as db:
        return db.execute(
            "SELECT s.*, u.username FROM sessions s LEFT JOIN users u ON u.id=s.user_id "
            "WHERE s.id=? AND s.expires>?",
            (hashlib.sha256(token.encode()).digest(), int(time.time())),
        ).fetchone()


def require_user(request: Request):
    session = current_session(request)
    if session is None or session["user_id"] is None:
        raise HTTPException(401, "authentication_required")
    return session


def new_session(request: Request, response: Response, user_id=None) -> bytes:
    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode()).digest()
    old = current_session(request)
    with database(request.app.state.database) as db:
        db.execute("DELETE FROM sessions WHERE expires<=?", (int(time.time()),))
        if old:
            db.execute("DELETE FROM sessions WHERE id=?", (old["id"],))
        if db.execute("SELECT count(*) FROM sessions").fetchone()[0] >= 512:
            raise HTTPException(429, "test_capacity_reached")
        db.execute(
            "INSERT INTO sessions VALUES (?, ?, ?)",
            (digest, user_id, int(time.time()) + SESSION_SECONDS),
        )
    response.set_cookie(
        COOKIE,
        token,
        max_age=SESSION_SECONDS,
        secure=True,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return digest


def consume_challenge(request: Request, session_id: bytes, kind: str) -> bytes:
    with database(request.app.state.database) as db:
        row = db.execute(
            "DELETE FROM challenges WHERE session_id=? AND kind=? RETURNING challenge, expires",
            (session_id, kind),
        ).fetchone()
    if row is None or row["expires"] <= int(time.time()):
        raise HTTPException(400, "challenge_unavailable")
    return row["challenge"]
