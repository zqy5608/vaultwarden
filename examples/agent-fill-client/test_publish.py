#!/usr/bin/env python3
"""Tests for publish_uri.py and the web vault Agent sites helper.

Ciphertext is built with OpenSSL, the same way as test_client.py. The publish
script must send websites only: the master password, the access token, and a
login password planted in the sync payload stay out of stdout and stderr.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import bw_kdf  # noqa: E402
import test_client  # noqa: E402
from bw_crypto import decrypt_to_bytes  # noqa: E402
from bw_kdf import (  # noqa: E402
    derive_master_key,
    master_password_hash,
    stretch_master_key,
    unwrap_account_key,
)
from publish_uri import choose_provider, publishable_uri, should_send_email  # noqa: E402

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PUBLISH = HERE / "publish_uri.py"
JS = REPO / "src" / "static" / "scripts" / "vw-agent-uri.js"

EMAIL = "user@example.com"
PASSWORD = "correct-horse-stamp"
EVIL = "EVIL-PASSWORD-SHOULD-NOT-LEAK"
QUERY_SECRET = "sekret-query"
USERINFO_SECRET = "uri-secret"
ACCESS_TOKEN = "user-access-token-do-not-print"
ITEM_A = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ITEM_B = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ITEM_C = "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ITEM_D = "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee"
ITEM_E = "eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee"
IV = bytes(range(16))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def enc(key: bytes, plaintext: bytes) -> str:
    return test_client.encstring_type2(key[:32], key[32:], IV, plaintext)


class KdfTests(unittest.TestCase):
    def test_pbkdf2_matches_cryptography_and_login_hash_is_one_round(self) -> None:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

        master = derive_master_key(PASSWORD, EMAIL, 0, 2)
        expected = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=EMAIL.encode(),
            iterations=2,
        ).derive(PASSWORD.encode())
        self.assertEqual(master, expected)
        stretched = stretch_master_key(master)
        self.assertEqual(HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master), stretched[:32])
        self.assertEqual(HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master), stretched[32:])
        login_hash = master_password_hash(master, PASSWORD)
        self.assertNotIn(PASSWORD, login_hash)

    def test_argon2id_uses_sha256_email_salt_and_kibibytes(self) -> None:
        from argon2.low_level import Type, hash_secret_raw
        import hashlib

        expected = hash_secret_raw(
            secret=PASSWORD.encode(),
            salt=hashlib.sha256(EMAIL.encode()).digest(),
            time_cost=1,
            memory_cost=8 * 1024,
            parallelism=1,
            hash_len=32,
            type=Type.ID,
        )
        self.assertEqual(derive_master_key(PASSWORD, EMAIL, 1, 1, 8, 1), expected)

    def test_type2_account_key_is_raw_bytes_not_utf8(self) -> None:
        master = derive_master_key(PASSWORD, EMAIL, 0, 1)
        user_key = bytes([0xFF]) * 64
        self.assertRaises(UnicodeDecodeError, user_key.decode, "utf-8")
        wrapped = enc(stretch_master_key(master), user_key)
        self.assertEqual(unwrap_account_key(wrapped, master), user_key)
        legacy = test_client.encstring_type0(master, IV, user_key)
        self.assertEqual(unwrap_account_key(legacy, master), user_key)
        self.assertEqual(len(decrypt_to_bytes(wrapped, stretch_master_key(master))), 64)

    def test_publishable_uri_strips_userinfo_and_query(self) -> None:
        cleaned = publishable_uri(f"https://{USERINFO_SECRET}:hunter@example.com/login?token={QUERY_SECRET}")
        self.assertEqual(cleaned, "https://example.com/login")
        self.assertIsNone(publishable_uri("ssh://example.com"))
        self.assertIsNone(publishable_uri(EVIL))

    def test_two_factor_choice(self) -> None:
        self.assertEqual(choose_provider(["1", "0"]), "0")
        self.assertEqual(choose_provider(["7", "1"]), "1")
        self.assertTrue(should_send_email("1", ""))
        self.assertFalse(should_send_email("1", "123456"))
        self.assertFalse(should_send_email("0", ""))
        with self.assertRaises(Exception):
            choose_provider(["7"])


class PublishScriptTests(unittest.TestCase):
    def setUp(self) -> None:
        master = derive_master_key(PASSWORD, EMAIL, 0, 1)
        self.password_hash = master_password_hash(master, PASSWORD)
        self.user_key = bytes(range(64, 128))
        self.account_key = enc(stretch_master_key(master), self.user_key)
        item_key = bytes(range(128, 192))
        self.ciphers = [
            {
                "id": ITEM_A,
                "type": 1,
                "organizationId": None,
                "deletedDate": None,
                "reprompt": 0,
                "name": enc(self.user_key, b"Example"),
                "notes": EVIL,
                "key": None,
                "login": {
                    "username": enc(self.user_key, b"alice"),
                    "password": enc(self.user_key, EVIL.encode()),
                    "uris": [{"uri": enc(self.user_key, f"https://example.com/login?token={QUERY_SECRET}".encode()), "match": None}],
                },
            },
            {
                "id": ITEM_B,
                "type": 1,
                "organizationId": None,
                "name": "Other",
                "notes": EVIL,
                "key": None,
                "login": {
                    "password": EVIL,
                    "uris": [{"uri": f"https://{USERINFO_SECRET}:hunter@plain.example/a", "match": None}],
                },
            },
            {
                "id": ITEM_C,
                "type": 1,
                "organizationId": "org-1",
                "name": "Org",
                "login": {"uris": [{"uri": "https://org.example", "match": None}]},
            },
            {
                "id": ITEM_D,
                "type": 1,
                "organizationId": None,
                "name": "Never",
                "login": {"uris": [{"uri": "https://never.example", "match": 5}]},
            },
            {
                "id": ITEM_E,
                "type": 1,
                "organizationId": None,
                "name": enc(item_key, b"Keyed"),
                "key": enc(self.user_key, item_key),
                "notes": EVIL,
                "login": {
                    "password": enc(item_key, EVIL.encode()),
                    "uris": [{"uri": enc(item_key, b"https://keyed.example/login"), "match": 1}],
                },
            },
        ]

    def test_publish_all_sends_websites_only(self) -> None:
        state: dict = {"bodies": [], "require_2fa": False}
        with serve(state, self.ciphers, self.password_hash, self.account_key) as base:
            result = run(
                "publish",
                "--email",
                EMAIL,
                "--all",
                VW_BASE_URL=base,
                VW_MASTER_PASSWORD=PASSWORD,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_free(result)
        payload = json.loads(result.stdout)
        published = {item["id"]: item for item in payload["published"]}
        self.assertEqual(set(published), {ITEM_A, ITEM_B, ITEM_E})
        self.assertEqual(published[ITEM_A]["name"], "Example")
        self.assertEqual(published[ITEM_A]["uris"], ["https://example.com/login"])
        self.assertEqual(published[ITEM_B]["uris"], ["https://plain.example/a"])
        self.assertEqual(published[ITEM_E]["name"], "Keyed")
        self.assertEqual(published[ITEM_E]["uris"], ["https://keyed.example/login"])
        puts = [hit for hit in state["bodies"] if hit["method"] == "PUT"]
        self.assertEqual(len(puts), 3)
        for hit in puts:
            self.assertEqual(hit["auth"], f"Bearer {ACCESS_TOKEN}")
            self.assertNotIn(EVIL, hit["body"])
            self.assertNotIn(QUERY_SECRET, hit["body"])
            self.assertNotIn(USERINFO_SECRET, hit["body"])
            self.assertNotIn(PASSWORD, hit["body"])
        login = next(hit for hit in state["bodies"] if hit["path"] == "/identity/connect/token")
        self.assertNotIn(PASSWORD, login["body"])
        form = urllib.parse.parse_qs(login["body"])
        self.assertEqual(form["password"], [self.password_hash])
        self.assertNotIn(EVIL, result.stdout)
        self.assertIn("Example", result.stdout)

    def test_name_filter_and_dry_run_do_not_put(self) -> None:
        state: dict = {"bodies": [], "require_2fa": False}
        with serve(state, self.ciphers, self.password_hash, self.account_key) as base:
            result = run(
                "publish",
                "--email",
                EMAIL,
                "--name",
                "example",
                "--dry-run",
                VW_BASE_URL=base,
                VW_MASTER_PASSWORD=PASSWORD,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_secret_free(result)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["dryRun"])
        self.assertEqual([item["id"] for item in payload["published"]], [ITEM_A])
        self.assertFalse(any(hit["method"] == "PUT" for hit in state["bodies"]))
        self.assertIn("Dry run", result.stderr)

    def test_two_factor_then_put_with_token(self) -> None:
        state: dict = {"bodies": [], "require_2fa": True}
        with serve(state, self.ciphers, self.password_hash, self.account_key) as base:
            signed_in = run(
                "publish",
                "--email",
                EMAIL,
                "--item",
                ITEM_B,
                VW_BASE_URL=base,
                VW_MASTER_PASSWORD=PASSWORD,
                VW_TWO_FACTOR_CODE="123456",
            )
            explicit = run(
                "put",
                "--item",
                ITEM_B,
                "--uri",
                f"https://example.com/path?token={QUERY_SECRET}",
                "--match",
                "0",
                VW_BASE_URL=base,
                VW_USER_TOKEN=ACCESS_TOKEN,
            )
            cleared = run(
                "clear",
                "--item",
                ITEM_B,
                VW_BASE_URL=base,
                VW_USER_TOKEN=ACCESS_TOKEN,
            )
        self.assertEqual(signed_in.returncode, 0, signed_in.stderr)
        self.assert_secret_free(signed_in)
        token_calls = [hit for hit in state["bodies"] if hit["path"] == "/identity/connect/token"]
        self.assertEqual(len(token_calls), 2)
        self.assertNotIn("twoFactorToken", token_calls[0]["body"])
        self.assertIn("twoFactorToken=123456", token_calls[1]["body"])
        self.assertEqual(explicit.returncode, 0, explicit.stderr)
        self.assert_secret_free(explicit)
        put = json.loads(next(hit["body"] for hit in state["bodies"] if hit["method"] == "PUT" and "match" in hit["body"]))
        self.assertEqual(put, {"uris": [{"uri": "https://example.com/path", "match": 0}]})
        self.assertNotIn(QUERY_SECRET, explicit.stdout)
        self.assertEqual(cleared.returncode, 0, cleared.stderr)
        self.assertTrue(any(hit["method"] == "DELETE" for hit in state["bodies"]))
        self.assert_secret_free(cleared)

    def test_agent_token_is_rejected_without_a_request(self) -> None:
        result = run(
            "put",
            "--item",
            ITEM_A,
            "--uri",
            "https://example.com",
            VW_BASE_URL="http://127.0.0.1:9",
            VW_USER_TOKEN="vwagent_" + "ab" * 32,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("vault user", result.stderr)
        self.assertNotIn("vwagent_", result.stdout)
        self.assertEqual(result.stdout, "")

    def assert_secret_free(self, result: subprocess.CompletedProcess[str]) -> None:
        for stream in (result.stdout, result.stderr):
            self.assertNotIn(PASSWORD, stream)
            self.assertNotIn(EVIL, stream)
            self.assertNotIn(ACCESS_TOKEN, stream)
            self.assertNotIn(QUERY_SECRET, stream)
            self.assertNotIn(USERINFO_SECRET, stream)
            self.assertNotIn(self.password_hash, stream)
            self.assertNotIn(b64(self.user_key), stream)


class BrowserHelperTests(unittest.TestCase):
    def test_token_item_and_uri_selection(self) -> None:
        proc = subprocess.run(
            ["node", "-e", NODE_CHECKS, str(JS)],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")


NODE_CHECKS = r"""
const api = require(process.argv[1]);
const item = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
function jwt(payload) {
  const part = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
  return part({ alg: "HS256", typ: "JWT" }) + "." + part(payload) + ".sigsigsigsig";
}
const access = jwt({
  sub: item,
  email: "user@example.com",
  scope: ["api", "offline_access"],
  exp: 2000000000,
});
const expired = jwt({
  sub: item,
  email: "user@example.com",
  scope: ["api"],
  exp: 10,
});
const refresh = jwt({ sub: "password", scope: ["api"], exp: 2000000000 });
const selected = api.selectAccessToken([
  { key: "refresh", value: refresh },
  { key: "old", value: expired },
  { key: "user_token_accessToken", value: JSON.stringify(access) },
  { key: "notes", value: "vwagent_" + "ab".repeat(32) },
], 1700000000);
if (!selected || selected.token !== access || selected.email !== "user@example.com") {
  throw new Error("access token was not selected");
}
if (api.itemIdFromLocation("#/vault?itemId=" + item + "&action=view", "") !== item) {
  throw new Error("item id was not read from the vault hash");
}
if (api.itemIdFromLocation("#/ciphers/" + item, "") !== item) {
  throw new Error("item id was not read from the cipher path");
}
const cleaned = api.publishableUri("https://user:pass@example.com/a?token=sekret");
if (cleaned !== "https://example.com/a") {
  throw new Error("uri was not stripped: " + cleaned);
}
const origins = api.originsFromNodes([
  { tag: "input", password: true, label: "password", value: "EVIL-PASSWORD" },
  { tag: "input", label: "uri", value: "https://user:pass@example.com/login?token=sekret" },
  { tag: "a", href: "https://vault.example/help", chrome: true },
  { tag: "a", href: "https://example.com/login", inView: true },
  { tag: "a", href: "https://other.example", inView: false },
], "vault.example");
if (origins.join("|") !== "https://example.com/login") {
  throw new Error("origins were " + origins.join("|"));
}
if (api.normalizeOriginLines("https://example.com/a?x=1\nhttps://example.com/a").join("|") !== "https://example.com/a") {
  throw new Error("lines were not normalized");
}
console.log("ok");
"""


class _Server:
    def __init__(self, server: ThreadingHTTPServer, thread: threading.Thread) -> None:
        self.server = server
        self.thread = thread

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self) -> None:
        self.server.shutdown()
        self.thread.join(timeout=5)
        self.server.server_close()

    def __enter__(self) -> str:
        return self.base

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()


def serve(state: dict, ciphers: list, password_hash: str, account_key: str) -> _Server:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self._read()
            self._record(raw)
            if self.path == "/identity/accounts/prelogin":
                self._json({"kdf": 0, "kdfIterations": 1, "kdfMemory": None, "kdfParallelism": None})
                return
            if self.path == "/identity/connect/token":
                form = urllib.parse.parse_qs(raw.decode())
                if form.get("password", [""])[0] != password_hash or form.get("username", [""])[0] != EMAIL:
                    self._json({"message": "Username or password is incorrect. Try again"}, status=400)
                    return
                if state["require_2fa"] and form.get("twoFactorToken", [""])[0] != "123456":
                    self._json(
                        {
                            "error": "invalid_grant",
                            "error_description": "Two factor required.",
                            "TwoFactorProviders": ["0"],
                            "TwoFactorProviders2": {"0": None},
                        },
                        status=400,
                    )
                    return
                self._json(
                    {
                        "access_token": ACCESS_TOKEN,
                        "Key": account_key,
                        "token_type": "Bearer",
                    }
                )
                return
            self._json({"message": "nope"}, status=404)

        def do_GET(self) -> None:  # noqa: N802
            self._record()
            if self.path.split("?", 1)[0] == "/api/sync":
                if self.headers.get("Authorization") != f"Bearer {ACCESS_TOKEN}":
                    self._json({"message": "Unauthorized"}, status=401)
                    return
                self._json({"ciphers": ciphers})
                return
            self._json({"message": "nope"}, status=404)

        def do_PUT(self) -> None:  # noqa: N802
            raw = self._read()
            self._record(raw)
            if self.headers.get("Authorization") != f"Bearer {ACCESS_TOKEN}":
                self._json({"message": "Unauthorized"}, status=401)
                return
            body = json.loads(raw.decode())
            item_id = self.path.rstrip("/").split("/")[-2]
            self._json({"object": "agentUriIndex", "id": item_id, "uris": [entry["uri"] for entry in body["uris"]]})

        def do_DELETE(self) -> None:  # noqa: N802
            self._record()
            item_id = self.path.rstrip("/").split("/")[-2]
            self._json({"object": "agentUriIndex", "id": item_id, "uris": []})

        def _read(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0") or "0")
            return self.rfile.read(length) if length else b""

        def _record(self, body: bytes = b"") -> None:
            state["bodies"].append(
                {
                    "method": self.command,
                    "path": self.path,
                    "auth": self.headers.get("Authorization"),
                    "body": body.decode() if body else "",
                }
            )

        def _json(self, obj: dict, status: int = 200) -> None:
            raw = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return _Server(server, thread)


def run(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    clean = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONUTF8": "1",
        "PYTHONPATH": str(HERE),
    }
    clean.update(env)
    return subprocess.run(
        [sys.executable, str(PUBLISH), *args],
        cwd=HERE,
        env=clean,
        capture_output=True,
        text=True,
        check=False,
    )


if __name__ == "__main__":
    unittest.main()
