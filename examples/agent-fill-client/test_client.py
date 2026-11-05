#!/usr/bin/env python3
"""Tests for the fill-only Agent API example client.

Crypto vectors are produced with OpenSSL AES-256-CBC and checked with
HMAC-SHA256 here, so a broken decryptor cannot pass by agreeing with itself.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import hmac
import io
import json
import os
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import agent_http  # noqa: E402
import bw_crypto  # noqa: E402
from bw_crypto import BitwardenCryptoError, decrypt_fill, load_user_key  # noqa: E402

HERE = Path(__file__).resolve().parent
AI = HERE / "ai_agent.py"
FILL = HERE / "fill_agent.py"

AGENT = "vwagent_" + "ab" * 32
FILL_TOKEN = "vwfill_" + "cd" * 32
FILL_ID = "11111111-2222-4333-8444-555555555555"
ITEM = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
TICKET = "99999999-8888-4777-8666-555555555555"
REDEEM_SECRET = "redeem-secret-value-do-not-print-from-ai"
EVIL_PASSWORD = "EVIL-PASSWORD-SHOULD-NOT-LEAK"
PLAINTEXT_PASSWORD = "correct-horse-battery"


def openssl_aes_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=plaintext,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode("utf-8", errors="replace"))
    return proc.stdout


def openssl_aes_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    proc = subprocess.run(
        ["openssl", "enc", "-d", "-aes-256-cbc", "-K", key.hex(), "-iv", iv.hex(), "-nosalt"],
        input=ciphertext,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr.decode("utf-8", errors="replace"))
    return proc.stdout


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encstring_type2(enc_key: bytes, mac_key: bytes, iv: bytes, plaintext: bytes) -> str:
    ciphertext = openssl_aes_encrypt(enc_key, iv, plaintext)
    if openssl_aes_decrypt(enc_key, iv, ciphertext) != plaintext:
        raise AssertionError("OpenSSL could not round-trip the ciphertext")
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return f"2.{b64(iv)}|{b64(ciphertext)}|{b64(mac)}"


def encstring_type0(enc_key: bytes, iv: bytes, plaintext: bytes) -> str:
    ciphertext = openssl_aes_encrypt(enc_key, iv, plaintext)
    return f"0.{b64(iv)}|{b64(ciphertext)}"


class CryptoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.enc = bytes(range(32))
        self.mac = bytes(range(32, 64))
        self.user_key = self.enc + self.mac
        self.iv = bytes(range(16))

    def test_type2_matches_openssl_and_rejects_a_bad_mac(self) -> None:
        token = encstring_type2(self.enc, self.mac, self.iv, "hunter2".encode())
        filled = decrypt_fill("alice", token, None, None, self.user_key)
        self.assertTrue(filled.ok)
        self.assertEqual(filled.password.value, "hunter2")
        self.assertEqual(filled.password.state, "decrypted")
        self.assertEqual(filled.username.value, "alice")
        self.assertEqual(filled.username.state, "plaintext")
        self.assertEqual(filled.totp.state, "absent")
        self.assertEqual(filled.item_key, "none")
        self.assertNotIn("hunter2", token)

        iv_b64, ct_b64, mac_b64 = token[2:].split("|")
        mac = bytearray(base64.b64decode(mac_b64))
        mac[-1] ^= 0x01
        tampered = f"2.{iv_b64}|{ct_b64}|{b64(bytes(mac))}"
        failed = decrypt_fill(None, tampered, None, None, self.user_key)
        self.assertFalse(failed.ok)
        self.assertIsNone(failed.password.value)
        self.assertEqual(failed.password.state, "failed")
        self.assertNotIn("hunter2", failed.error or "")
        self.assertNotIn(tampered, failed.error or "")

    def test_type2_unicode_block_and_empty(self) -> None:
        block = encstring_type2(self.enc, self.mac, self.iv, "0123456789abcdef".encode())
        text = encstring_type2(self.enc, self.mac, self.iv, "päss wörd".encode())
        empty = encstring_type2(self.enc, self.mac, self.iv, b"")
        filled = decrypt_fill(text, block, empty, None, self.user_key)
        self.assertEqual(filled.username.value, "päss wörd")
        self.assertEqual(filled.password.value, "0123456789abcdef")
        self.assertEqual(filled.totp.value, "")
        self.assertEqual(filled.totp.state, "decrypted")

    def test_item_key_is_unwrapped_before_field_decrypt(self) -> None:
        item_key = bytes(range(64, 128))
        key_iv = bytes([3]) * 16
        field_iv = bytes([9]) * 16
        wrapped = encstring_type2(self.enc, self.mac, key_iv, item_key)
        password = encstring_type2(item_key[:32], item_key[32:], field_iv, b"s3cret!")
        filled = decrypt_fill("bob", password, None, wrapped, self.user_key)
        self.assertTrue(filled.ok, filled.error)
        self.assertEqual(filled.password.value, "s3cret!")
        self.assertEqual(filled.item_key, "unwrapped")
        # The same field MAC fails under the user key, so this only passes if
        # the item key was actually unwrapped.
        direct = decrypt_fill(None, password, None, None, self.user_key)
        self.assertFalse(direct.ok)
        self.assertIsNone(direct.password.value)

    def test_historical_base64_item_key(self) -> None:
        item_key = bytes([0xFB]) * 64
        wrapped = encstring_type2(
            self.enc,
            self.mac,
            self.iv,
            base64.b64encode(item_key),
        )
        password = encstring_type2(item_key[:32], item_key[32:], self.iv, b"legacy-key")
        filled = decrypt_fill(None, password, None, wrapped, self.user_key)
        self.assertTrue(filled.ok, filled.error)
        self.assertEqual(filled.password.value, "legacy-key")
        self.assertEqual(filled.item_key, "unwrapped-base64")

    def test_type0_uses_the_enc_half_of_a_64_byte_key(self) -> None:
        token = encstring_type0(self.enc, self.iv, b"legacy")
        self.assertEqual(decrypt_fill(None, token, None, None, self.user_key).password.value, "legacy")
        self.assertEqual(decrypt_fill(None, token, None, None, self.enc).password.value, "legacy")

    def test_type2_with_a_32_byte_key_is_an_error(self) -> None:
        token = encstring_type2(self.enc, self.mac, self.iv, b"hunter2")
        filled = decrypt_fill(None, token, None, None, self.enc)
        self.assertFalse(filled.ok)
        self.assertIn("64-byte", filled.error or "")
        self.assertIsNone(filled.password.value)

    def test_rsa_encstring_is_not_returned_as_plaintext(self) -> None:
        blob = "3." + b64(b"R" * 32)
        filled = decrypt_fill("alice", blob, None, None, self.user_key)
        self.assertFalse(filled.ok)
        self.assertIsNone(filled.password.value)
        self.assertNotIn(blob, filled.error or "")
        self.assertIn("type 3", filled.error or "")

    def test_plain_prefix_lookalike_stays_plaintext(self) -> None:
        odd = "2.abcdefghijklmnop"
        filled = decrypt_fill(None, odd, None, None, self.user_key)
        self.assertTrue(filled.ok)
        self.assertEqual(filled.password.value, odd)
        self.assertEqual(filled.password.state, "plaintext")

    def test_user_key_formats(self) -> None:
        raw = bytes([0xFB, 0x10]) * 32
        encoded = base64.b64encode(raw).decode("ascii")
        self.assertEqual(load_user_key(encoded), raw)
        self.assertEqual(load_user_key(f'"{encoded}"'), raw)
        self.assertEqual(load_user_key("\n" + encoded + "\n"), raw)
        url = encoded.replace("+", "-").replace("/", "_").rstrip("=")
        self.assertEqual(load_user_key(url), raw)
        self.assertEqual(load_user_key(raw.hex()), raw)
        self.assertEqual(load_user_key(self.enc.hex()), self.enc)
        with self.assertRaises(BitwardenCryptoError):
            load_user_key("correct horse battery staple")
        with self.assertRaises(BitwardenCryptoError):
            load_user_key("2." + b64(self.iv) + "|" + b64(b"x" * 16) + "|" + b64(self.mac))

    def test_pkcs7_rejects_tampered_padding(self) -> None:
        self.assertEqual(bw_crypto._pkcs7_unpad(b"hunter2" + bytes([9]) * 9), b"hunter2")
        with self.assertRaises(BitwardenCryptoError):
            bw_crypto._pkcs7_unpad(b"hunter2" + bytes([9]) * 8 + bytes([8]))
        with self.assertRaises(BitwardenCryptoError):
            bw_crypto._pkcs7_unpad(b"")


class HttpTests(unittest.TestCase):
    def test_query_auth_and_redirect_refusal(self) -> None:
        state = {"hits": []}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                state["hits"].append((self.path, self.headers.get("Authorization")))
                if self.path.startswith("/api/agent/items"):
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:9/steal")
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, fmt: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with self.assertRaises(agent_http.ApiError) as caught:
                agent_http.api_request(
                    base,
                    "GET",
                    "/api/agent/items",
                    AGENT,
                    query={"url": "https://example.com/login", "q": "git hub"},
                )
            self.assertIn("refusing to follow a redirect", str(caught.exception))
            self.assertEqual(len(state["hits"]), 1)
            path, auth = state["hits"][0]
            self.assertEqual(auth, f"Bearer {AGENT}")
            self.assertIn("url=https%3A%2F%2Fexample.com%2Flogin", path)
            self.assertIn("q=git+hub", path)
        finally:
            server.shutdown()
            server.server_close()

    def test_error_message_is_the_api_message(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                body = json.dumps({"message": "Origin not allowed", "object": "error"}).encode()
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{server.server_address[1]}"
            with self.assertRaises(agent_http.ApiError) as caught:
                agent_http.api_request(base, "POST", "/api/agent/fills", AGENT, body={"itemId": ITEM})
            self.assertEqual(caught.exception.status, 400)
            self.assertEqual(caught.exception.message, "Origin not allowed")
        finally:
            server.shutdown()
            server.server_close()


class CliTests(unittest.TestCase):
    def test_ai_drops_ciphertext_username_and_folder(self) -> None:
        import ai_agent

        blob = "2." + ("ab" * 8) + "|" + ("cd" * 8) + "|" + ("ef" * 8)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            item = ai_agent._drop_ciphertext_labels(
                {
                    "id": ITEM,
                    "name": "Example",
                    "username": blob,
                    "folderName": blob,
                }
            )
        self.assertNotIn("username", item)
        self.assertNotIn("folderName", item)
        self.assertEqual(item["name"], "Example")
        self.assertNotIn(blob, stderr.getvalue())

    def test_ai_source_does_not_call_fill_routes(self) -> None:
        source = AI.read_text(encoding="utf-8")
        self.assertNotIn("/api/agent/fill-agent", source)
        self.assertNotIn('require_token("VW_FILL_TOKEN"', source)
        self.assertNotIn('os.environ.get("BW_USER_KEY"', source)
        self.assertNotIn('os.environ["BW_USER_KEY"', source)
        self.assertNotIn("import bw_crypto", source)

    def test_wrong_token_never_reaches_the_network(self) -> None:
        completed = run_ai(
            "items",
            VW_BASE_URL="http://127.0.0.1:1",
            VW_AGENT_TOKEN=FILL_TOKEN,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("vwfill_", completed.stderr)
        self.assertNotIn("request failed", completed.stderr)
        self.assertNotIn(FILL_TOKEN, completed.stdout)
        self.assertNotIn(FILL_TOKEN, completed.stderr)

    def test_fill_agent_id_rejects_the_secret(self) -> None:
        completed = run_ai(
            "fill",
            "--item",
            ITEM,
            "--origin",
            "https://example.com",
            "--fill-agent-id",
            FILL_TOKEN,
            VW_BASE_URL="http://127.0.0.1:1",
            VW_AGENT_TOKEN=AGENT,
        )
        self.assertEqual(completed.returncode, 1)
        self.assertIn("public UUID", completed.stderr)
        self.assertNotIn("request failed", completed.stderr)

    def test_ai_strips_secrets_and_fill_round_trip(self) -> None:
        enc = bytes(range(32))
        mac = bytes(range(32, 64))
        user_key = enc + mac
        iv = bytes(range(16))
        password_blob = encstring_type2(enc, mac, iv, PLAINTEXT_PASSWORD.encode())
        totp_blob = encstring_type2(enc, mac, bytes([7]) * 16, b"otpauth://totp/Example")
        state = {"redeemed": 0, "bodies": []}

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self._record()
                if self.path.startswith("/api/agent/items"):
                    self._json(
                        {
                            "object": "agentItemList",
                            "data": [
                                {
                                    "object": "agentItem",
                                    "id": ITEM,
                                    "name": "Example",
                                    "folderId": None,
                                    "uris": ["https://example.com"],
                                    "username": "alice",
                                    "reprompt": False,
                                    "password": EVIL_PASSWORD,
                                    "login": {"password": EVIL_PASSWORD},
                                }
                            ],
                            "truncated": False,
                            "redeemSecret": REDEEM_SECRET,
                        }
                    )
                    return
                if self.path == f"/api/agent/fills/{TICKET}":
                    self._json(
                        {
                            "object": "fillTicket",
                            "id": TICKET,
                            "status": "pending",
                            "expiresAt": "2026-11-05T00:01:00.000000Z",
                            "password": EVIL_PASSWORD,
                        }
                    )
                    return
                if self.path == "/api/agent/fill-agent/pending":
                    self._json(
                        {
                            "object": "fillAgentTicketList",
                            "data": [
                                {
                                    "object": "fillAgentTicket",
                                    "id": TICKET,
                                    "itemId": ITEM,
                                    "origin": "https://example.com",
                                    "expiresAt": "2026-11-05T00:01:00.000000Z",
                                    "redeemSecret": REDEEM_SECRET,
                                    "password": EVIL_PASSWORD,
                                }
                            ],
                        }
                    )
                    return
                self._json({"message": "nope"}, status=404)

            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                self._record(raw)
                if self.path == "/api/agent/fills":
                    self._json(
                        {
                            "object": "fillTicket",
                            "id": TICKET,
                            "status": "pending",
                            "expiresAt": "2026-11-05T00:01:00.000000Z",
                            "fillAgentId": FILL_ID,
                            "redeemSecret": REDEEM_SECRET,
                            "password": EVIL_PASSWORD,
                        }
                    )
                    return
                if self.path == "/api/agent/fill-agent/redeem":
                    body = json.loads(raw.decode())
                    if body.get("secret") != REDEEM_SECRET or body.get("ticketId") != TICKET:
                        self._json({"message": "Ticket not available"}, status=400)
                        return
                    state["redeemed"] += 1
                    self._json(
                        {
                            "object": "fillPayload",
                            "ticketId": TICKET,
                            "itemId": ITEM,
                            "origin": "https://example.com",
                            "key": None,
                            "login": {
                                "username": "2." + "a" * 20,
                                "password": password_blob,
                                "totp": totp_blob,
                                "notes": EVIL_PASSWORD,
                            },
                            "notes": EVIL_PASSWORD,
                        }
                    )
                    return
                self._json({"message": "nope"}, status=404)

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
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            listed = run_ai("items", "--url", "https://example.com", VW_BASE_URL=base, VW_AGENT_TOKEN=AGENT)
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertNotIn(EVIL_PASSWORD, listed.stdout)
            self.assertNotIn(REDEEM_SECRET, listed.stdout)
            self.assertNotIn(EVIL_PASSWORD, listed.stderr)
            items = json.loads(listed.stdout)
            self.assertEqual(items["data"][0]["id"], ITEM)
            self.assertEqual(items["data"][0]["username"], "alice")
            self.assertNotIn("password", items["data"][0])
            self.assertIn("dropped unexpected field 'password'", listed.stderr)

            created = run_ai(
                "fill",
                "--item",
                ITEM,
                "--origin",
                "https://example.com",
                "--fill-agent-id",
                FILL_ID,
                VW_BASE_URL=base,
                VW_AGENT_TOKEN=AGENT,
            )
            self.assertEqual(created.returncode, 0, created.stderr)
            self.assertNotIn(EVIL_PASSWORD, created.stdout)
            self.assertNotIn(REDEEM_SECRET, created.stdout)
            ticket = json.loads(created.stdout)
            self.assertEqual(
                list(ticket),
                ["object", "id", "status", "expiresAt", "fillAgentId"],
            )
            self.assertEqual(ticket["id"], TICKET)
            self.assertEqual(ticket["status"], "pending")

            status = run_ai("status", "--ticket", TICKET, VW_BASE_URL=base, VW_AGENT_TOKEN=AGENT)
            self.assertEqual(status.returncode, 0, status.stderr)
            self.assertNotIn(EVIL_PASSWORD, status.stdout)
            self.assertEqual(json.loads(status.stdout)["status"], "pending")

            create_body = json.loads(
                next(hit["body"] for hit in state["bodies"] if hit["path"] == "/api/agent/fills")
            )
            self.assertEqual(
                create_body,
                {"itemId": ITEM, "origin": "https://example.com", "fillAgentId": FILL_ID},
            )
            self.assertTrue(
                all(hit["auth"] == f"Bearer {AGENT}" for hit in state["bodies"] if hit["path"].startswith("/api/agent/"))
            )

            pending = run_fill("pending", VW_BASE_URL=base, VW_FILL_TOKEN=FILL_TOKEN)
            self.assertEqual(pending.returncode, 0, pending.stderr)
            self.assertNotIn(REDEEM_SECRET, pending.stdout)
            self.assertNotIn(EVIL_PASSWORD, pending.stdout)
            self.assertTrue(json.loads(pending.stdout)["data"][0]["hasRedeemSecret"])

            shown = run_fill("pending", "--show-secret", VW_BASE_URL=base, VW_FILL_TOKEN=FILL_TOKEN)
            self.assertIn(REDEEM_SECRET, shown.stdout)

            hidden = run_fill(
                "poll",
                "--wait",
                "0",
                VW_BASE_URL=base,
                VW_FILL_TOKEN=FILL_TOKEN,
                BW_USER_KEY=base64.b64encode(user_key).decode(),
            )
            self.assertEqual(hidden.returncode, 0, hidden.stderr)
            self.assertNotIn(PLAINTEXT_PASSWORD, hidden.stdout)
            self.assertNotIn(REDEEM_SECRET, hidden.stdout)
            self.assertNotIn("otpauth://totp/Example", hidden.stdout)
            self.assertNotIn(EVIL_PASSWORD, hidden.stdout)
            hidden_json = json.loads(hidden.stdout)
            self.assertFalse(hidden_json["revealed"])
            self.assertIsNone(hidden_json["login"]["password"])
            self.assertIsNone(hidden_json["login"]["totp"])
            self.assertEqual(hidden_json["received"]["password"], password_blob)
            self.assertEqual(hidden_json["received"]["totp"], totp_blob)
            self.assertEqual(hidden_json["decryption"]["password"], "decrypted")
            self.assertEqual(hidden_json["decryption"]["itemKey"], "none")
            self.assertEqual(hidden_json["login"]["username"], "2." + "a" * 20)

            revealed = run_fill(
                "redeem",
                "--ticket",
                TICKET,
                "--reveal",
                VW_BASE_URL=base,
                VW_FILL_TOKEN=FILL_TOKEN,
                BW_USER_KEY=base64.b64encode(user_key).decode(),
            )
            self.assertEqual(revealed.returncode, 0, revealed.stderr)
            self.assertEqual(json.loads(revealed.stdout)["login"]["password"], PLAINTEXT_PASSWORD)
            self.assertEqual(json.loads(revealed.stdout)["login"]["totp"], "otpauth://totp/Example")
            self.assertNotIn(REDEEM_SECRET, revealed.stdout)
            self.assertNotIn(EVIL_PASSWORD, revealed.stdout)
            self.assertGreaterEqual(state["redeemed"], 2)
            redeem_hits = [hit for hit in state["bodies"] if hit["path"] == "/api/agent/fill-agent/redeem"]
            self.assertTrue(redeem_hits)
            self.assertTrue(all(hit["auth"] == f"Bearer {FILL_TOKEN}" for hit in redeem_hits))
            self.assertNotIn(AGENT, "".join(hit["auth"] or "" for hit in redeem_hits))

            locked = run_fill(
                "poll",
                "--wait",
                "0",
                "--reveal",
                VW_BASE_URL=base,
                VW_FILL_TOKEN=FILL_TOKEN,
            )
            self.assertEqual(locked.returncode, 0, locked.stderr)
            self.assertNotIn(PLAINTEXT_PASSWORD, locked.stdout)
            self.assertNotIn("otpauth://totp/Example", locked.stdout)
            locked_json = json.loads(locked.stdout)
            self.assertEqual(locked_json["decryption"]["userKey"], "missing")
            self.assertEqual(locked_json["decryption"]["password"], "ciphertext")
            self.assertIsNone(locked_json["login"]["password"])
            self.assertEqual(locked_json["received"]["password"], password_blob)
            self.assertIn("BW_USER_KEY", locked.stderr)
        finally:
            server.shutdown()
            server.server_close()

    def test_origin_hint_and_bad_mac_do_not_print_a_password(self) -> None:
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                if self.path == "/api/agent/fills":
                    body = json.dumps({"message": "Origin not allowed"}).encode()
                    self.send_response(400)
                else:
                    body = json.dumps(
                        {
                            "object": "fillPayload",
                            "ticketId": TICKET,
                            "itemId": ITEM,
                            "origin": "https://example.com",
                            "key": None,
                            "login": {
                                "username": "alice",
                                "password": "2."
                                + b64(bytes(range(16)))
                                + "|"
                                + b64(b"c" * 16)
                                + "|"
                                + b64(b"m" * 32),
                            },
                        }
                    ).encode()
                    self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                body = json.dumps(
                    {
                        "object": "fillAgentTicketList",
                        "data": [
                            {
                                "id": TICKET,
                                "itemId": ITEM,
                                "origin": "https://example.com",
                                "expiresAt": "2026-11-05T00:01:00.000000Z",
                                "redeemSecret": REDEEM_SECRET,
                            }
                        ],
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt: str, *args: object) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = f"http://127.0.0.1:{server.server_address[1]}"
        try:
            denied = run_ai(
                "fill",
                "--item",
                ITEM,
                "--origin",
                "https://example.com",
                VW_BASE_URL=base,
                VW_AGENT_TOKEN=AGENT,
                FILL_AGENT_ID=FILL_ID,
            )
            self.assertEqual(denied.returncode, 1)
            self.assertIn("Origin not allowed", denied.stderr)
            self.assertIn("uri-index", denied.stderr)
            self.assertEqual(denied.stdout, "")

            user_key = base64.b64encode(bytes(range(64))).decode()
            failed = run_fill(
                "redeem",
                "--reveal",
                VW_BASE_URL=base,
                VW_FILL_TOKEN=FILL_TOKEN,
                BW_USER_KEY=user_key,
            )
            self.assertEqual(failed.returncode, 1)
            self.assertIn("MAC mismatch", failed.stderr)
            self.assertNotIn(REDEEM_SECRET, failed.stdout)
            self.assertNotIn(REDEEM_SECRET, failed.stderr)
            failed_json = json.loads(failed.stdout)
            self.assertIsNone(failed_json["login"]["password"])
            self.assertIn("MAC mismatch", failed_json["error"])
            self.assertTrue(failed_json["received"]["password"])
        finally:
            server.shutdown()
            server.server_close()


def run_ai(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return _run(AI, args, env)


def run_fill(*args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return _run(FILL, args, env)


def _run(script: Path, args: tuple[str, ...], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    clean = {
        "PATH": os.environ.get("PATH", ""),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "PYTHONUTF8": "1",
        "PYTHONPATH": str(HERE),
    }
    clean.update(env)
    return subprocess.run(
        [sys.executable, str(script), *args],
        cwd=HERE,
        env=clean,
        capture_output=True,
        text=True,
        check=False,
    )


if __name__ == "__main__":
    unittest.main()
