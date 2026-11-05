"""Decrypt Bitwarden symmetric ciphertext locally.

Current clients store login fields as EncStrings. Type 2, the common form, is::

    2.<iv b64>|<ciphertext b64>|<mac b64>

The MAC is HMAC-SHA256 over the raw IV bytes concatenated with the raw
ciphertext bytes, keyed by the last 32 bytes of the 64-byte symmetric key.
It is checked before AES-256-CBC decryption. Padding is PKCS#7.

Type 0 is the legacy unauthenticated form ``0.<iv b64>|<ciphertext b64>``.
It uses a 32-byte AES key (the first 32 bytes when a 64-byte key is supplied).

A cipher ``key`` blob, when present, is itself a type 0 or type 2 EncString
wrapped by the user key. Its plaintext is the item key: 32 or 64 raw bytes,
or the older UTF-8 base64 encoding of those bytes. Login fields are then
decrypted with the item key. When ``key`` is null, fields use the user key.

This module does not derive a key from a master password, and it does not
implement RSA EncStrings (types 3–6) or type 1 (AES-128-HMAC).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass

_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
)


class BitwardenCryptoError(Exception):
    """The ciphertext is not a supported EncString or did not decrypt."""


@dataclass(frozen=True)
class _SymmetricKey:
    enc_key: bytes
    mac_key: bytes | None


@dataclass(frozen=True)
class _EncString:
    enc_type: int
    iv: bytes
    data: bytes
    mac: bytes | None


@dataclass(frozen=True)
class FieldText:
    """One login field after a decrypt attempt.

    ``value`` is set for plaintext and for a successful decrypt. It is never
    the original ciphertext. ``state`` is ``absent``, ``empty``, ``invalid``,
    ``plaintext``, ``ciphertext``, ``decrypted``, or ``failed``.
    """

    value: str | None
    state: str
    error: str | None = None


@dataclass(frozen=True)
class DecryptedFill:
    """Login fields decrypted with the user key and optional item key."""

    username: FieldText
    password: FieldText
    totp: FieldText
    item_key: str
    error: str | None = None

    @property
    def ok(self) -> bool:
        if self.error:
            return False
        return all(
            field.state != "failed"
            for field in (self.username, self.password, self.totp)
        )


def load_user_key(material: str) -> bytes:
    """Decode the unlocked user symmetric key.

    Accepts standard base64, base64url, or hex. The decoded length must be
    64 bytes (AES-256 key || HMAC-SHA256 key) or 32 bytes (legacy AES key).
    This is the same material as Bitwarden CLI ``BW_SESSION`` after
    ``bw unlock``, not the master password and not an encrypted key blob.
    """

    text = material.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    compact = "".join(text.split())
    if not compact:
        raise BitwardenCryptoError("user key is empty")
    if re.fullmatch(r"\d\..+", compact):
        raise BitwardenCryptoError(
            "value looks like a Bitwarden EncString. Pass the unlocked raw "
            "key (base64 of 64 bytes), such as BW_SESSION from `bw unlock`, "
            "not the encrypted key stored on the account"
        )
    if re.fullmatch(r"[0-9a-fA-F]{64}|[0-9a-fA-F]{128}", compact):
        return bytes.fromhex(compact)
    try:
        raw = _b64decode(compact)
    except ValueError:
        raw = b""
    if len(raw) not in (32, 64):
        raise BitwardenCryptoError(
            "user key must decode to 32 or 64 bytes. Pass base64 or hex of "
            "the unlocked symmetric key from `bw unlock` (BW_SESSION). "
            "A master password or the 32-byte stretched master key will not "
            "decrypt type 2 vault fields"
        )
    return raw


def classify_field(value: object) -> str:
    """Describe a redeem field without decrypting it."""

    if value is None:
        return "absent"
    if not isinstance(value, str):
        return "invalid"
    if value == "":
        return "empty"
    try:
        if _parse_supported(value) is not None:
            return "ciphertext"
    except BitwardenCryptoError:
        return "ciphertext"
    if _unsupported_type(value) is not None:
        return "ciphertext"
    return "plaintext"


def locked_field(value: object) -> FieldText:
    """Field view used when no user key is available.

    Plaintext is returned. Ciphertext is not copied into ``value``.
    """

    state = classify_field(value)
    if state == "plaintext" and isinstance(value, str):
        return FieldText(value, state)
    if state == "empty":
        return FieldText("", state)
    return FieldText(None, state)


def decrypt_fill(
    username: object,
    password: object,
    totp: object,
    cipher_key: object,
    user_key: bytes,
) -> DecryptedFill:
    """Decrypt redeem login fields with the unlocked user key.

    Check ``ok`` before using secret values. On failure ``value`` is None
    and ``error`` names the field. Ciphertext is never returned as the value.
    """

    user = _split_key(user_key)
    if cipher_key is None or cipher_key == "":
        item = user
        item_state = "none"
    elif isinstance(cipher_key, str):
        try:
            item, item_state = _unwrap_item_key(cipher_key, user)
        except BitwardenCryptoError as exc:
            return DecryptedFill(
                username=_untouched(username),
                password=_untouched(password),
                totp=_untouched(totp),
                item_key="failed",
                error=f"cipher key: {exc}",
            )
    else:
        raise BitwardenCryptoError("cipher key was not a string")

    errors: list[str] = []
    fields: list[FieldText] = []
    for name, value in (
        ("username", username),
        ("password", password),
        ("totp", totp),
    ):
        try:
            fields.append(_decrypt_field(value, item))
        except BitwardenCryptoError as exc:
            errors.append(f"{name}: {exc}")
            fields.append(FieldText(None, "failed", str(exc)))
    error = "; ".join(errors) if errors else None
    return DecryptedFill(
        username=fields[0],
        password=fields[1],
        totp=fields[2],
        item_key=item_state,
        error=error,
    )


def _untouched(value: object) -> FieldText:
    """Plaintext stays readable when the item key cannot be unwrapped."""

    field = locked_field(value)
    if field.state == "plaintext":
        return field
    if field.state == "empty":
        return field
    return FieldText(None, field.state)


def _decrypt_field(value: object, key: _SymmetricKey) -> FieldText:
    state = classify_field(value)
    if state == "absent":
        return FieldText(None, state)
    if state == "invalid":
        raise BitwardenCryptoError("field was not a string")
    if state == "empty":
        return FieldText("", state)
    if not isinstance(value, str):
        raise BitwardenCryptoError("field was not a string")
    if state == "plaintext":
        return FieldText(value, "plaintext")
    return FieldText(_decrypt_utf8(value, key), "decrypted")


def _decrypt_utf8(value: str, key: _SymmetricKey) -> str:
    parsed = _parse_supported(value)
    if parsed is None:
        unsupported = _unsupported_type(value)
        if unsupported is not None:
            raise BitwardenCryptoError(
                f"unsupported Bitwarden encryption type {unsupported} "
                "(this client decrypts AES-CBC type 0 and type 2 only)"
            )
        raise BitwardenCryptoError("field is not a type 0 or type 2 EncString")
    try:
        return _decrypt_parsed(parsed, key).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BitwardenCryptoError("decrypted field is not UTF-8") from exc


def _unwrap_item_key(cipher_key: str, user: _SymmetricKey) -> tuple[_SymmetricKey, str]:
    parsed = _parse_supported(cipher_key)
    if parsed is None:
        unsupported = _unsupported_type(cipher_key)
        if unsupported is not None:
            raise BitwardenCryptoError(
                f"unsupported Bitwarden encryption type {unsupported} "
                "(this client decrypts AES-CBC type 0 and type 2 only)"
            )
        raise BitwardenCryptoError("cipher key is not a type 0 or type 2 EncString")
    raw = _decrypt_parsed(parsed, user)
    if len(raw) in (32, 64):
        return _split_key(raw), "unwrapped"
    # Older clients encrypted the base64 text of the key instead of the raw bytes.
    try:
        decoded = _b64decode(raw.decode("utf-8").strip())
    except (UnicodeDecodeError, ValueError):
        raise BitwardenCryptoError("item key must be 32 or 64 bytes") from None
    if len(decoded) not in (32, 64):
        raise BitwardenCryptoError("item key must be 32 or 64 bytes")
    return _split_key(decoded), "unwrapped-base64"


def _split_key(raw: bytes) -> _SymmetricKey:
    if len(raw) == 64:
        return _SymmetricKey(raw[:32], raw[32:])
    if len(raw) == 32:
        return _SymmetricKey(raw, None)
    raise BitwardenCryptoError("symmetric key must be 32 or 64 bytes")


def _parse_supported(value: str) -> _EncString | None:
    text = value.strip()
    if len(text) < 8 or text[1:2] != "." or text[0] not in "02":
        return None
    rest = text[2:]
    parts = rest.split("|")
    enc_type = int(text[0])
    if enc_type == 2 and len(parts) != 3:
        if "|" in rest:
            raise BitwardenCryptoError("type 2 EncString must be iv|ciphertext|mac")
        return None
    if enc_type == 0 and len(parts) != 2:
        if "|" in rest:
            raise BitwardenCryptoError("type 0 EncString must be iv|ciphertext")
        return None
    try:
        blobs = [_b64decode(part) for part in parts]
    except ValueError as exc:
        raise BitwardenCryptoError(
            f"type {enc_type} EncString is not valid base64"
        ) from exc
    iv, data = blobs[0], blobs[1]
    if len(iv) != 16 or len(data) == 0 or len(data) % 16 != 0:
        raise BitwardenCryptoError(
            f"type {enc_type} EncString has an invalid IV or ciphertext length"
        )
    if enc_type == 0:
        return _EncString(0, iv, data, None)
    mac = blobs[2]
    if len(mac) != 32:
        raise BitwardenCryptoError("type 2 EncString MAC must be 32 bytes")
    return _EncString(2, iv, data, mac)


def _unsupported_type(value: str) -> int | None:
    text = value.strip()
    if len(text) < 8 or text[1:2] != "." or not text[0].isdigit() or text[0] in "02":
        return None
    rest = text[2:]
    enc_type = int(text[0])
    if "|" in rest:
        return enc_type
    if len(rest) < 16:
        return None
    try:
        raw = _b64decode(rest)
    except ValueError:
        return None
    if len(raw) >= 16:
        return enc_type
    return None


def _decrypt_parsed(enc: _EncString, key: _SymmetricKey) -> bytes:
    if enc.enc_type == 2:
        if key.mac_key is None or enc.mac is None:
            raise BitwardenCryptoError(
                "type 2 ciphertext needs a 64-byte key "
                "(32-byte AES key and 32-byte HMAC key)"
            )
        expected = hmac.new(key.mac_key, enc.iv + enc.data, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, enc.mac):
            raise BitwardenCryptoError("MAC mismatch")
        padded = _aes_cbc_decrypt(key.enc_key, enc.iv, enc.data)
    elif enc.enc_type == 0:
        padded = _aes_cbc_decrypt(key.enc_key, enc.iv, enc.data)
    else:
        raise BitwardenCryptoError(
            f"unsupported Bitwarden encryption type {enc.enc_type}"
        )
    return _pkcs7_unpad(padded)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 32:
        raise BitwardenCryptoError("AES-256 key must be 32 bytes")
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except ImportError as exc:
        raise BitwardenCryptoError(
            "AES decryption needs the cryptography package. "
            "Install examples/agent-fill-client/requirements.txt"
        ) from exc
    try:
        decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return decryptor.update(data) + decryptor.finalize()
    except ValueError as exc:
        raise BitwardenCryptoError("AES-CBC decryption failed") from exc


def _pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data or len(data) % block_size != 0:
        raise BitwardenCryptoError("invalid PKCS#7 padding")
    pad = data[-1]
    if pad < 1 or pad > block_size:
        raise BitwardenCryptoError("invalid PKCS#7 padding")
    if data[-pad:] != bytes([pad]) * pad:
        raise BitwardenCryptoError("invalid PKCS#7 padding")
    return data[:-pad]


def _b64decode(value: str) -> bytes:
    text = value.strip().replace("-", "+").replace("_", "/")
    if not text or any(char not in _B64_ALPHABET for char in text):
        raise ValueError("invalid base64")
    text += "=" * ((-len(text)) % 4)
    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("invalid base64") from exc
