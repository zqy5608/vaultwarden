"""Master-password KDF for publishing URI indexes.

Derives the 32-byte master key and the server login hash. The stretched key
unwraps the account encryption key. This module does not decrypt login
passwords.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from bw_crypto import BitwardenCryptoError, decode_key_bytes, decrypt_to_bytes

_MAX_PBKDF2_ITERATIONS = 2_000_000
_MAX_ARGON2_MEMORY_MB = 1024
_MAX_ARGON2_TIME = 16
_MAX_ARGON2_PARALLELISM = 16


class KdfError(Exception):
    """The server KDF settings cannot be used, or derivation failed."""


def derive_master_key(
    password: str,
    email: str,
    kdf: int,
    iterations: int,
    memory_mb: int | None = None,
    parallelism: int | None = None,
) -> bytes:
    """Return the 32-byte master key for this email and password.

    ``kdf`` 0 is PBKDF2-HMAC-SHA256 with the lowercased email as salt.
    ``kdf`` 1 is Argon2id. The salt is SHA-256 of that email, ``memory_mb``
    is mebibytes (converted to kibibytes), and the output is 32 bytes.
    """

    salt = email.strip().lower().encode("utf-8")
    if not salt:
        raise KdfError("email is empty")
    if not password:
        raise KdfError("master password is empty")
    if kdf in (0, None):
        if iterations < 1 or iterations > _MAX_PBKDF2_ITERATIONS:
            raise KdfError(
                "PBKDF2 iterations from the server are outside 1.."
                f"{_MAX_PBKDF2_ITERATIONS}"
            )
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=32)
    if kdf == 1:
        if memory_mb is None or parallelism is None:
            raise KdfError("Argon2id settings are missing memory or parallelism")
        if iterations < 1 or iterations > _MAX_ARGON2_TIME:
            raise KdfError("Argon2id iterations from the server are outside the accepted range")
        if memory_mb < 1 or memory_mb > _MAX_ARGON2_MEMORY_MB:
            raise KdfError("Argon2id memory from the server is outside 1..1024 MiB")
        if parallelism < 1 or parallelism > _MAX_ARGON2_PARALLELISM:
            raise KdfError("Argon2id parallelism from the server is outside the accepted range")
        try:
            from argon2.low_level import Type, hash_secret_raw
        except ImportError as exc:
            raise KdfError(
                "this account uses Argon2id. Install argon2-cffi from "
                "examples/agent-fill-client/requirements.txt"
            ) from exc
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=hashlib.sha256(salt).digest(),
            time_cost=iterations,
            memory_cost=memory_mb * 1024,
            parallelism=parallelism,
            hash_len=32,
            type=Type.ID,
            version=19,
        )
    raise KdfError(f"unsupported KDF type {kdf}")


def master_password_hash(master_key: bytes, password: str) -> str:
    """Base64 login hash. One PBKDF2-HMAC-SHA256 round, password as the salt."""

    if len(master_key) != 32:
        raise KdfError("master key must be 32 bytes")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        master_key,
        password.encode("utf-8"),
        1,
        dklen=32,
    )
    return base64.b64encode(digest).decode("ascii")


def stretch_master_key(master_key: bytes) -> bytes:
    """HKDF-Expand the 32-byte master key into a 64-byte enc||mac key.

    Bitwarden uses the master key as the PRK and the info strings ``enc`` and
    ``mac``. There is no HKDF-Extract step.
    """

    if len(master_key) != 32:
        raise KdfError("master key must be 32 bytes")
    enc = _hkdf_expand(master_key, b"enc", 32)
    mac = _hkdf_expand(master_key, b"mac", 32)
    return enc + mac


def unwrap_account_key(encrypted_key: str, master_key: bytes) -> bytes:
    """Unwrap the account symmetric key stored on the user.

    Type 2 keys are encrypted with the stretched master key. Type 0 keys are
    encrypted with the raw 32-byte master key.
    """

    text = encrypted_key.strip()
    if text.startswith("2."):
        wrapping = stretch_master_key(master_key)
    elif text.startswith("0."):
        wrapping = master_key
    else:
        raise BitwardenCryptoError("account key is not a type 0 or type 2 EncString")
    return decode_key_bytes(decrypt_to_bytes(text, wrapping))


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = 32
    if length > 255 * hash_len:
        raise KdfError("HKDF length is too large")
    okm = b""
    previous = b""
    counter = 1
    while len(okm) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        okm += previous
        counter += 1
    return okm[:length]
