"""
praetor.core.crypto
===================
Cryptographic primitives — one implementation for the whole control plane.

Design choices are deliberately conservative and standards-aligned:

* Signatures: Ed25519 (EdDSA) — NIST FIPS 186-5 approved, deterministic,
  resistant to the nonce-reuse failures that plague ECDSA.
* Hashing: SHA-256 — NIST FIPS 180-4.
* Canonical serialization: RFC 8785-style sorted, separator-tight JSON so the
  bytes signed by a producer are *exactly* the bytes verified by a consumer.
  Any ambiguity here is a forgery vector, so it is centralized in one function.

This module never logs, prints, or persists private key material.

Note on the merge: the previous ``veritrail`` and ``mcp-gate`` packages each
carried their own signing and canonicalization code, with mcp-gate additionally
offering a symmetric HMAC mode. Symmetric identity is deliberately dropped here
-- in a control plane whose whole product is non-repudiation, a mode where the
verifier can also forge is a liability, not a convenience.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .errors import ValidationError

__all__ = [
    "canonical_bytes",
    "sha256_hex",
    "generate_keypair",
    "sign",
    "verify",
    "public_key_to_b64",
    "public_key_from_b64",
    "private_key_to_b64",
    "private_key_from_b64",
    "Ed25519PrivateKey",
    "Ed25519PublicKey",
]


def canonical_bytes(obj: Any) -> bytes:
    """Deterministically serialize an object to bytes for hashing/signing.

    Keys are sorted, whitespace stripped, non-ASCII preserved as UTF-8. The
    same logical object always yields identical bytes, which is the bedrock of
    a tamper-evident, signature-verifiable ledger.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Return the lowercase hex SHA-256 digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def digest_of(obj: Any) -> str:
    """Canonical SHA-256 digest of an arbitrary JSON-able object."""
    return sha256_hex(canonical_bytes(obj))


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair using the OS CSPRNG."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    """Sign ``message``; return a urlsafe-base64 signature with padding stripped."""
    raw = private_key.sign(message)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def verify(public_key: Ed25519PublicKey, message: bytes, signature_b64: str) -> bool:
    """Verify a base64 signature over ``message``. Returns True/False only.

    Verification failures are a normal ``False`` result rather than an
    exception, so callers cannot crash on attacker-supplied input — but an
    invalid signature can never be silently treated as valid.
    """
    try:
        padded = signature_b64 + "=" * (-len(signature_b64) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        public_key.verify(raw, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def public_key_to_b64(public_key: Ed25519PublicKey) -> str:
    """Serialize a public key to urlsafe base64, unpadded."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_key_from_b64(b64: str) -> Ed25519PublicKey:
    """Deserialize a public key. Raises ValidationError if malformed."""
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return Ed25519PublicKey.from_public_bytes(raw)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValidationError(f"invalid Ed25519 public key: {exc}") from None


def private_key_to_b64(private_key: Ed25519PrivateKey) -> str:
    """Serialize a private key to base64. Handle the result as a secret."""
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_key_from_b64(b64: str) -> Ed25519PrivateKey:
    """Deserialize a private key. Raises ValidationError if malformed."""
    try:
        padded = b64 + "=" * (-len(b64) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise ValidationError(f"invalid Ed25519 private key: {exc}") from None
