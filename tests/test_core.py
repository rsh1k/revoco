"""Shared primitives. These underpin every signature in the system."""

from __future__ import annotations

import pytest

from revoco.core import crypto
from revoco.core.errors import ValidationError


def test_sign_and_verify_round_trip():
    priv, pub = crypto.generate_keypair()
    msg = b"authorize payment"
    assert crypto.verify(pub, msg, crypto.sign(priv, msg))


def test_verification_fails_for_a_different_key():
    priv, _pub = crypto.generate_keypair()
    _priv2, pub2 = crypto.generate_keypair()
    assert not crypto.verify(pub2, b"x", crypto.sign(priv, b"x"))


def test_verification_fails_for_altered_content():
    priv, pub = crypto.generate_keypair()
    sig = crypto.sign(priv, b"pay 100")
    assert not crypto.verify(pub, b"pay 900", sig)


def test_verification_returns_false_on_garbage_rather_than_raising():
    """Attacker-supplied input must never crash a verifier."""
    _priv, pub = crypto.generate_keypair()
    for junk in ("", "!!!!", "a" * 500, "====", "not-base64-at-all"):
        assert crypto.verify(pub, b"x", junk) is False


def test_canonical_bytes_is_key_order_independent():
    a = crypto.canonical_bytes({"b": 1, "a": {"d": 2, "c": 3}})
    b = crypto.canonical_bytes({"a": {"c": 3, "d": 2}, "b": 1})
    assert a == b


def test_canonical_bytes_distinguishes_different_content():
    assert crypto.canonical_bytes({"a": 1}) != crypto.canonical_bytes({"a": 2})


def test_canonical_bytes_preserves_non_ascii():
    assert "München".encode() in crypto.canonical_bytes({"city": "München"})


def test_digest_of_is_stable():
    obj = {"tool": "invoices.pay", "amount": 900}
    assert crypto.digest_of(obj) == crypto.digest_of(dict(reversed(list(obj.items()))))


def test_public_key_round_trips_through_base64():
    _priv, pub = crypto.generate_keypair()
    b64 = crypto.public_key_to_b64(pub)
    assert crypto.public_key_to_b64(crypto.public_key_from_b64(b64)) == b64


def test_private_key_round_trips_and_still_signs():
    priv, pub = crypto.generate_keypair()
    restored = crypto.private_key_from_b64(crypto.private_key_to_b64(priv))
    assert crypto.verify(pub, b"m", crypto.sign(restored, b"m"))


def test_malformed_key_material_raises_validation_error():
    with pytest.raises(ValidationError):
        crypto.public_key_from_b64("not-a-key")
    with pytest.raises(ValidationError):
        crypto.private_key_from_b64("nope")


def test_ids_are_prefixed_and_unique():
    from revoco.core import ids

    made = {ids.new_id("act") for _ in range(1000)}
    assert len(made) == 1000
    assert all(i.startswith("act_") for i in made)
