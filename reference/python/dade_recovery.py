from __future__ import annotations

import os
from collections.abc import Mapping

import cbor2
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from dade_identity import owner_id
from dade_verify import VerificationError

RECOVERY_VERSION = 1
RECOVERY_SECRET_BYTES = 32
RECOVERY_NONCE_BYTES = 12
MAX_RECOVERY_BUNDLE_BYTES = 4096
RECOVERY_AAD_PREFIX = b"DADE1-RECOVERY\x00"


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _bstr(value: object, name: str, size: int) -> bytes:
    _expect(isinstance(value, bytes), f"{name} must be bytes")
    _expect(len(value) == size, f"{name} must be {size} bytes")
    return value


def _aad(expected_owner_id: bytes) -> bytes:
    return RECOVERY_AAD_PREFIX + expected_owner_id


def create_recovery_bundle(
    anchor_private_key: ec.EllipticCurvePrivateKey,
    recovery_secret: bytes,
    *,
    nonce: bytes | None = None,
) -> bytes:
    _expect(isinstance(anchor_private_key.curve, ec.SECP256R1), "owner anchor must use P-256")
    _bstr(recovery_secret, "recovery secret", RECOVERY_SECRET_BYTES)

    if nonce is None:
        nonce = os.urandom(RECOVERY_NONCE_BYTES)
    _bstr(nonce, "recovery nonce", RECOVERY_NONCE_BYTES)

    expected_owner_id = owner_id(anchor_private_key.public_key())
    private_value = anchor_private_key.private_numbers().private_value.to_bytes(32, "big")

    plaintext = cbor2.dumps(
        {
            1: RECOVERY_VERSION,
            2: private_value,
        },
        canonical=True,
    )

    ciphertext = AESGCM(recovery_secret).encrypt(
        nonce,
        plaintext,
        _aad(expected_owner_id),
    )

    bundle = cbor2.dumps(
        {
            1: RECOVERY_VERSION,
            2: expected_owner_id,
            3: nonce,
            4: ciphertext,
        },
        canonical=True,
    )

    _expect(len(bundle) <= MAX_RECOVERY_BUNDLE_BYTES, "recovery bundle exceeds the maximum size")
    return bundle


def restore_owner_anchor(bundle: bytes, recovery_secret: bytes) -> ec.EllipticCurvePrivateKey:
    _expect(len(bundle) <= MAX_RECOVERY_BUNDLE_BYTES, "recovery bundle exceeds the maximum size")
    _bstr(recovery_secret, "recovery secret", RECOVERY_SECRET_BYTES)

    try:
        parsed = cbor2.loads(bundle)
    except Exception as exc:
        raise VerificationError("invalid recovery bundle") from exc

    _expect(isinstance(parsed, Mapping), "recovery bundle must be a map")
    _expect(set(parsed.keys()) == {1, 2, 3, 4}, "invalid recovery bundle fields")
    _expect(parsed[1] == RECOVERY_VERSION, "unsupported recovery bundle version")

    expected_owner_id = _bstr(parsed[2], "recovery owner_id", 16)
    nonce = _bstr(parsed[3], "recovery nonce", RECOVERY_NONCE_BYTES)
    _expect(isinstance(parsed[4], bytes), "recovery ciphertext must be bytes")

    _expect(cbor2.dumps(dict(parsed), canonical=True) == bundle, "recovery bundle is not deterministic CBOR")

    try:
        plaintext = AESGCM(recovery_secret).decrypt(
            nonce,
            parsed[4],
            _aad(expected_owner_id),
        )
    except InvalidTag as exc:
        raise VerificationError("recovery bundle authentication failed") from exc

    try:
        private_data = cbor2.loads(plaintext)
    except Exception as exc:
        raise VerificationError("invalid recovery private data") from exc

    _expect(isinstance(private_data, Mapping), "recovery private data must be a map")
    _expect(set(private_data.keys()) == {1, 2}, "invalid recovery private data fields")
    _expect(private_data[1] == RECOVERY_VERSION, "unsupported recovery private data version")
    private_value_bytes = _bstr(private_data[2], "owner anchor private value", 32)
    _expect(cbor2.dumps(dict(private_data), canonical=True) == plaintext, "recovery private data is not deterministic CBOR")

    private_value = int.from_bytes(private_value_bytes, "big")
    _expect(private_value != 0, "invalid owner anchor private key")

    try:
        anchor_private_key = ec.derive_private_key(private_value, ec.SECP256R1())
    except ValueError as exc:
        raise VerificationError("invalid owner anchor private key") from exc

    _expect(
        owner_id(anchor_private_key.public_key()) == expected_owner_id,
        "recovered owner anchor does not match owner_id",
    )

    return anchor_private_key
