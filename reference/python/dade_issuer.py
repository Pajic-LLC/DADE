from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dade_identity import (
    cose_to_public_key,
    key_id,
    load_p256_public_key,
    public_key_to_cose,
    verify_signed_map,
)
from dade_verify import VerificationError, VerificationResult, verify_deed

ISSUER_PREFIX = b"DADE1-ISSUER\x00"


@dataclass(frozen=True)
class SigningCredential:
    credential_id: bytes
    issuer_id: bytes
    signing_key_id: bytes
    signing_public_key: ec.EllipticCurvePublicKey
    valid_from: int
    valid_until: int


@dataclass(frozen=True)
class IssuerTrustResult:
    deed: VerificationResult
    issuer_id: bytes
    signing_key_id: bytes
    credential_id: bytes


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _bstr(value: object, name: str, size: int) -> bytes:
    _expect(isinstance(value, bytes), f"{name} must be bytes")
    _expect(len(value) == size, f"{name} must be {size} bytes")
    return value


def _canonical_cose_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return cbor2.dumps(public_key_to_cose(public_key), canonical=True)


def issuer_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(ISSUER_PREFIX + _canonical_cose_key(public_key)).digest()[:16]


def verify_signing_credential(
    raw: bytes,
    root_public_key: ec.EllipticCurvePublicKey,
    expected_issuer_id: bytes | None = None,
) -> SigningCredential:
    payload = verify_signed_map(raw, root_public_key)

    _expect(isinstance(payload, Mapping), "signing credential payload must be a map")
    _expect(set(payload.keys()) == set(range(1, 8)), "invalid signing credential fields")
    _expect(payload[1] == 1, "unsupported signing credential version")

    credential_id = _bstr(payload[2], "signing credential_id", 16)
    claimed_issuer_id = _bstr(payload[3], "signing credential issuer_id", 16)
    claimed_signing_key_id = _bstr(payload[4], "signing credential key_id", 8)
    signing_public_key = cose_to_public_key(payload[5])

    _expect(key_id(signing_public_key) == claimed_signing_key_id, "signing key id does not match signing key")
    _expect(_is_uint(payload[6]), "valid_from must be an unsigned integer")
    _expect(_is_uint(payload[7]), "valid_until must be an unsigned integer")
    _expect(payload[7] >= payload[6], "signing credential validity window is invalid")

    derived_issuer_id = issuer_id(root_public_key)
    _expect(claimed_issuer_id == derived_issuer_id, "signing credential belongs to the wrong issuer root")

    if expected_issuer_id is not None:
        _expect(claimed_issuer_id == expected_issuer_id, "signing credential issuer does not match")

    return SigningCredential(
        credential_id=credential_id,
        issuer_id=claimed_issuer_id,
        signing_key_id=claimed_signing_key_id,
        signing_public_key=signing_public_key,
        valid_from=payload[6],
        valid_until=payload[7],
    )


def verify_deed_with_issuer_trust(
    deed_raw: bytes,
    root_public_key_pem: bytes,
    signing_credential_raw: bytes,
    expected_asset: str | None = None,
) -> IssuerTrustResult:
    root_public_key = load_p256_public_key(root_public_key_pem)
    expected_issuer_id = issuer_id(root_public_key)

    credential = verify_signing_credential(
        signing_credential_raw,
        root_public_key,
        expected_issuer_id=expected_issuer_id,
    )

    signing_public_key_pem = credential.signing_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    deed = verify_deed(
        deed_raw,
        signing_public_key_pem,
        expected_asset=expected_asset,
    )

    _expect(deed.issuer_id == expected_issuer_id, "deed issuer does not match trusted issuer")
    _expect(
        credential.valid_from <= deed.issued_at <= credential.valid_until,
        "deed was issued outside the signing credential validity window",
    )

    return IssuerTrustResult(
        deed=deed,
        issuer_id=expected_issuer_id,
        signing_key_id=credential.signing_key_id,
        credential_id=credential.credential_id,
    )
