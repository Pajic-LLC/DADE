from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

MAX_DEED_BYTES = 64 * 1024
SUPPORTED_VERSION = 1
SUPPORTED_ALG = -7
KNOWN_TOP_LEVEL_FIELDS = set(range(1, 12))
ARRAY_TYPES = (list, tuple)


class VerificationError(Exception):
    pass


@dataclass(frozen=True)
class VerificationResult:
    asset_id: str
    deed_id: bytes
    issuer_id: bytes
    owner_id: bytes
    rights: dict
    issued_at: int


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _check_text(value: object, name: str, max_bytes: int) -> str:
    _expect(isinstance(value, str), f"{name} must be text")
    size = len(value.encode("utf-8"))
    _expect(1 <= size <= max_bytes, f"{name} has an invalid length")
    return value


def _check_bstr(value: object, name: str, size: int) -> bytes:
    _expect(isinstance(value, bytes), f"{name} must be bytes")
    _expect(len(value) == size, f"{name} must be {size} bytes")
    return value


def _validate_rights(rights: object) -> dict:
    _expect(isinstance(rights, Mapping), "rights must be a map")

    for label in range(1, 7):
        _expect(label in rights, f"rights field {label} is required")

    use_mode = rights[1]
    offline_mode = rights[2]

    _expect(_is_uint(use_mode) and use_mode in {0, 1, 2}, "invalid use mode")
    _expect(_is_uint(offline_mode) and offline_mode in {0, 1, 2}, "invalid offline mode")

    for label in (3, 4, 5, 6):
        _expect(type(rights[label]) is bool, f"rights field {label} must be boolean")

    if use_mode == 1:
        _expect(8 in rights and _is_uint(rights[8]), "use_until is required for fixed-time use")
    else:
        _expect(8 not in rights, "use_until is only valid for fixed-time use")

    if 7 in rights:
        platforms = rights[7]
        _expect(isinstance(platforms, ARRAY_TYPES) and 1 <= len(platforms) <= 32, "invalid platforms list")
        for platform in platforms:
            _check_text(platform, "platform", 32)

    if 9 in rights:
        dependencies = rights[9]
        _expect(
            isinstance(dependencies, ARRAY_TYPES) and 1 <= len(dependencies) <= 32,
            "invalid service dependency list",
        )
        for dependency in dependencies:
            _check_text(dependency, "service dependency", 128)

    return dict(rights)


def _public_key_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    numbers = public_key.public_numbers()
    cose_key = {
        1: 2,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }
    return hashlib.sha256(cbor2.dumps(cose_key, canonical=True)).digest()[:8]


def verify_deed(raw: bytes, public_key_pem: bytes, expected_asset: str | None = None) -> VerificationResult:
    _expect(len(raw) <= MAX_DEED_BYTES, "deed exceeds the maximum size")

    try:
        cose = cbor2.loads(raw)
    except Exception as exc:
        raise VerificationError("invalid CBOR") from exc

    _expect(isinstance(cose, cbor2.CBORTag) and cose.tag == 18, "expected tagged COSE_Sign1")
    _expect(isinstance(cose.value, ARRAY_TYPES) and len(cose.value) == 4, "invalid COSE_Sign1 structure")

    protected_bytes, unprotected, payload_bytes, signature = cose.value

    _expect(isinstance(protected_bytes, bytes), "protected header must be bytes")
    _expect(isinstance(unprotected, Mapping) and not unprotected, "unprotected headers are not allowed in this draft")
    _expect(isinstance(payload_bytes, bytes), "embedded payload is required")
    _expect(isinstance(signature, bytes) and len(signature) == 64, "ES256 signature must be 64 bytes")

    try:
        protected = cbor2.loads(protected_bytes)
    except Exception as exc:
        raise VerificationError("invalid protected header") from exc

    _expect(isinstance(protected, Mapping), "protected header must decode to a map")
    _expect(protected.get(1) == SUPPORTED_ALG, "unsupported COSE algorithm")
    _expect(isinstance(protected.get(4), bytes), "protected kid is required")
    _expect(set(protected.keys()) <= {1, 4}, "unsupported protected header")

    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise VerificationError("invalid issuer public key") from exc

    _expect(isinstance(public_key, ec.EllipticCurvePublicKey), "issuer key must be an EC public key")
    _expect(isinstance(public_key.curve, ec.SECP256R1), "issuer key must use P-256")
    _expect(protected[4] == _public_key_id(public_key), "issuer key id does not match the public key")

    sig_structure = cbor2.dumps(["Signature1", protected_bytes, b"", payload_bytes], canonical=True)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)

    try:
        public_key.verify(der_signature, sig_structure, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerificationError("signature invalid") from exc

    try:
        deed = cbor2.loads(payload_bytes)
    except Exception as exc:
        raise VerificationError("invalid deed payload") from exc

    _expect(isinstance(deed, Mapping), "deed payload must be a map")
    normalized_deed = dict(deed)
    _expect(cbor2.dumps(normalized_deed, canonical=True) == payload_bytes, "deed payload is not deterministic CBOR")

    required = set(range(1, 9))
    _expect(required <= set(deed.keys()), "deed is missing a required field")

    critical = deed.get(11, [])
    _expect(isinstance(critical, ARRAY_TYPES) and len(critical) <= 32, "invalid critical field list")
    for label in critical:
        _expect(_is_uint(label), "critical field labels must be unsigned integers")
        _expect(label in KNOWN_TOP_LEVEL_FIELDS, f"unknown critical field {label}")

    _expect(deed[1] == SUPPORTED_VERSION, "unsupported DADE version")
    deed_id = _check_bstr(deed[2], "deed_id", 16)
    asset_id = _check_text(deed[3], "asset_id", 255)
    issuer_id = _check_bstr(deed[4], "issuer_id", 16)
    owner_id = _check_bstr(deed[5], "owner_id", 16)
    rights = _validate_rights(deed[6])
    _expect(_is_uint(deed[7]), "issued_at must be an unsigned integer")
    _check_bstr(deed[8], "terms_sha256", 32)

    if 9 in deed:
        _check_text(deed[9], "terms_uri", 2048)
    if 10 in deed:
        _check_text(deed[10], "edition", 128)

    if expected_asset is not None:
        _expect(asset_id == expected_asset, "wrong asset")

    return VerificationResult(
        asset_id=asset_id,
        deed_id=deed_id,
        issuer_id=issuer_id,
        owner_id=owner_id,
        rights=rights,
        issued_at=deed[7],
    )


def _load_hex(path: Path) -> bytes:
    try:
        return bytes.fromhex(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise VerificationError("could not read deed hex file") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a DADE 1 draft deed test vector")
    parser.add_argument("deed", type=Path)
    parser.add_argument("public_key", type=Path)
    parser.add_argument("--asset", dest="expected_asset")
    args = parser.parse_args()

    try:
        result = verify_deed(
            _load_hex(args.deed),
            args.public_key.read_bytes(),
            expected_asset=args.expected_asset,
        )
    except VerificationError as exc:
        print(f"invalid: {exc}", file=sys.stderr)
        return 1

    print(f"valid: {result.asset_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
