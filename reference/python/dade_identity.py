from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from dade_verify import VerificationError, VerificationResult

SUPPORTED_ALG = -7
ARRAY_TYPES = (list, tuple)

OWNER_PREFIX = b"DADE1-OWNER\x00"
CONTROLLER_PREFIX = b"DADE1-CONTROLLER\x00"
DEVICE_PREFIX = b"DADE1-DEVICE\x00"

CONTROLLER_SCOPE_AUTHORIZE_DEVICES = 1
CONTROLLER_SCOPE_PROVE_OWNER = 2
DEVICE_SCOPE_USE_OWNED_ASSETS = 1
RIGHT_USE = 1


@dataclass(frozen=True)
class IdentityChainResult:
    owner_id: bytes
    controller_id: bytes
    device_id: bytes
    asset_id: str
    requested_right: int


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _bstr(value: object, name: str, size: int) -> bytes:
    _expect(isinstance(value, bytes), f"{name} must be bytes")
    _expect(len(value) == size, f"{name} must be {size} bytes")
    return value


def _text(value: object, name: str, max_bytes: int) -> str:
    _expect(isinstance(value, str), f"{name} must be text")
    size = len(value.encode("utf-8"))
    _expect(1 <= size <= max_bytes, f"{name} has an invalid length")
    return value


def public_key_to_cose(public_key: ec.EllipticCurvePublicKey) -> dict:
    _expect(isinstance(public_key.curve, ec.SECP256R1), "public key must use P-256")
    numbers = public_key.public_numbers()
    return {
        1: 2,
        -1: 1,
        -2: numbers.x.to_bytes(32, "big"),
        -3: numbers.y.to_bytes(32, "big"),
    }


def cose_to_public_key(value: object) -> ec.EllipticCurvePublicKey:
    _expect(isinstance(value, Mapping), "COSE_Key must be a map")
    _expect(value.get(1) == 2, "COSE_Key must use EC2")
    _expect(value.get(-1) == 1, "COSE_Key must use P-256")
    x = _bstr(value.get(-2), "COSE_Key x", 32)
    y = _bstr(value.get(-3), "COSE_Key y", 32)
    _expect(-4 not in value, "public COSE_Key must not contain private key material")

    allowed = {1, -1, -2, -3}
    _expect(set(value.keys()) <= allowed, "unsupported COSE_Key field")

    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError as exc:
        raise VerificationError("invalid P-256 public key") from exc


def _canonical_cose_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return cbor2.dumps(public_key_to_cose(public_key), canonical=True)


def key_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(_canonical_cose_key(public_key)).digest()[:8]


def owner_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(OWNER_PREFIX + _canonical_cose_key(public_key)).digest()[:16]


def controller_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(CONTROLLER_PREFIX + _canonical_cose_key(public_key)).digest()[:16]


def device_id(public_key: ec.EllipticCurvePublicKey) -> bytes:
    return hashlib.sha256(DEVICE_PREFIX + _canonical_cose_key(public_key)).digest()[:16]


def load_p256_public_key(public_key_pem: bytes) -> ec.EllipticCurvePublicKey:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except Exception as exc:
        raise VerificationError("invalid public key") from exc

    _expect(isinstance(public_key, ec.EllipticCurvePublicKey), "public key must be an EC key")
    _expect(isinstance(public_key.curve, ec.SECP256R1), "public key must use P-256")
    return public_key


def verify_signed_map(raw: bytes, public_key: ec.EllipticCurvePublicKey) -> Mapping:
    try:
        cose = cbor2.loads(raw)
    except Exception as exc:
        raise VerificationError("invalid signed CBOR") from exc

    _expect(isinstance(cose, cbor2.CBORTag) and cose.tag == 18, "expected tagged COSE_Sign1")
    _expect(isinstance(cose.value, ARRAY_TYPES) and len(cose.value) == 4, "invalid COSE_Sign1 structure")

    protected_bytes, unprotected, payload_bytes, signature = cose.value
    _expect(isinstance(protected_bytes, bytes), "protected header must be bytes")
    _expect(isinstance(unprotected, Mapping) and not unprotected, "unprotected headers are not allowed")
    _expect(isinstance(payload_bytes, bytes), "embedded payload is required")
    _expect(isinstance(signature, bytes) and len(signature) == 64, "ES256 signature must be 64 bytes")

    try:
        protected = cbor2.loads(protected_bytes)
    except Exception as exc:
        raise VerificationError("invalid protected header") from exc

    _expect(isinstance(protected, Mapping), "protected header must be a map")
    _expect(protected.get(1) == SUPPORTED_ALG, "unsupported signature algorithm")
    _expect(protected.get(4) == key_id(public_key), "signing key id does not match")
    _expect(set(protected.keys()) <= {1, 4}, "unsupported protected header")

    sig_structure = cbor2.dumps(["Signature1", protected_bytes, b"", payload_bytes], canonical=True)
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    der_signature = encode_dss_signature(r, s)

    try:
        public_key.verify(der_signature, sig_structure, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise VerificationError("signature invalid") from exc

    try:
        payload = cbor2.loads(payload_bytes)
    except Exception as exc:
        raise VerificationError("invalid signed payload") from exc

    _expect(isinstance(payload, Mapping), "signed payload must be a map")
    _expect(cbor2.dumps(dict(payload), canonical=True) == payload_bytes, "signed payload is not deterministic CBOR")
    return payload


def verify_controller_credential(
    raw: bytes,
    anchor_public_key: ec.EllipticCurvePublicKey,
    expected_owner_id: bytes,
) -> tuple[Mapping, ec.EllipticCurvePublicKey]:
    payload = verify_signed_map(raw, anchor_public_key)
    required = set(range(1, 8))
    _expect(required <= set(payload.keys()), "controller credential is missing a required field")
    _expect(set(payload.keys()) <= set(range(1, 9)), "unsupported controller credential field")

    _expect(payload[1] == 1, "unsupported controller credential version")
    _bstr(payload[2], "controller credential_id", 16)
    _expect(_bstr(payload[3], "controller owner_id", 16) == expected_owner_id, "controller belongs to the wrong owner")
    claimed_controller_id = _bstr(payload[4], "controller_id", 16)
    controller_public_key = cose_to_public_key(payload[5])
    _expect(controller_id(controller_public_key) == claimed_controller_id, "controller_id does not match controller key")

    scopes = payload[6]
    _expect(isinstance(scopes, ARRAY_TYPES) and scopes, "controller scopes must be a non-empty array")
    _expect(all(_is_uint(scope) for scope in scopes), "controller scopes must be unsigned integers")
    _expect(len(scopes) == len(set(scopes)), "controller scopes must not contain duplicates")
    _expect(_is_uint(payload[7]), "controller issued_at must be an unsigned integer")
    if 8 in payload:
        _expect(_is_uint(payload[8]), "controller expires_at must be an unsigned integer")
        _expect(payload[8] >= payload[7], "controller expires_at precedes issued_at")

    return payload, controller_public_key


def verify_device_authorization(
    raw: bytes,
    controller_public_key: ec.EllipticCurvePublicKey,
    expected_owner_id: bytes,
    expected_controller_id: bytes,
) -> tuple[Mapping, ec.EllipticCurvePublicKey]:
    payload = verify_signed_map(raw, controller_public_key)
    required = set(range(1, 9))
    _expect(required <= set(payload.keys()), "device authorization is missing a required field")
    _expect(set(payload.keys()) <= set(range(1, 10)), "unsupported device authorization field")

    _expect(payload[1] == 1, "unsupported device authorization version")
    _bstr(payload[2], "device authorization_id", 16)
    _expect(_bstr(payload[3], "device owner_id", 16) == expected_owner_id, "device belongs to the wrong owner")
    _expect(
        _bstr(payload[4], "device controller_id", 16) == expected_controller_id,
        "device authorization was issued by the wrong controller",
    )
    claimed_device_id = _bstr(payload[5], "device_id", 16)
    device_public_key = cose_to_public_key(payload[6])
    _expect(device_id(device_public_key) == claimed_device_id, "device_id does not match device key")

    scopes = payload[7]
    _expect(isinstance(scopes, ARRAY_TYPES) and scopes, "device scopes must be a non-empty array")
    _expect(all(_is_uint(scope) for scope in scopes), "device scopes must be unsigned integers")
    _expect(len(scopes) == len(set(scopes)), "device scopes must not contain duplicates")
    _expect(_is_uint(payload[8]), "device issued_at must be an unsigned integer")
    if 9 in payload:
        _expect(_is_uint(payload[9]), "device expires_at must be an unsigned integer")
        _expect(payload[9] >= payload[8], "device expires_at precedes issued_at")

    return payload, device_public_key


def verify_device_proof(
    raw: bytes,
    device_public_key: ec.EllipticCurvePublicKey,
    expected_challenge: bytes,
    expected_asset: str,
    expected_right: int,
    expected_owner_id: bytes,
    expected_device_id: bytes,
) -> Mapping:
    payload = verify_signed_map(raw, device_public_key)
    _expect(set(payload.keys()) == set(range(1, 7)), "invalid device proof fields")
    _expect(payload[1] == 1, "unsupported device proof version")
    _expect(_bstr(payload[2], "device proof challenge", 32) == expected_challenge, "device proof challenge does not match")
    _expect(_text(payload[3], "device proof asset_id", 255) == expected_asset, "device proof asset does not match")
    _expect(_is_uint(payload[4]) and payload[4] == expected_right, "device proof right does not match")
    _expect(_bstr(payload[5], "device proof owner_id", 16) == expected_owner_id, "device proof owner does not match")
    _expect(_bstr(payload[6], "device proof device_id", 16) == expected_device_id, "device proof device does not match")
    return payload


def verify_identity_chain(
    deed: VerificationResult,
    anchor_public_key_pem: bytes,
    controller_credential: bytes,
    device_authorization: bytes,
    device_proof: bytes,
    challenge: bytes,
    expected_asset: str,
    requested_right: int = RIGHT_USE,
) -> IdentityChainResult:
    _expect(len(challenge) == 32, "challenge must be 32 bytes")
    _expect(deed.asset_id == expected_asset, "deed asset does not match")

    anchor_public_key = load_p256_public_key(anchor_public_key_pem)
    expected_owner_id = owner_id(anchor_public_key)
    _expect(deed.owner_id == expected_owner_id, "deed owner does not match identity anchor")

    controller, controller_public_key = verify_controller_credential(
        controller_credential,
        anchor_public_key,
        expected_owner_id,
    )
    scopes = set(controller[6])
    _expect(CONTROLLER_SCOPE_AUTHORIZE_DEVICES in scopes, "controller cannot authorize devices")
    claimed_controller_id = controller[4]

    device, device_public_key = verify_device_authorization(
        device_authorization,
        controller_public_key,
        expected_owner_id,
        claimed_controller_id,
    )
    device_scopes = set(device[7])
    _expect(DEVICE_SCOPE_USE_OWNED_ASSETS in device_scopes, "device cannot use owned assets")
    claimed_device_id = device[5]

    verify_device_proof(
        device_proof,
        device_public_key,
        challenge,
        expected_asset,
        requested_right,
        expected_owner_id,
        claimed_device_id,
    )

    return IdentityChainResult(
        owner_id=expected_owner_id,
        controller_id=claimed_controller_id,
        device_id=claimed_device_id,
        asset_id=expected_asset,
        requested_right=requested_right,
    )
