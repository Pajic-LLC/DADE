from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from dade_identity import (
    IdentityChainResult,
    load_p256_public_key,
    owner_id,
    verify_identity_chain,
    verify_signed_map,
)
from dade_issuer import IssuerTrustResult, issuer_id, verify_deed_with_issuer_trust
from dade_verify import VerificationError, VerificationResult

ARRAY_TYPES = (list, tuple)


@dataclass(frozen=True)
class OwnerTrustState:
    owner_id: bytes
    sequence: int
    issued_at: int
    revoked_controllers: dict[bytes, int]


@dataclass(frozen=True)
class IssuerTrustState:
    issuer_id: bytes
    sequence: int
    issued_at: int
    rejected_signing_keys: dict[bytes, int]


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _is_uint(value: object) -> bool:
    return type(value) is int and value >= 0


def _bstr(value: object, name: str, size: int) -> bytes:
    _expect(isinstance(value, bytes), f"{name} must be bytes")
    _expect(len(value) == size, f"{name} must be {size} bytes")
    return value


def _sequence(value: object, minimum_sequence: int | None) -> int:
    _expect(_is_uint(value), "trust snapshot sequence must be an unsigned integer")
    sequence = value
    if minimum_sequence is not None:
        _expect(sequence >= minimum_sequence, "trust snapshot is older than remembered state")
    return sequence


def verify_owner_trust_snapshot(
    raw: bytes,
    anchor_public_key_pem: bytes,
    minimum_sequence: int | None = None,
) -> OwnerTrustState:
    anchor_public_key = load_p256_public_key(anchor_public_key_pem)
    payload = verify_signed_map(raw, anchor_public_key)

    _expect(set(payload.keys()) == set(range(1, 6)), "invalid owner trust snapshot fields")
    _expect(payload[1] == 1, "unsupported owner trust snapshot version")

    expected_owner_id = owner_id(anchor_public_key)
    claimed_owner_id = _bstr(payload[2], "owner trust owner_id", 16)
    _expect(claimed_owner_id == expected_owner_id, "owner trust snapshot belongs to the wrong owner")

    sequence = _sequence(payload[3], minimum_sequence)
    _expect(_is_uint(payload[4]), "owner trust issued_at must be an unsigned integer")

    entries = payload[5]
    _expect(isinstance(entries, ARRAY_TYPES), "revoked controller list must be an array")
    _expect(len(entries) <= 1024, "too many revoked controllers")

    revoked: dict[bytes, int] = {}
    for entry in entries:
        _expect(isinstance(entry, Mapping), "revoked controller entry must be a map")
        _expect(set(entry.keys()) == {1, 2}, "invalid revoked controller entry fields")
        controller_id = _bstr(entry[1], "revoked controller_id", 16)
        _expect(_is_uint(entry[2]), "controller revoked_at must be an unsigned integer")
        _expect(controller_id not in revoked, "duplicate revoked controller")
        revoked[controller_id] = entry[2]

    return OwnerTrustState(
        owner_id=claimed_owner_id,
        sequence=sequence,
        issued_at=payload[4],
        revoked_controllers=revoked,
    )


def verify_issuer_trust_snapshot(
    raw: bytes,
    root_public_key_pem: bytes,
    minimum_sequence: int | None = None,
) -> IssuerTrustState:
    root_public_key = load_p256_public_key(root_public_key_pem)
    payload = verify_signed_map(raw, root_public_key)

    _expect(set(payload.keys()) == set(range(1, 6)), "invalid issuer trust snapshot fields")
    _expect(payload[1] == 1, "unsupported issuer trust snapshot version")

    expected_issuer_id = issuer_id(root_public_key)
    claimed_issuer_id = _bstr(payload[2], "issuer trust issuer_id", 16)
    _expect(claimed_issuer_id == expected_issuer_id, "issuer trust snapshot belongs to the wrong issuer")

    sequence = _sequence(payload[3], minimum_sequence)
    _expect(_is_uint(payload[4]), "issuer trust issued_at must be an unsigned integer")

    entries = payload[5]
    _expect(isinstance(entries, ARRAY_TYPES), "rejected signing-key list must be an array")
    _expect(len(entries) <= 1024, "too many rejected signing keys")

    rejected: dict[bytes, int] = {}
    for entry in entries:
        _expect(isinstance(entry, Mapping), "rejected signing-key entry must be a map")
        _expect(set(entry.keys()) == {1, 2}, "invalid rejected signing-key entry fields")
        signing_key_id = _bstr(entry[1], "rejected signing key_id", 8)
        _expect(_is_uint(entry[2]), "reject_from must be an unsigned integer")
        _expect(signing_key_id not in rejected, "duplicate rejected signing key")
        rejected[signing_key_id] = entry[2]

    return IssuerTrustState(
        issuer_id=claimed_issuer_id,
        sequence=sequence,
        issued_at=payload[4],
        rejected_signing_keys=rejected,
    )


def require_controller_trusted(controller_id: bytes, state: OwnerTrustState | None) -> None:
    if state is None:
        return
    _bstr(controller_id, "controller_id", 16)
    _expect(controller_id not in state.revoked_controllers, "controller has been revoked")


def require_signing_key_trusted(
    signing_key_id: bytes,
    deed_issued_at: int,
    state: IssuerTrustState | None,
) -> None:
    if state is None:
        return

    _bstr(signing_key_id, "signing key_id", 8)
    _expect(_is_uint(deed_issued_at), "deed issued_at must be an unsigned integer")

    reject_from = state.rejected_signing_keys.get(signing_key_id)
    if reject_from is None:
        return

    _expect(deed_issued_at < reject_from, "deed was issued after signing key compromise cutoff")


def verify_deed_with_trust_state(
    deed_raw: bytes,
    root_public_key_pem: bytes,
    signing_credential_raw: bytes,
    issuer_trust_state: IssuerTrustState | None = None,
    expected_asset: str | None = None,
) -> IssuerTrustResult:
    result = verify_deed_with_issuer_trust(
        deed_raw,
        root_public_key_pem,
        signing_credential_raw,
        expected_asset=expected_asset,
    )

    if issuer_trust_state is not None:
        _expect(issuer_trust_state.issuer_id == result.issuer_id, "issuer trust state belongs to the wrong issuer")
        require_signing_key_trusted(
            result.signing_key_id,
            result.deed.issued_at,
            issuer_trust_state,
        )

    return result


def verify_identity_chain_with_trust_state(
    deed: VerificationResult,
    anchor_public_key_pem: bytes,
    controller_credential: bytes,
    device_authorization: bytes,
    device_proof: bytes,
    challenge: bytes,
    expected_asset: str,
    owner_trust_state: OwnerTrustState | None = None,
    requested_right: int = 1,
) -> IdentityChainResult:
    result = verify_identity_chain(
        deed,
        anchor_public_key_pem,
        controller_credential,
        device_authorization,
        device_proof,
        challenge,
        expected_asset,
        requested_right=requested_right,
    )

    if owner_trust_state is not None:
        _expect(owner_trust_state.owner_id == result.owner_id, "owner trust state belongs to the wrong owner")
        require_controller_trusted(result.controller_id, owner_trust_state)

    return result
