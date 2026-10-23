from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cryptography.hazmat.primitives import serialization

from dade_identity import (
    CONTROLLER_SCOPE_AUTHORIZE_DEVICES,
    DEVICE_SCOPE_USE_OWNED_ASSETS,
    RIGHT_USE,
    load_p256_public_key,
    owner_id,
    verify_controller_credential,
    verify_device_authorization,
    verify_device_proof,
)
from dade_issuer import issuer_id, verify_signing_credential
from dade_trust import (
    require_controller_trusted,
    require_signing_key_trusted,
    verify_issuer_trust_snapshot,
    verify_owner_trust_snapshot,
)
from dade_verify import VerificationError, verify_deed


class DecisionCode(str, Enum):
    OWNED = "owned"
    NOT_OWNED = "not_owned"
    WRONG_ASSET = "wrong_asset"
    INVALID_DEED = "invalid_deed"
    UNTRUSTED_ISSUER = "untrusted_issuer"
    OWNER_PROOF_FAILED = "owner_proof_failed"
    DEVICE_NOT_AUTHORIZED = "device_not_authorized"
    DEVICE_PROOF_FAILED = "device_proof_failed"
    CONTROLLER_REVOKED = "controller_revoked"
    ISSUER_KEY_REVOKED = "issuer_key_revoked"
    TRUST_STATE_ROLLBACK = "trust_state_rollback"
    RIGHT_NOT_GRANTED = "right_not_granted"


@dataclass(frozen=True)
class LocalArtifacts:
    deed: bytes | None
    issuer_root_public_key: bytes
    issuer_signing_credential: bytes
    owner_anchor_public_key: bytes
    controller_credential: bytes
    device_authorization: bytes
    device_proof: bytes
    owner_trust_snapshot: bytes | None = None
    issuer_trust_snapshot: bytes | None = None
    remembered_owner_trust_sequence: int | None = None
    remembered_issuer_trust_sequence: int | None = None


@dataclass(frozen=True)
class UseDecision:
    allowed: bool
    code: DecisionCode
    asset_id: str
    detail: str
    deed_id: bytes | None = None
    issuer_id: bytes | None = None
    owner_id: bytes | None = None
    controller_id: bytes | None = None
    device_id: bytes | None = None


def _deny(code: DecisionCode, asset_id: str, detail: str) -> UseDecision:
    return UseDecision(False, code, asset_id, detail)


def _rights_allow_local_use(
    rights: dict,
    platform: str | None,
    evaluation_time: int | None,
) -> tuple[bool, str]:
    if not rights.get(3, False):
        return False, "deed does not allow use on personal devices"

    platforms = rights.get(7)
    if platform is not None and platforms is not None and platform not in platforms:
        return False, f"deed does not include platform {platform}"

    use_mode = rights[1]
    if use_mode == 0:
        return True, "permanent use right is granted"

    if use_mode == 1:
        if evaluation_time is None:
            return False, "fixed-time use requires a local evaluation time"
        if evaluation_time > rights[8]:
            return False, "fixed-time use right has expired"
        return True, "fixed-time use right is still active"

    if use_mode == 2:
        return False, "subscription state is not defined by the local DADE 1 reference path"

    return False, "unsupported use right"


def can_use(
    asset_id: str,
    artifacts: LocalArtifacts,
    challenge: bytes,
    *,
    platform: str | None = None,
    evaluation_time: int | None = None,
) -> UseDecision:
    if artifacts.deed is None:
        return _deny(DecisionCode.NOT_OWNED, asset_id, "no local deed is available")

    try:
        root_public_key = load_p256_public_key(artifacts.issuer_root_public_key)
        expected_issuer_id = issuer_id(root_public_key)
        signing_credential = verify_signing_credential(
            artifacts.issuer_signing_credential,
            root_public_key,
            expected_issuer_id=expected_issuer_id,
        )
    except VerificationError as exc:
        return _deny(DecisionCode.UNTRUSTED_ISSUER, asset_id, str(exc))

    signing_public_key_pem = signing_credential.signing_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    try:
        deed = verify_deed(artifacts.deed, signing_public_key_pem)
    except VerificationError as exc:
        return _deny(DecisionCode.INVALID_DEED, asset_id, str(exc))

    if deed.asset_id != asset_id:
        return _deny(DecisionCode.WRONG_ASSET, asset_id, "deed belongs to another asset")

    if deed.issuer_id != expected_issuer_id:
        return _deny(DecisionCode.UNTRUSTED_ISSUER, asset_id, "deed issuer does not match trusted issuer")

    if not signing_credential.valid_from <= deed.issued_at <= signing_credential.valid_until:
        return _deny(
            DecisionCode.UNTRUSTED_ISSUER,
            asset_id,
            "deed was issued outside the signing credential validity window",
        )

    issuer_trust_state = None
    if artifacts.issuer_trust_snapshot is not None:
        try:
            issuer_trust_state = verify_issuer_trust_snapshot(
                artifacts.issuer_trust_snapshot,
                artifacts.issuer_root_public_key,
                minimum_sequence=artifacts.remembered_issuer_trust_sequence,
            )
        except VerificationError as exc:
            code = (
                DecisionCode.TRUST_STATE_ROLLBACK
                if "older than remembered state" in str(exc)
                else DecisionCode.UNTRUSTED_ISSUER
            )
            return _deny(code, asset_id, str(exc))

        if issuer_trust_state.issuer_id != expected_issuer_id:
            return _deny(DecisionCode.UNTRUSTED_ISSUER, asset_id, "issuer trust state belongs to another issuer")

        try:
            require_signing_key_trusted(
                signing_credential.signing_key_id,
                deed.issued_at,
                issuer_trust_state,
            )
        except VerificationError as exc:
            return _deny(DecisionCode.ISSUER_KEY_REVOKED, asset_id, str(exc))

    rights_ok, rights_detail = _rights_allow_local_use(deed.rights, platform, evaluation_time)
    if not rights_ok:
        return _deny(DecisionCode.RIGHT_NOT_GRANTED, asset_id, rights_detail)

    try:
        anchor_public_key = load_p256_public_key(artifacts.owner_anchor_public_key)
        expected_owner_id = owner_id(anchor_public_key)
    except VerificationError as exc:
        return _deny(DecisionCode.OWNER_PROOF_FAILED, asset_id, str(exc))

    if deed.owner_id != expected_owner_id:
        return _deny(DecisionCode.OWNER_PROOF_FAILED, asset_id, "deed owner does not match identity anchor")

    owner_trust_state = None
    if artifacts.owner_trust_snapshot is not None:
        try:
            owner_trust_state = verify_owner_trust_snapshot(
                artifacts.owner_trust_snapshot,
                artifacts.owner_anchor_public_key,
                minimum_sequence=artifacts.remembered_owner_trust_sequence,
            )
        except VerificationError as exc:
            code = (
                DecisionCode.TRUST_STATE_ROLLBACK
                if "older than remembered state" in str(exc)
                else DecisionCode.OWNER_PROOF_FAILED
            )
            return _deny(code, asset_id, str(exc))

    try:
        controller, controller_public_key = verify_controller_credential(
            artifacts.controller_credential,
            anchor_public_key,
            expected_owner_id,
        )
    except VerificationError as exc:
        return _deny(DecisionCode.OWNER_PROOF_FAILED, asset_id, str(exc))

    controller_scopes = set(controller[6])
    if CONTROLLER_SCOPE_AUTHORIZE_DEVICES not in controller_scopes:
        return _deny(
            DecisionCode.DEVICE_NOT_AUTHORIZED,
            asset_id,
            "controller cannot authorize personal devices",
        )

    claimed_controller_id = controller[4]
    if owner_trust_state is not None:
        if owner_trust_state.owner_id != expected_owner_id:
            return _deny(DecisionCode.OWNER_PROOF_FAILED, asset_id, "owner trust state belongs to another owner")
        try:
            require_controller_trusted(claimed_controller_id, owner_trust_state)
        except VerificationError as exc:
            return _deny(DecisionCode.CONTROLLER_REVOKED, asset_id, str(exc))

    try:
        device, device_public_key = verify_device_authorization(
            artifacts.device_authorization,
            controller_public_key,
            expected_owner_id,
            claimed_controller_id,
        )
    except VerificationError as exc:
        return _deny(DecisionCode.DEVICE_NOT_AUTHORIZED, asset_id, str(exc))

    device_scopes = set(device[7])
    if DEVICE_SCOPE_USE_OWNED_ASSETS not in device_scopes:
        return _deny(DecisionCode.DEVICE_NOT_AUTHORIZED, asset_id, "device cannot use owned assets")

    claimed_device_id = device[5]
    try:
        verify_device_proof(
            artifacts.device_proof,
            device_public_key,
            challenge,
            asset_id,
            RIGHT_USE,
            expected_owner_id,
            claimed_device_id,
        )
    except VerificationError as exc:
        return _deny(DecisionCode.DEVICE_PROOF_FAILED, asset_id, str(exc))

    return UseDecision(
        allowed=True,
        code=DecisionCode.OWNED,
        asset_id=asset_id,
        detail="local ownership proof is valid",
        deed_id=deed.deed_id,
        issuer_id=deed.issuer_id,
        owner_id=expected_owner_id,
        controller_id=claimed_controller_id,
        device_id=claimed_device_id,
    )
