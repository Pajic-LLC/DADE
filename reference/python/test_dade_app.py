from __future__ import annotations

import unittest
from dataclasses import replace

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dade_app import DecisionCode, LocalArtifacts, can_use
from dade_identity import controller_id, device_id, key_id, owner_id, public_key_to_cose
from dade_issuer import issuer_id


ASSET_ID = "com.pajic.vice"
CHALLENGE = bytes.fromhex("ab" * 32)
TERMS_HASH = bytes.fromhex("11" * 32)


def private_key(value: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(value, ec.SECP256R1())


ISSUER_ROOT = private_key(0x1111111111111111111111111111111111111111111111111111111111111111)
SIGNING_KEY = private_key(0x2222222222222222222222222222222222222222222222222222222222222222)
OWNER_ANCHOR = private_key(0x3333333333333333333333333333333333333333333333333333333333333333)
CONTROLLER = private_key(0x4444444444444444444444444444444444444444444444444444444444444444)
DEVICE = private_key(0x5555555555555555555555555555555555555555555555555555555555555555)
OTHER_ROOT = private_key(0x6666666666666666666666666666666666666666666666666666666666666666)


def pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_payload(payload: dict, signing_key: ec.EllipticCurvePrivateKey) -> bytes:
    protected = cbor2.dumps(
        {1: -7, 4: key_id(signing_key.public_key())},
        canonical=True,
    )
    payload_bytes = cbor2.dumps(payload, canonical=True)
    structure = cbor2.dumps(["Signature1", protected, b"", payload_bytes], canonical=True)
    der_signature = signing_key.sign(structure, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return cbor2.dumps(
        cbor2.CBORTag(18, [protected, {}, payload_bytes, signature]),
        canonical=True,
    )


def signing_credential() -> bytes:
    return sign_payload(
        {
            1: 1,
            2: bytes.fromhex("a1" * 16),
            3: issuer_id(ISSUER_ROOT.public_key()),
            4: key_id(SIGNING_KEY.public_key()),
            5: public_key_to_cose(SIGNING_KEY.public_key()),
            6: 1000,
            7: 3000,
        },
        ISSUER_ROOT,
    )


def deed(*, personal_devices: bool = True, platforms: list[str] | None = None) -> bytes:
    rights = {
        1: 0,
        2: 0,
        3: personal_devices,
        4: True,
        5: True,
        6: True,
    }
    if platforms is not None:
        rights[7] = platforms

    return sign_payload(
        {
            1: 1,
            2: bytes.fromhex("b1" * 16),
            3: ASSET_ID,
            4: issuer_id(ISSUER_ROOT.public_key()),
            5: owner_id(OWNER_ANCHOR.public_key()),
            6: rights,
            7: 1500,
            8: TERMS_HASH,
        },
        SIGNING_KEY,
    )


def controller_credential() -> bytes:
    return sign_payload(
        {
            1: 1,
            2: bytes.fromhex("c1" * 16),
            3: owner_id(OWNER_ANCHOR.public_key()),
            4: controller_id(CONTROLLER.public_key()),
            5: public_key_to_cose(CONTROLLER.public_key()),
            6: [1, 2],
            7: 1200,
        },
        OWNER_ANCHOR,
    )


def device_authorization() -> bytes:
    return sign_payload(
        {
            1: 1,
            2: bytes.fromhex("d1" * 16),
            3: owner_id(OWNER_ANCHOR.public_key()),
            4: controller_id(CONTROLLER.public_key()),
            5: device_id(DEVICE.public_key()),
            6: public_key_to_cose(DEVICE.public_key()),
            7: [1],
            8: 1300,
        },
        CONTROLLER,
    )


def device_proof() -> bytes:
    return sign_payload(
        {
            1: 1,
            2: CHALLENGE,
            3: ASSET_ID,
            4: 1,
            5: owner_id(OWNER_ANCHOR.public_key()),
            6: device_id(DEVICE.public_key()),
        },
        DEVICE,
    )


def owner_snapshot(sequence: int, *, revoke_controller: bool = False) -> bytes:
    entries = []
    if revoke_controller:
        entries.append({1: controller_id(CONTROLLER.public_key()), 2: 1600})
    return sign_payload(
        {
            1: 1,
            2: owner_id(OWNER_ANCHOR.public_key()),
            3: sequence,
            4: 1600,
            5: entries,
        },
        OWNER_ANCHOR,
    )


def issuer_snapshot(sequence: int, *, reject_from: int | None = None) -> bytes:
    entries = []
    if reject_from is not None:
        entries.append({1: key_id(SIGNING_KEY.public_key()), 2: reject_from})
    return sign_payload(
        {
            1: 1,
            2: issuer_id(ISSUER_ROOT.public_key()),
            3: sequence,
            4: 1600,
            5: entries,
        },
        ISSUER_ROOT,
    )


def artifacts() -> LocalArtifacts:
    return LocalArtifacts(
        deed=deed(platforms=["windows"]),
        issuer_root_public_key=pem(ISSUER_ROOT),
        issuer_signing_credential=signing_credential(),
        owner_anchor_public_key=pem(OWNER_ANCHOR),
        controller_credential=controller_credential(),
        device_authorization=device_authorization(),
        device_proof=device_proof(),
    )


class ApplicationVerificationTests(unittest.TestCase):
    def test_owned_asset_is_allowed(self) -> None:
        result = can_use(ASSET_ID, artifacts(), CHALLENGE, platform="windows")
        self.assertTrue(result.allowed)
        self.assertEqual(result.code, DecisionCode.OWNED)
        self.assertEqual(result.owner_id, owner_id(OWNER_ANCHOR.public_key()))
        self.assertEqual(result.device_id, device_id(DEVICE.public_key()))

    def test_missing_deed_is_not_owned(self) -> None:
        result = can_use(ASSET_ID, replace(artifacts(), deed=None), CHALLENGE)
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.NOT_OWNED)

    def test_wrong_asset_is_distinct(self) -> None:
        result = can_use("com.pajic.other", artifacts(), CHALLENGE)
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.WRONG_ASSET)

    def test_wrong_issuer_root_is_untrusted(self) -> None:
        result = can_use(
            ASSET_ID,
            replace(artifacts(), issuer_root_public_key=pem(OTHER_ROOT)),
            CHALLENGE,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.UNTRUSTED_ISSUER)

    def test_revoked_controller_is_rejected(self) -> None:
        result = can_use(
            ASSET_ID,
            replace(artifacts(), owner_trust_snapshot=owner_snapshot(4, revoke_controller=True)),
            CHALLENGE,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.CONTROLLER_REVOKED)

    def test_compromised_issuer_key_is_rejected(self) -> None:
        result = can_use(
            ASSET_ID,
            replace(artifacts(), issuer_trust_snapshot=issuer_snapshot(7, reject_from=1500)),
            CHALLENGE,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.ISSUER_KEY_REVOKED)

    def test_wrong_device_proof_is_distinct(self) -> None:
        result = can_use(ASSET_ID, artifacts(), bytes.fromhex("00" * 32))
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.DEVICE_PROOF_FAILED)

    def test_platform_outside_deed_is_not_granted(self) -> None:
        result = can_use(ASSET_ID, artifacts(), CHALLENGE, platform="macos")
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.RIGHT_NOT_GRANTED)

    def test_stale_owner_trust_snapshot_is_rejected(self) -> None:
        result = can_use(
            ASSET_ID,
            replace(
                artifacts(),
                owner_trust_snapshot=owner_snapshot(4),
                remembered_owner_trust_sequence=5,
            ),
            CHALLENGE,
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.code, DecisionCode.TRUST_STATE_ROLLBACK)


if __name__ == "__main__":
    unittest.main()
