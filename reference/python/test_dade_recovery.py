from __future__ import annotations

import unittest

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dade_identity import (
    CONTROLLER_SCOPE_AUTHORIZE_DEVICES,
    controller_id,
    key_id,
    owner_id,
    public_key_to_cose,
    verify_controller_credential,
)
from dade_recovery import create_recovery_bundle, restore_owner_anchor
from dade_verify import VerificationError


ANCHOR_KEY = ec.derive_private_key(
    0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234,
    ec.SECP256R1(),
)
CONTROLLER_KEY = ec.derive_private_key(
    0x223456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234,
    ec.SECP256R1(),
)
RECOVERY_SECRET = bytes.fromhex("42" * 32)
WRONG_RECOVERY_SECRET = bytes.fromhex("99" * 32)
TEST_NONCE = bytes.fromhex("11" * 12)


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


def controller_credential(anchor_key: ec.EllipticCurvePrivateKey) -> bytes:
    controller_public_key = CONTROLLER_KEY.public_key()
    payload = {
        1: 1,
        2: bytes.fromhex("aa" * 16),
        3: owner_id(anchor_key.public_key()),
        4: controller_id(controller_public_key),
        5: public_key_to_cose(controller_public_key),
        6: [CONTROLLER_SCOPE_AUTHORIZE_DEVICES],
        7: 1000,
    }
    return sign_payload(payload, anchor_key)


class RecoveryTests(unittest.TestCase):
    def test_recovery_restores_same_owner(self) -> None:
        original_owner_id = owner_id(ANCHOR_KEY.public_key())
        bundle = create_recovery_bundle(
            ANCHOR_KEY,
            RECOVERY_SECRET,
            nonce=TEST_NONCE,
        )

        recovered = restore_owner_anchor(bundle, RECOVERY_SECRET)

        self.assertEqual(owner_id(recovered.public_key()), original_owner_id)
        self.assertEqual(
            recovered.private_numbers().private_value,
            ANCHOR_KEY.private_numbers().private_value,
        )

    def test_recovered_anchor_can_authorize_a_controller(self) -> None:
        bundle = create_recovery_bundle(
            ANCHOR_KEY,
            RECOVERY_SECRET,
            nonce=TEST_NONCE,
        )
        recovered = restore_owner_anchor(bundle, RECOVERY_SECRET)
        credential = controller_credential(recovered)

        payload, controller_public_key = verify_controller_credential(
            credential,
            recovered.public_key(),
            owner_id(ANCHOR_KEY.public_key()),
        )

        self.assertEqual(payload[3], owner_id(ANCHOR_KEY.public_key()))
        self.assertEqual(controller_id(controller_public_key), controller_id(CONTROLLER_KEY.public_key()))

    def test_wrong_recovery_secret_fails(self) -> None:
        bundle = create_recovery_bundle(
            ANCHOR_KEY,
            RECOVERY_SECRET,
            nonce=TEST_NONCE,
        )

        with self.assertRaisesRegex(VerificationError, "authentication failed"):
            restore_owner_anchor(bundle, WRONG_RECOVERY_SECRET)

    def test_tampered_bundle_fails(self) -> None:
        bundle = bytearray(
            create_recovery_bundle(
                ANCHOR_KEY,
                RECOVERY_SECRET,
                nonce=TEST_NONCE,
            )
        )
        bundle[-1] ^= 0x01

        with self.assertRaises(VerificationError):
            restore_owner_anchor(bytes(bundle), RECOVERY_SECRET)

    def test_tampered_owner_id_fails(self) -> None:
        bundle = create_recovery_bundle(
            ANCHOR_KEY,
            RECOVERY_SECRET,
            nonce=TEST_NONCE,
        )
        parsed = dict(cbor2.loads(bundle))
        parsed[2] = bytes.fromhex("77" * 16)
        tampered = cbor2.dumps(parsed, canonical=True)

        with self.assertRaisesRegex(VerificationError, "authentication failed"):
            restore_owner_anchor(tampered, RECOVERY_SECRET)


if __name__ == "__main__":
    unittest.main()
