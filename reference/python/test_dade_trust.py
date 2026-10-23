from __future__ import annotations

import unittest

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dade_identity import controller_id, key_id, owner_id
from dade_issuer import issuer_id
from dade_trust import (
    require_controller_trusted,
    require_signing_key_trusted,
    verify_issuer_trust_snapshot,
    verify_owner_trust_snapshot,
)
from dade_verify import VerificationError


def private_key(value: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(value, ec.SECP256R1())


OWNER_ANCHOR = private_key(0x1111111111111111111111111111111111111111111111111111111111111111)
CONTROLLER = private_key(0x2222222222222222222222222222222222222222222222222222222222222222)
OTHER_ANCHOR = private_key(0x3333333333333333333333333333333333333333333333333333333333333333)
ISSUER_ROOT = private_key(0x4444444444444444444444444444444444444444444444444444444444444444)
SIGNING_KEY = private_key(0x5555555555555555555555555555555555555555555555555555555555555555)
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


def owner_snapshot(sequence: int, revoked: bool = True) -> bytes:
    entries = []
    if revoked:
        entries.append({1: controller_id(CONTROLLER.public_key()), 2: 5000})

    return sign_payload(
        {
            1: 1,
            2: owner_id(OWNER_ANCHOR.public_key()),
            3: sequence,
            4: 5001,
            5: entries,
        },
        OWNER_ANCHOR,
    )


def issuer_snapshot(sequence: int, reject_from: int = 2000) -> bytes:
    return sign_payload(
        {
            1: 1,
            2: issuer_id(ISSUER_ROOT.public_key()),
            3: sequence,
            4: 5001,
            5: [{1: key_id(SIGNING_KEY.public_key()), 2: reject_from}],
        },
        ISSUER_ROOT,
    )


class TrustUpdateTests(unittest.TestCase):
    def test_owner_snapshot_revokes_controller(self) -> None:
        state = verify_owner_trust_snapshot(owner_snapshot(4), pem(OWNER_ANCHOR))
        self.assertEqual(state.sequence, 4)
        with self.assertRaisesRegex(VerificationError, "controller has been revoked"):
            require_controller_trusted(controller_id(CONTROLLER.public_key()), state)

    def test_owner_snapshot_rejects_rollback(self) -> None:
        with self.assertRaisesRegex(VerificationError, "older than remembered state"):
            verify_owner_trust_snapshot(
                owner_snapshot(4),
                pem(OWNER_ANCHOR),
                minimum_sequence=5,
            )

    def test_owner_snapshot_requires_owner_anchor(self) -> None:
        with self.assertRaises(VerificationError):
            verify_owner_trust_snapshot(owner_snapshot(4), pem(OTHER_ANCHOR))

    def test_issuer_cutoff_preserves_old_deed(self) -> None:
        state = verify_issuer_trust_snapshot(issuer_snapshot(7, reject_from=2000), pem(ISSUER_ROOT))
        require_signing_key_trusted(key_id(SIGNING_KEY.public_key()), 1999, state)

    def test_issuer_cutoff_rejects_compromised_window(self) -> None:
        state = verify_issuer_trust_snapshot(issuer_snapshot(7, reject_from=2000), pem(ISSUER_ROOT))
        with self.assertRaisesRegex(VerificationError, "compromise cutoff"):
            require_signing_key_trusted(key_id(SIGNING_KEY.public_key()), 2000, state)

    def test_issuer_snapshot_rejects_rollback(self) -> None:
        with self.assertRaisesRegex(VerificationError, "older than remembered state"):
            verify_issuer_trust_snapshot(
                issuer_snapshot(7),
                pem(ISSUER_ROOT),
                minimum_sequence=8,
            )

    def test_issuer_snapshot_requires_issuer_root(self) -> None:
        with self.assertRaises(VerificationError):
            verify_issuer_trust_snapshot(issuer_snapshot(7), pem(OTHER_ROOT))


if __name__ == "__main__":
    unittest.main()
