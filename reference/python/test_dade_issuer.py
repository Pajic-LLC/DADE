from __future__ import annotations

import unittest

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dade_identity import key_id, public_key_to_cose
from dade_issuer import issuer_id, verify_deed_with_issuer_trust
from dade_verify import VerificationError


ASSET_ID = "com.pajic.vice"
OWNER_ID = bytes.fromhex("20000000000000000000000000000001")
TERMS_HASH = bytes.fromhex("11" * 32)


def private_key(value: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(value, ec.SECP256R1())


ROOT_KEY = private_key(0x123456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234)
OLD_SIGNING_KEY = private_key(0x223456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234)
NEW_SIGNING_KEY = private_key(0x323456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234)
WRONG_ROOT_KEY = private_key(0x423456789ABCDEF123456789ABCDEF123456789ABCDEF123456789ABCDEF1234)


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


def signing_credential(
    signing_key: ec.EllipticCurvePrivateKey,
    credential_byte: int,
    valid_from: int,
    valid_until: int,
) -> bytes:
    payload = {
        1: 1,
        2: bytes([credential_byte]) * 16,
        3: issuer_id(ROOT_KEY.public_key()),
        4: key_id(signing_key.public_key()),
        5: public_key_to_cose(signing_key.public_key()),
        6: valid_from,
        7: valid_until,
    }
    return sign_payload(payload, ROOT_KEY)


def deed(signing_key: ec.EllipticCurvePrivateKey, issued_at: int, deed_byte: int) -> bytes:
    payload = {
        1: 1,
        2: bytes([deed_byte]) * 16,
        3: ASSET_ID,
        4: issuer_id(ROOT_KEY.public_key()),
        5: OWNER_ID,
        6: {
            1: 0,
            2: 0,
            3: True,
            4: True,
            5: True,
            6: True,
            7: ["windows", "macos"],
        },
        7: issued_at,
        8: TERMS_HASH,
    }
    return sign_payload(payload, signing_key)


def root_pem(key: ec.EllipticCurvePrivateKey = ROOT_KEY) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class IssuerTrustTests(unittest.TestCase):
    def test_old_deed_survives_signing_key_rotation(self) -> None:
        old_credential = signing_credential(OLD_SIGNING_KEY, 0xA1, 1000, 1999)
        result = verify_deed_with_issuer_trust(
            deed(OLD_SIGNING_KEY, 1500, 0xB1),
            root_pem(),
            old_credential,
            expected_asset=ASSET_ID,
        )

        self.assertEqual(result.issuer_id, issuer_id(ROOT_KEY.public_key()))
        self.assertEqual(result.signing_key_id, key_id(OLD_SIGNING_KEY.public_key()))

    def test_new_key_uses_same_issuer_identity(self) -> None:
        new_credential = signing_credential(NEW_SIGNING_KEY, 0xA2, 2000, 2999)
        result = verify_deed_with_issuer_trust(
            deed(NEW_SIGNING_KEY, 2500, 0xB2),
            root_pem(),
            new_credential,
            expected_asset=ASSET_ID,
        )

        self.assertEqual(result.issuer_id, issuer_id(ROOT_KEY.public_key()))
        self.assertEqual(result.signing_key_id, key_id(NEW_SIGNING_KEY.public_key()))

    def test_wrong_root_is_not_trusted(self) -> None:
        old_credential = signing_credential(OLD_SIGNING_KEY, 0xA1, 1000, 1999)

        with self.assertRaises(VerificationError):
            verify_deed_with_issuer_trust(
                deed(OLD_SIGNING_KEY, 1500, 0xB1),
                root_pem(WRONG_ROOT_KEY),
                old_credential,
                expected_asset=ASSET_ID,
            )

    def test_deed_outside_credential_window_fails(self) -> None:
        old_credential = signing_credential(OLD_SIGNING_KEY, 0xA1, 1000, 1999)

        with self.assertRaisesRegex(
            VerificationError,
            "outside the signing credential validity window",
        ):
            verify_deed_with_issuer_trust(
                deed(OLD_SIGNING_KEY, 2500, 0xB3),
                root_pem(),
                old_credential,
                expected_asset=ASSET_ID,
            )


if __name__ == "__main__":
    unittest.main()
