import unittest
from pathlib import Path

from dade_identity import RIGHT_USE, verify_identity_chain
from dade_verify import VerificationError, verify_deed

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test-vectors"
IDENTITY = VECTORS / "identity"
ISSUER_KEY = (VECTORS / "issuer-public-key.pem").read_bytes()
ANCHOR_KEY = (IDENTITY / "anchor-public-key.pem").read_bytes()
CHALLENGE = bytes.fromhex("fca6dee2372a043effc2f57dc8aaedb639ff31cee6777a4221414a18b47e8fac")


def read_hex(path: Path) -> bytes:
    return bytes.fromhex(path.read_text(encoding="utf-8"))


def verified_deed():
    return verify_deed(
        read_hex(IDENTITY / "owned-device-deed.hex"),
        ISSUER_KEY,
        expected_asset="com.pajic.vice",
    )


class IdentityChainTests(unittest.TestCase):
    def test_valid_identity_chain(self) -> None:
        result = verify_identity_chain(
            verified_deed(),
            ANCHOR_KEY,
            read_hex(IDENTITY / "controller-credential.hex"),
            read_hex(IDENTITY / "device-authorization.hex"),
            read_hex(IDENTITY / "device-proof.hex"),
            CHALLENGE,
            "com.pajic.vice",
            RIGHT_USE,
        )

        self.assertEqual(result.owner_id.hex(), "6a68a10eb0a0747a549dfda8cfa82fe8")
        self.assertEqual(result.controller_id.hex(), "7547b84b4bdc8a90839042c1310163a8")
        self.assertEqual(result.device_id.hex(), "17ccc41d5b1723cae307d65b2008b8c7")
        self.assertEqual(result.asset_id, "com.pajic.vice")
        self.assertEqual(result.requested_right, RIGHT_USE)

    def test_wrong_challenge_fails(self) -> None:
        wrong_challenge = b"\x00" * 32

        with self.assertRaisesRegex(VerificationError, "challenge does not match"):
            verify_identity_chain(
                verified_deed(),
                ANCHOR_KEY,
                read_hex(IDENTITY / "controller-credential.hex"),
                read_hex(IDENTITY / "device-authorization.hex"),
                read_hex(IDENTITY / "device-proof.hex"),
                wrong_challenge,
                "com.pajic.vice",
                RIGHT_USE,
            )

    def test_wrong_anchor_fails(self) -> None:
        with self.assertRaisesRegex(VerificationError, "deed owner does not match identity anchor"):
            verify_identity_chain(
                verified_deed(),
                ISSUER_KEY,
                read_hex(IDENTITY / "controller-credential.hex"),
                read_hex(IDENTITY / "device-authorization.hex"),
                read_hex(IDENTITY / "device-proof.hex"),
                CHALLENGE,
                "com.pajic.vice",
                RIGHT_USE,
            )


if __name__ == "__main__":
    unittest.main()
