import unittest
from pathlib import Path

from dade_verify import VerificationError, verify_deed

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "test-vectors"
PUBLIC_KEY = (VECTORS / "issuer-public-key.pem").read_bytes()


def read_hex(name: str) -> bytes:
    return bytes.fromhex((VECTORS / name).read_text(encoding="utf-8"))


class VerifyDeedTests(unittest.TestCase):
    def test_valid_deed(self) -> None:
        result = verify_deed(
            read_hex("valid-deed.hex"),
            PUBLIC_KEY,
            expected_asset="com.pajic.vice",
        )

        self.assertEqual(result.asset_id, "com.pajic.vice")
        self.assertEqual(result.rights[1], 0)
        self.assertEqual(result.rights[2], 1)
        self.assertTrue(result.rights[3])
        self.assertTrue(result.rights[4])
        self.assertTrue(result.rights[5])
        self.assertTrue(result.rights[6])

    def test_tampered_deed_fails(self) -> None:
        with self.assertRaisesRegex(VerificationError, "signature invalid"):
            verify_deed(
                read_hex("invalid-tampered-asset.hex"),
                PUBLIC_KEY,
            )

    def test_wrong_asset_fails(self) -> None:
        with self.assertRaisesRegex(VerificationError, "wrong asset"):
            verify_deed(
                read_hex("valid-deed.hex"),
                PUBLIC_KEY,
                expected_asset="com.pajic.some-other-game",
            )


if __name__ == "__main__":
    unittest.main()
