from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

import generate_retail_slice as retail
import stage_vice_provider
from dade_app import DecisionCode, LocalArtifacts, can_use
from dade_identity import device_id


CHALLENGE = bytes.fromhex("42" * 32)


def read_hex(path: Path) -> bytes:
    return bytes.fromhex(path.read_text(encoding="utf-8"))


class RetailSliceFixtureTests(unittest.TestCase):
    def test_hardware_mode_keeps_private_device_key_out_of_install_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            device_private = ec.generate_private_key(ec.SECP256R1())
            metadata = retail.generate(
                output,
                asset_id="com.pajic.stagej.test",
                platforms=["windows"],
                device_public_key=device_private.public_key(),
                development_file_signer=False,
                force=False,
            )

            install = output / "install" / "dade-home"
            owner = bytes.fromhex(str(metadata["owner_id"]))
            issuer = bytes.fromhex(str(metadata["issuer_id"]))
            device = bytes.fromhex(str(metadata["device_id"]))
            asset = str(metadata["asset_id"])

            self.assertFalse((install / "devices" / f"{device.hex()}.pem").exists())
            self.assertFalse((output / "secrets" / "development-device-private.pem").exists())
            self.assertTrue((output / "secrets" / "issuer-root-private.pem").is_file())
            self.assertTrue((output / "trust-updates" / "owner-controller-revoked-sequence-2.hex").is_file())

            proof = retail.sign_payload(
                {
                    1: 1,
                    2: CHALLENGE,
                    3: asset,
                    4: 1,
                    5: owner,
                    6: device,
                },
                device_private,
            )
            owner_root = install / "owners" / owner.hex()
            issuer_root = install / "trust" / "issuers" / issuer.hex()
            asset_root = install / "assets" / asset
            artifacts = LocalArtifacts(
                deed=read_hex(asset_root / "deed.hex"),
                issuer_root_public_key=(issuer_root / "root.pem").read_bytes(),
                issuer_signing_credential=read_hex(asset_root / "signing-credential.hex"),
                owner_anchor_public_key=(owner_root / "anchor.pem").read_bytes(),
                controller_credential=read_hex(owner_root / "controller.hex"),
                device_authorization=read_hex(owner_root / "device-authorization.hex"),
                device_proof=proof,
            )
            result = can_use(asset, artifacts, CHALLENGE, platform="windows")
            self.assertTrue(result.allowed, result.detail)
            self.assertEqual(result.code, DecisionCode.OWNED)
            self.assertEqual(result.owner_id, owner)
            self.assertEqual(result.device_id, device)
            self.assertEqual(device, device_id(device_private.public_key()))

    def test_development_mode_is_explicit_about_file_backed_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            metadata = retail.generate(
                output,
                asset_id="com.pajic.stagej.dev",
                platforms=["macos", "windows"],
                device_public_key=None,
                development_file_signer=True,
                force=False,
            )
            device = str(metadata["device_id"])
            install_key = output / "install" / "dade-home" / "devices" / f"{device}.pem"
            self.assertTrue(install_key.is_file())
            self.assertTrue((output / "secrets" / "development-device-private.pem").is_file())
            self.assertTrue(metadata["private_keys_in_install_root"])

    def test_fixture_output_is_create_only_without_force(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "fixture"
            retail.generate(
                output,
                asset_id="com.pajic.stagej.once",
                platforms=["windows"],
                device_public_key=None,
                development_file_signer=True,
                force=False,
            )
            with self.assertRaises(FileExistsError):
                retail.generate(
                    output,
                    asset_id="com.pajic.stagej.once",
                    platforms=["windows"],
                    device_public_key=None,
                    development_file_signer=True,
                    force=False,
                )

    def test_provider_staging_helper_is_create_only_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provider_directory = root / "provider"
            game_output = root / "game"
            provider_directory.mkdir()
            game_output.mkdir()
            source = provider_directory / "dade_provider.test"
            source.write_bytes(b"provider-binary")

            destination = stage_vice_provider.stage(provider_directory, game_output, force=False)
            self.assertEqual(destination, game_output / "modules" / source.name)
            self.assertEqual(destination.read_bytes(), b"provider-binary")

            with self.assertRaises(FileExistsError):
                stage_vice_provider.stage(provider_directory, game_output, force=False)

            source.write_bytes(b"replacement")
            replaced = stage_vice_provider.stage(provider_directory, game_output, force=True)
            self.assertEqual(replaced.read_bytes(), b"replacement")


if __name__ == "__main__":
    unittest.main()
