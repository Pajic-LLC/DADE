from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dade_identity import controller_id, device_id, key_id, owner_id, public_key_to_cose
from dade_issuer import issuer_id


DEFAULT_ASSET_ID = "com.pajic.dade.stagej"
ISSUED_AT = 2_000
VALID_FROM = 1_000
VALID_UNTIL = 4_000
TRUST_UPDATED_AT = 2_500
TERMS_HASH = hashlib.sha256(b"DADE Stage J retail fixture terms").digest()


def public_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def private_pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def write_hex(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.hex() + "\n", encoding="utf-8")


def write_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)


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


def random_id() -> bytes:
    import os

    return os.urandom(16)


def signing_credential(
    issuer_root: ec.EllipticCurvePrivateKey,
    signing_key: ec.EllipticCurvePrivateKey,
) -> bytes:
    return sign_payload(
        {
            1: 1,
            2: random_id(),
            3: issuer_id(issuer_root.public_key()),
            4: key_id(signing_key.public_key()),
            5: public_key_to_cose(signing_key.public_key()),
            6: VALID_FROM,
            7: VALID_UNTIL,
        },
        issuer_root,
    )


def digital_deed(
    asset_id: str,
    platforms: list[str],
    issuer_root: ec.EllipticCurvePrivateKey,
    signing_key: ec.EllipticCurvePrivateKey,
    owner_anchor: ec.EllipticCurvePrivateKey,
) -> bytes:
    return sign_payload(
        {
            1: 1,
            2: random_id(),
            3: asset_id,
            4: issuer_id(issuer_root.public_key()),
            5: owner_id(owner_anchor.public_key()),
            6: {
                1: 0,
                2: 0,
                3: True,
                4: True,
                5: True,
                6: True,
                7: platforms,
            },
            7: ISSUED_AT,
            8: TERMS_HASH,
        },
        signing_key,
    )


def controller_credential(
    owner_anchor: ec.EllipticCurvePrivateKey,
    controller: ec.EllipticCurvePrivateKey,
) -> bytes:
    return sign_payload(
        {
            1: 1,
            2: random_id(),
            3: owner_id(owner_anchor.public_key()),
            4: controller_id(controller.public_key()),
            5: public_key_to_cose(controller.public_key()),
            6: [1, 2],
            7: ISSUED_AT,
        },
        owner_anchor,
    )


def device_authorization(
    owner_anchor: ec.EllipticCurvePrivateKey,
    controller: ec.EllipticCurvePrivateKey,
    device_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    return sign_payload(
        {
            1: 1,
            2: random_id(),
            3: owner_id(owner_anchor.public_key()),
            4: controller_id(controller.public_key()),
            5: device_id(device_public_key),
            6: public_key_to_cose(device_public_key),
            7: [1],
            8: ISSUED_AT,
        },
        controller,
    )


def owner_snapshot(
    owner_anchor: ec.EllipticCurvePrivateKey,
    controller: ec.EllipticCurvePrivateKey,
    sequence: int,
    *,
    revoke_controller: bool,
) -> bytes:
    revoked = []
    if revoke_controller:
        revoked.append({1: controller_id(controller.public_key()), 2: TRUST_UPDATED_AT})
    return sign_payload(
        {
            1: 1,
            2: owner_id(owner_anchor.public_key()),
            3: sequence,
            4: TRUST_UPDATED_AT,
            5: revoked,
        },
        owner_anchor,
    )


def issuer_snapshot(
    issuer_root: ec.EllipticCurvePrivateKey,
    signing_key: ec.EllipticCurvePrivateKey,
    sequence: int,
    *,
    compromise_cutoff: int | None,
) -> bytes:
    rejected = []
    if compromise_cutoff is not None:
        rejected.append({1: key_id(signing_key.public_key()), 2: compromise_cutoff})
    return sign_payload(
        {
            1: 1,
            2: issuer_id(issuer_root.public_key()),
            3: sequence,
            4: TRUST_UPDATED_AT,
            5: rejected,
        },
        issuer_root,
    )


def parse_device_public_key(value: str) -> ec.EllipticCurvePublicKey:
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("device public key is not valid hex") from error
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    except ValueError as error:
        raise ValueError("device public key is not an uncompressed P-256 SEC1 point") from error


def prepare_output(output: Path, force: bool) -> None:
    if output.exists():
        if not force:
            raise FileExistsError(f"{output} already exists; pass --force to replace it")
        shutil.rmtree(output)
    output.mkdir(parents=True)


def generate(
    output: Path,
    *,
    asset_id: str,
    platforms: list[str],
    device_public_key: ec.EllipticCurvePublicKey | None,
    development_file_signer: bool,
    force: bool,
) -> dict[str, str | list[str] | bool]:
    if not asset_id or len(asset_id.encode("utf-8")) > 255:
        raise ValueError("asset ID is empty or too long")
    if not platforms:
        raise ValueError("at least one platform is required")
    if development_file_signer == (device_public_key is not None):
        raise ValueError(
            "choose exactly one device mode: hardware public key or development file signer"
        )

    prepare_output(output, force)
    install = output / "install" / "dade-home"
    secrets = output / "secrets"
    updates = output / "trust-updates"

    issuer_root = ec.generate_private_key(ec.SECP256R1())
    signing_key = ec.generate_private_key(ec.SECP256R1())
    owner_anchor = ec.generate_private_key(ec.SECP256R1())
    controller = ec.generate_private_key(ec.SECP256R1())

    device_private_key: ec.EllipticCurvePrivateKey | None = None
    if development_file_signer:
        device_private_key = ec.generate_private_key(ec.SECP256R1())
        device_public_key = device_private_key.public_key()
    assert device_public_key is not None

    issuer = issuer_id(issuer_root.public_key())
    owner = owner_id(owner_anchor.public_key())
    device = device_id(device_public_key)

    credential = signing_credential(issuer_root, signing_key)
    deed = digital_deed(asset_id, platforms, issuer_root, signing_key, owner_anchor)
    controller_cred = controller_credential(owner_anchor, controller)
    device_auth = device_authorization(owner_anchor, controller, device_public_key)

    asset_root = install / "assets" / asset_id
    write_hex(asset_root / "issuer-id.hex", issuer)
    write_hex(asset_root / "deed.hex", deed)
    write_hex(asset_root / "signing-credential.hex", credential)

    issuer_root_dir = install / "trust" / "issuers" / issuer.hex()
    write_bytes(issuer_root_dir / "root.pem", public_pem(issuer_root))

    owner_root_dir = install / "owners" / owner.hex()
    write_bytes(owner_root_dir / "anchor.pem", public_pem(owner_anchor))
    write_hex(owner_root_dir / "controller.hex", controller_cred)
    write_hex(owner_root_dir / "device-authorization.hex", device_auth)

    if device_private_key is not None:
        write_bytes(install / "devices" / f"{device.hex()}.pem", private_pem(device_private_key))

    write_bytes(secrets / "issuer-root-private.pem", private_pem(issuer_root))
    write_bytes(secrets / "issuer-signing-private.pem", private_pem(signing_key))
    write_bytes(secrets / "owner-anchor-private.pem", private_pem(owner_anchor))
    write_bytes(secrets / "controller-private.pem", private_pem(controller))
    if device_private_key is not None:
        write_bytes(secrets / "development-device-private.pem", private_pem(device_private_key))

    write_hex(
        updates / "owner-sequence-1.hex",
        owner_snapshot(owner_anchor, controller, 1, revoke_controller=False),
    )
    write_hex(
        updates / "owner-controller-revoked-sequence-2.hex",
        owner_snapshot(owner_anchor, controller, 2, revoke_controller=True),
    )
    write_hex(
        updates / "issuer-sequence-1.hex",
        issuer_snapshot(issuer_root, signing_key, 1, compromise_cutoff=None),
    )
    write_hex(
        updates / "issuer-signing-key-compromised-sequence-2.hex",
        issuer_snapshot(issuer_root, signing_key, 2, compromise_cutoff=ISSUED_AT),
    )

    metadata: dict[str, str | list[str] | bool] = {
        "asset_id": asset_id,
        "platforms": platforms,
        "issuer_id": issuer.hex(),
        "owner_id": owner.hex(),
        "controller_id": controller_id(controller.public_key()).hex(),
        "device_id": device.hex(),
        "device_mode": "development-file-signer" if development_file_signer else "hardware",
        "install_root": str(Path("install") / "dade-home"),
        "secrets_root": "secrets",
        "trust_updates_root": "trust-updates",
        "private_keys_in_install_root": development_file_signer,
    }
    (output / "fixture.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Create a Stage J DADE ownership fixture with secrets separated from installed state."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument("--asset-id", default=DEFAULT_ASSET_ID)
    parser.add_argument(
        "--platform",
        action="append",
        choices=["macos", "windows"],
        dest="platforms",
        help="Allowed platform. Repeat for more than one platform.",
    )
    device = parser.add_mutually_exclusive_group(required=True)
    device.add_argument(
        "--device-public-key-sec1",
        help="Uncompressed P-256 SEC1 public key from hardware enrollment, as hex.",
    )
    device.add_argument(
        "--development-file-signer",
        action="store_true",
        help="Generate and install an exportable development-only device key.",
    )
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        public_key = (
            parse_device_public_key(args.device_public_key_sec1)
            if args.device_public_key_sec1
            else None
        )
        metadata = generate(
            args.output,
            asset_id=args.asset_id,
            platforms=args.platforms or ["macos", "windows"],
            device_public_key=public_key,
            development_file_signer=args.development_file_signer,
            force=args.force,
        )
    except (FileExistsError, ValueError) as error:
        raise SystemExit(str(error)) from error

    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
