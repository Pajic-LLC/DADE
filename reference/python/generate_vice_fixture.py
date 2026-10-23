from __future__ import annotations

import shutil
import sys
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from dade_app import can_use
from dade_identity import device_id, owner_id
from test_dade_app import (
    ASSET_ID,
    CHALLENGE,
    CONTROLLER,
    DEVICE,
    ISSUER_ROOT,
    OTHER_ROOT,
    OWNER_ANCHOR,
    artifacts,
    controller_credential,
    deed,
    device_authorization,
    issuer_id,
    issuer_snapshot,
    owner_snapshot,
    pem,
    sign_payload,
    signing_credential,
)


OTHER_ASSET_ID = "com.pajic.other"


def write_hex(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.hex() + "\n", encoding="utf-8")


def write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


def private_pem(key) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def write_home(
    root: Path,
    *,
    asset_directory: str = ASSET_ID,
    deed_bytes: bytes | None = None,
    trusted_root=ISSUER_ROOT,
    owner_trust: bytes | None = None,
    issuer_trust: bytes | None = None,
    remembered_owner_sequence: int | None = None,
    remembered_issuer_sequence: int | None = None,
    device_key=DEVICE,
) -> None:
    issuer = issuer_id(ISSUER_ROOT.public_key())
    owner = owner_id(OWNER_ANCHOR.public_key())
    device = device_id(DEVICE.public_key())

    asset_root = root / "assets" / asset_directory
    asset_root.mkdir(parents=True, exist_ok=True)
    write_text(asset_root / "issuer-id.hex", issuer.hex() + "\n")
    if deed_bytes is not None:
        write_hex(asset_root / "deed.hex", deed_bytes)
    write_hex(asset_root / "signing-credential.hex", signing_credential())

    issuer_root = root / "trust" / "issuers" / issuer.hex()
    issuer_root.mkdir(parents=True, exist_ok=True)
    (issuer_root / "root.pem").write_bytes(pem(trusted_root))
    if issuer_trust is not None:
        write_hex(issuer_root / "snapshot.hex", issuer_trust)

    owner_root = root / "owners" / owner.hex()
    owner_root.mkdir(parents=True, exist_ok=True)
    (owner_root / "anchor.pem").write_bytes(pem(OWNER_ANCHOR))
    write_hex(owner_root / "controller.hex", controller_credential())
    write_hex(owner_root / "device-authorization.hex", device_authorization())
    if owner_trust is not None:
        write_hex(owner_root / "snapshot.hex", owner_trust)

    device_root = root / "devices"
    device_root.mkdir(parents=True, exist_ok=True)
    (device_root / f"{device.hex()}.pem").write_bytes(private_pem(device_key))

    if remembered_owner_sequence is not None:
        write_text(
            root / "state" / "owners" / f"{owner.hex()}.seq",
            f"{remembered_owner_sequence}\n",
        )
    if remembered_issuer_sequence is not None:
        write_text(
            root / "state" / "issuers" / f"{issuer.hex()}.seq",
            f"{remembered_issuer_sequence}\n",
        )


def python_expectations() -> list[tuple[str, str, str, str]]:
    base = artifacts()
    valid_deed = deed(platforms=["windows"])
    tampered = bytearray(valid_deed)
    tampered[-1] ^= 1

    wrong_device_proof = sign_payload(
        {
            1: 1,
            2: CHALLENGE,
            3: ASSET_ID,
            4: 1,
            5: owner_id(OWNER_ANCHOR.public_key()),
            6: device_id(DEVICE.public_key()),
        },
        OTHER_ROOT,
    )

    cases = [
        ("owned", ASSET_ID, "windows", base),
        ("owned-abi", ASSET_ID, "windows", base),
        ("missing-deed", ASSET_ID, "windows", replace(base, deed=None)),
        ("wrong-asset", OTHER_ASSET_ID, "windows", base),
        ("bad-deed", ASSET_ID, "windows", replace(base, deed=bytes(tampered))),
        (
            "wrong-root",
            ASSET_ID,
            "windows",
            replace(base, issuer_root_public_key=pem(OTHER_ROOT)),
        ),
        (
            "revoked-controller",
            ASSET_ID,
            "windows",
            replace(base, owner_trust_snapshot=owner_snapshot(4, revoke_controller=True)),
        ),
        (
            "compromised-issuer",
            ASSET_ID,
            "windows",
            replace(base, issuer_trust_snapshot=issuer_snapshot(7, reject_from=1500)),
        ),
        (
            "owner-rollback",
            ASSET_ID,
            "windows",
            replace(
                base,
                owner_trust_snapshot=owner_snapshot(4),
                remembered_owner_trust_sequence=5,
            ),
        ),
        (
            "issuer-rollback",
            ASSET_ID,
            "windows",
            replace(
                base,
                issuer_trust_snapshot=issuer_snapshot(7),
                remembered_issuer_trust_sequence=8,
            ),
        ),
        ("platform-denied", ASSET_ID, "macos", base),
        (
            "bad-device-key",
            ASSET_ID,
            "windows",
            replace(base, device_proof=wrong_device_proof),
        ),
    ]

    output = []
    for name, asset, platform, local_artifacts in cases:
        result = can_use(asset, local_artifacts, CHALLENGE, platform=platform)
        output.append((name, asset, platform, result.code.value))
    return output


def generate(output: Path) -> None:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    valid = deed(platforms=["windows"])
    tampered = bytearray(valid)
    tampered[-1] ^= 1

    write_home(output / "owned", deed_bytes=valid, owner_trust=owner_snapshot(4), issuer_trust=issuer_snapshot(7))
    write_home(output / "owned-abi", deed_bytes=valid, owner_trust=owner_snapshot(4), issuer_trust=issuer_snapshot(7))
    write_home(output / "missing-deed", deed_bytes=None)
    write_home(output / "wrong-asset", asset_directory=OTHER_ASSET_ID, deed_bytes=valid)
    write_home(output / "bad-deed", deed_bytes=bytes(tampered))
    write_home(output / "wrong-root", deed_bytes=valid, trusted_root=OTHER_ROOT)
    write_home(
        output / "revoked-controller",
        deed_bytes=valid,
        owner_trust=owner_snapshot(4, revoke_controller=True),
    )
    write_home(
        output / "compromised-issuer",
        deed_bytes=valid,
        issuer_trust=issuer_snapshot(7, reject_from=1500),
    )
    write_home(
        output / "owner-rollback",
        deed_bytes=valid,
        owner_trust=owner_snapshot(4),
        remembered_owner_sequence=5,
    )
    write_home(
        output / "issuer-rollback",
        deed_bytes=valid,
        issuer_trust=issuer_snapshot(7),
        remembered_issuer_sequence=8,
    )
    write_home(output / "platform-denied", deed_bytes=valid)
    write_home(output / "bad-device-key", deed_bytes=valid, device_key=OTHER_ROOT)

    expectations = python_expectations()
    lines = ["scenario\tasset\tplatform\tcode"]
    lines.extend("\t".join(row) for row in expectations)
    write_text(output / "expectations.tsv", "\n".join(lines) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_vice_fixture.py <output-directory>")
    generate(Path(sys.argv[1]))
