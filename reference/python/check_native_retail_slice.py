from __future__ import annotations

import argparse
import ctypes
import os
from pathlib import Path


ABI_VERSION = 1
OWNED = 0


class VerifyRequest(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("size", ctypes.c_size_t),
        ("asset_id", ctypes.c_char_p),
        ("platform", ctypes.c_char_p),
        ("project_root", ctypes.c_char_p),
    ]


class VerifyResult(ctypes.Structure):
    _fields_ = [
        ("abi_version", ctypes.c_uint32),
        ("size", ctypes.c_size_t),
        ("code", ctypes.c_uint32),
        ("detail", ctypes.c_char_p),
    ]


def provider_file(directory: Path) -> Path:
    matches = [path for path in directory.iterdir() if path.name.startswith("dade_provider.")]
    if len(matches) != 1:
        raise ValueError(f"expected one packaged DADE provider in {directory}, found {matches}")
    return matches[0]


def verify(home: Path, platform: str, provider: Path, asset_id: str) -> str:
    os.environ["DADE_HOME"] = str(home.resolve())
    library = ctypes.CDLL(str(provider.resolve()))
    entrypoint = library.vice_dade_verify
    entrypoint.argtypes = [
        ctypes.c_uint32,
        ctypes.POINTER(VerifyRequest),
        ctypes.POINTER(VerifyResult),
    ]
    entrypoint.restype = ctypes.c_bool

    asset = asset_id.encode("utf-8")
    platform_bytes = platform.encode("utf-8")
    project_root = str(home.resolve()).encode("utf-8")
    request = VerifyRequest(
        abi_version=ABI_VERSION,
        size=ctypes.sizeof(VerifyRequest),
        asset_id=asset,
        platform=platform_bytes,
        project_root=project_root,
    )
    result = VerifyResult()

    completed = entrypoint(ABI_VERSION, ctypes.byref(request), ctypes.byref(result))
    if not completed:
        raise RuntimeError("native DADE provider rejected the ABI request")
    if result.abi_version != ABI_VERSION:
        raise RuntimeError(f"provider returned ABI version {result.abi_version}")
    if result.size < ctypes.sizeof(VerifyResult):
        raise RuntimeError(f"provider returned undersized result {result.size}")

    detail = result.detail.decode("utf-8") if result.detail else ""
    if result.code != OWNED:
        raise RuntimeError(f"native retail fixture was denied with code {result.code}: {detail}")
    return detail


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the packaged native provider against a Stage J fixture.")
    parser.add_argument("dade_home", type=Path)
    parser.add_argument("platform", choices=["macos", "windows"])
    parser.add_argument("provider_directory", type=Path)
    parser.add_argument("asset_id")
    args = parser.parse_args()

    detail = verify(
        args.dade_home,
        args.platform,
        provider_file(args.provider_directory),
        args.asset_id,
    )
    print(f"owned: {detail}")


if __name__ == "__main__":
    main()
