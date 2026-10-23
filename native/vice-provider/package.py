from __future__ import annotations

import shutil
import sys
from pathlib import Path


def main() -> int:
    crate = Path(__file__).resolve().parent
    output = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else crate / "dist"
    release = crate / "target" / "release"

    if sys.platform == "win32":
        source = release / "dade_provider.dll"
        name = "dade_provider.dll"
    elif sys.platform == "darwin":
        source = release / "libdade_provider.dylib"
        name = "dade_provider.dylib"
    else:
        source = release / "libdade_provider.so"
        name = "dade_provider.so"

    if not source.is_file():
        raise SystemExit(f"provider build not found: {source}")

    output.mkdir(parents=True, exist_ok=True)
    destination = output / name
    shutil.copy2(source, destination)
    print(destination)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
