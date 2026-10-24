from __future__ import annotations

import argparse
import shutil
from pathlib import Path


def find_provider(directory: Path) -> Path:
    if not directory.is_dir():
        raise ValueError(f"provider directory does not exist: {directory}")
    matches = [path for path in directory.iterdir() if path.is_file() and path.name.startswith("dade_provider.")]
    if len(matches) != 1:
        raise ValueError(f"expected one packaged DADE provider in {directory}, found {matches}")
    return matches[0]


def stage(provider_directory: Path, game_output: Path, *, force: bool) -> Path:
    if not game_output.is_dir():
        raise ValueError(f"VICE game output directory does not exist: {game_output}")
    source = find_provider(provider_directory)
    modules = game_output / "modules"
    modules.mkdir(parents=True, exist_ok=True)
    destination = modules / source.name
    if destination.exists() and not force:
        raise FileExistsError(f"{destination} already exists; pass --force to replace it")
    shutil.copy2(source, destination)
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Copy a packaged native DADE provider into a staged VICE game output."
    )
    parser.add_argument("provider_directory", type=Path)
    parser.add_argument("game_output", type=Path)
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    try:
        destination = stage(args.provider_directory, args.game_output, force=args.force)
    except (FileExistsError, ValueError) as error:
        raise SystemExit(str(error)) from error
    print(destination)


if __name__ == "__main__":
    main()
