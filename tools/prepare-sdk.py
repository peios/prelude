#!/usr/bin/env python3
"""Prepare a target-matched static SDK from the recorded peios-sdk revision."""

import argparse
import hashlib
import json
import shutil
import subprocess
import tomllib
from pathlib import Path

SDK_REVISION = "d56e86fbc922b83873006752600f8de7bc12cb84"


def output(source: Path, command: list[str]) -> str:
    """Capture successful output without concealing diagnostics."""
    return subprocess.check_output(command, cwd=source, text=True).strip()


def built_output(source: Path, bazel: list[str], target: str, flags: list[str]) -> Path:
    """Build and locate exactly one output under the same target configuration."""
    subprocess.run([*bazel, "build", *flags, target], cwd=source, check=True)
    files = output(source, [*bazel, "cquery", *flags, target, "--output=files"]).splitlines()
    if len(files) != 1:
        raise ValueError(f"expected one output for {target}, got {files}")
    execution_root = Path(output(source, [*bazel, "info", "execution_root"]))
    return execution_root / files[0]


def prepare(args: argparse.Namespace) -> None:
    """Export matching headers, notices and an archive with exact provenance."""
    source = args.source.resolve()
    destination = args.destination.resolve()
    if destination.exists() or source == destination or source in destination.parents:
        raise ValueError("choose a new SDK destination outside the source checkout")
    if output(source, ["git", "rev-parse", "HEAD"]) != SDK_REVISION:
        raise ValueError(f"peios-sdk must be checked out at {SDK_REVISION}")
    if output(source, ["git", "status", "--porcelain"]):
        raise ValueError("peios-sdk source must be clean")
    bazel = [str(source / "bazel")]
    if args.output_base:
        bazel.append(f"--output_base={args.output_base.resolve()}")
    stage = args.notices_stage
    if stage is None:
        stage = built_output(source, bazel, "//packages:stage", [])
    # Copy notices before changing the build configuration, whose outputs can share paths.
    notices = stage / "licenses/libpeios"
    metadata = json.loads((stage / "build.json").read_text())
    license_expression = metadata["licences"]["libpeios"]
    destination.mkdir(parents=True)
    try:
        shutil.copytree(notices, destination / "licenses")
        archive = args.archive
        if archive is None:
            flags = ["--config=musl"] if args.target.endswith("musl") else []
            archive = built_output(source, bazel, "//libpeios:static", flags)
        shutil.copytree(source / "libpeios/include", destination / "include")
        shutil.copytree(source / "vendor/kernel/include/uapi/pkm", destination / "include/pkm")
        (destination / "lib").mkdir()
        library = destination / "lib/libpeios.a"
        shutil.copyfile(archive, library)
        (destination / "TARGET").write_text(args.target + "\n")
        version = tomllib.loads((source / "Cargo.toml").read_text())["workspace"]["package"][
            "version"
        ]
        record = {
            "target": args.target,
            "version": version,
            "source_commit": SDK_REVISION,
            "native": args.native,
            "license": license_expression,
            "library_sha256": hashlib.sha256(library.read_bytes()).hexdigest(),
        }
        (destination / "SDK.json").write_text(json.dumps(record, indent=4) + "\n")
    except BaseException:
        shutil.rmtree(destination)
        raise


def main() -> None:
    """Accept explicit source/output paths and optional native build products."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--target", choices=["x86_64-unknown-linux-gnu", "x86_64-unknown-linux-musl"], required=True
    )
    parser.add_argument("--output-base", type=Path)
    parser.add_argument(
        "--archive", type=Path, help="Explicit archive built from the recorded SDK revision"
    )
    parser.add_argument(
        "--notices-stage", type=Path, help="SDK package stage built from the recorded revision"
    )
    parser.add_argument(
        "--native",
        action="store_true",
        help="Record an explicitly supplied native-toolchain archive",
    )
    args = parser.parse_args()
    if args.native and (args.archive is None or args.notices_stage is None):
        parser.error("--native requires --archive and --notices-stage")
    prepare(args)


if __name__ == "__main__":
    main()
