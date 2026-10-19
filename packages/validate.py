"""Validate static initramfs payloads without executing either boot program."""

import os
import re
import subprocess
from pathlib import Path

BINARIES = {"prelude": "usr/sbin/prelude", "seed-sd": "usr/bin/seed-sd"}


def require(condition: bool, message: str) -> None:
    """Fail a package gate even when Python assertions are disabled."""
    if not condition:
        raise ValueError(message)


def readelf(path: Path, option: str) -> str:
    """Inspect ELF metadata using stable binutils output."""
    return subprocess.check_output(
        ["readelf", option, str(path)], text=True, env=os.environ | {"LC_ALL": "C"}
    )


def validate_elf(stage: Path, name: str, relative: str) -> None:
    """Require a self-contained static PIE with matching split debug data."""
    elf = stage / relative
    require(elf.is_file() and os.access(elf, os.X_OK), f"missing executable: {elf}")
    header, program, dynamic = (readelf(elf, flag) for flag in ("-h", "-lW", "-dW"))
    require(bool(re.search(r"Type:\s+DYN\b", header)), f"{elf}: not a static PIE")
    require(
        "INTERP" not in program and "(NEEDED)" not in dynamic, f"{elf}: external runtime dependency"
    )
    require("GNU_RELRO" in program and "BIND_NOW" in dynamic, f"{elf}: missing full RELRO")
    stack = [line for line in program.splitlines() if "GNU_STACK" in line]
    require(len(stack) == 1 and bool(re.search(r"\sRW\s", stack[0])), f"{elf}: executable stack")
    require(bool(re.search(r"FLAGS_1.*\bPIE\b", dynamic)), f"{elf}: missing PIE flag")
    require(not re.search(r"\((RPATH|RUNPATH|TEXTREL)\)", dynamic), f"{elf}: unsafe dynamic tag")
    require(".debug_info" not in readelf(elf, "-SW"), f"{elf}: unsplit debug information")
    identities = re.findall(r"Build ID: ([0-9a-f]+)", readelf(elf, "-n"))
    require(len(identities) == 1, f"{elf}: missing or ambiguous build ID")
    identity = identities[0]
    debug = stage / f"debug/{name}/usr/lib/debug/.build-id/{identity[:2]}/{identity[2:]}.debug"
    require(debug.is_file(), f"{elf}: missing debug companion")
    require(".debug_info" in readelf(debug, "-SW"), f"{debug}: no debug information")
    require(identity in readelf(debug, "-n"), f"{debug}: build ID differs")
    # Some readelf versions print the binary CRC following the filename as raw
    # bytes. Match the ASCII build-ID filename without decoding that checksum.
    debuglink = subprocess.check_output(
        ["readelf", "--string-dump=.gnu_debuglink", str(elf)],
        env=os.environ | {"LC_ALL": "C"},
    )
    require(debug.name.encode("ascii") in debuglink, f"{elf}: wrong debug link")
    forbidden = str(Path.cwd().resolve()).encode()
    for artifact in (elf, debug):
        require(forbidden not in artifact.read_bytes(), f"{artifact}: build path leaked")


def validate(stage: Path, *, native: bool, sdk: Path) -> None:
    """Check the installed static contract; never start PID 1 or seed live files."""
    for name, relative in BINARIES.items():
        validate_elf(stage, name, relative)
    helper = stage / "usr/libexec/prelude/hook-log.sh"
    require(
        helper.is_file() and helper.stat().st_mode & 0o777 == 0o644, "invalid sourced logger mode"
    )
    for section, page in [(8, "prelude"), (8, "seed-sd"), (5, "prelude-hooks")]:
        require(
            (stage / f"usr/share/man/man{section}/{page}.{section}.gz").is_file(), "missing manual"
        )
    require(
        (sdk / "TARGET").read_text().strip() == "x86_64-unknown-linux-musl", "SDK target differs"
    )
    if native:
        compiler = subprocess.check_output([os.environ["RUSTC"], "--version"], text=True)
        require(compiler.startswith("rustc 1.98.1 "), "unexpected native compiler version")
    # Static musl does not enable shadow stack at startup. CET property notes
    # and RELR are not runtime guarantees or mandatory static-PIE properties.
