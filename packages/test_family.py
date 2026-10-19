#!/usr/bin/env python3
"""Check the installed boot contract across all four emitted package manifests."""

import hashlib
import json
import sys
import tomllib
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> None:
    store = Path(sys.argv[1])
    index = json.loads((store / "index.json").read_text())
    records = {entry["name"]: entry for entry in index["packages"]}
    require(
        set(records)
        == {
            "dev.peios.prelude" + suffix for suffix in ("", "-debuginfo", "-debugsource", "-source")
        },
        "incomplete package family",
    )
    manifests = {}
    for name, record in records.items():
        raw = (store / record["manifest"]).read_bytes()
        require(
            "sha256:" + hashlib.sha256(raw).hexdigest() == record["manifest_hash"],
            "manifest identity differs",
        )
        doc = tomllib.loads(raw.decode())
        require(doc["name"] == name and doc["version"] == "0.0.7-1", "unexpected package identity")
        manifests[name] = doc["files"]
    runtime = records["dev.peios.prelude"]
    metadata = runtime["package_metadata"]
    require(metadata["package"]["default_root"] == "initramfs", "runtime must belong to initramfs")
    require(
        metadata["claims"]["provides"]["init"]["bin"]
        == {"path": "/init", "target": "/usr/sbin/prelude"},
        "init claim differs",
    )
    require(metadata["dependencies"] == {"sh": ">= 1"}, "shell dependency missing")
    files = manifests["dev.peios.prelude"]
    require(
        {path for path, info in files.items() if info.get("exec")}
        == {"usr/sbin/prelude", "usr/bin/seed-sd"},
        "installed executable contract differs",
    )
    require("usr/libexec/prelude/hook-log.sh" in files, "missing hook logger")
    for section, name in [(8, "prelude"), (8, "seed-sd"), (5, "prelude-hooks")]:
        require(
            f"usr/share/man/man{section}/{name}.{section}.gz" in files, "missing installed manual"
        )
    require(
        not runtime["build"]["release_ready"] and not runtime["build"]["signed"],
        "unqualified packages cannot claim release readiness",
    )
    sources = manifests["dev.peios.prelude-source"]
    for path in [
        "MODULE.bazel",
        "Cargo.lock",
        "tools/prepare-sdk.py",
        ".cargo/config.toml",
        "crates/seed-sd/tests/fixtures/bootstrap.sd",
    ]:
        require(f"usr/src/prelude/{path}" in sources, f"missing reproducibility input: {path}")
    require(
        not any("/target/" in path or "/.git/" in path or "/dist/" in path for path in sources),
        "generated output leaked into source package",
    )
    print("verified runtime, debug, debug-source and source package contracts")


if __name__ == "__main__":
    main()
