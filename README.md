# Prelude

Prelude is Peios's initramfs process 1. It mounts the kernel virtual
filesystems, runs boot hooks, and hands control to the init on the mounted
root. The repository also provides `seed-sd`, which initializes security
descriptors, and a shell logging helper for boot hooks.

Both executables ship in one runtime package because they participate in the
same early-boot lifecycle. The runtime binaries are static musl executables.
The initramfs builder, `mkirf`, belongs to peiosutils; the real-root service
supervisor, peinit, has its own repository.

## Build and test

Pekit builds and tests both programs. Start with
[Building Prelude](docs/building.md). Cargo remains available for Rust
editor integration and development checks.

Do not run the `prelude` executable on a development host. It changes mounts
and roots, deletes the old initramfs, and halts on failure. Use the unit tests
or a disposable boot environment. `seed-sd` changes access control and must
only be run on deliberately selected targets.

## Documentation

- [Prelude architecture](docs/architecture.md) describes boot sequencing and
  component boundaries.
- [Learn](docs/learn/) contains the Peios initramfs-boot topic, merged into
  Peios Learn.
- [Manual pages](docs/man/) specify command-line and hook contracts.
- [Coding style](docs/CODING_STYLE.md) records PSC adoption and exceptions.
- [Archived recipes](docs/archive/pekit/) preserve the Pekit build inputs.

The repository is licensed under MIT. Dependency notices accompany the
runtime and source packages; see [LICENSE](LICENSE) and `third-party/`.
