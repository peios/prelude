# prelude

The Peios initramfs subsystem — the boot stage between the kernel
unpacking the initramfs and the real-root PID 1 taking over.

A Cargo workspace:

- **`crates/prelude`** — the initramfs PID 1. The kernel execs it as
  `/init`; it gets userspace from "just unpacked into RAM" to "real root
  mounted, real PID 1 running." See `crates/prelude/README.md`.
**mkirf — the builder that compiles a directory tree into the
deterministic initramfs `cpio.gz` the kernel loads — does not live here.**
It ships as a `peiosutils` applet (`/usr/bin/mkirf` is a symlink into the
multi-call binary), and its source is `peiosutils/src/uu/mkirf/`. A copy
used to sit in this workspace and was removed once it became clear that
the packaged one was the peiosutils applet, and that two copies of the
hook-DAG resolver would drift.

That split matters when changing the `hooks.seq` format: mkirf writes it
and prelude reads it, but they ship in two independently versioned
packages, so an image can pair a new writer with an old reader.

## Build

```
make
```

Builds the whole workspace for the `x86_64-unknown-linux-musl` target
(static binaries). See the Makefile header for the NixOS toolchain note.

## Design context

`boot-design.md` in the parent `peios/` working tree sketches the
boot-stack endgoal. Parts of it predate the current code — the crate
docs describe what is actually true today.
