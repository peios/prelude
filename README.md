# prelude

The Peios initramfs subsystem — the boot stage between the kernel
unpacking the initramfs and the real-root PID 1 taking over.

A Cargo workspace:

- **`crates/prelude`** — the initramfs PID 1. The kernel execs it as
  `/init`; it gets userspace from "just unpacked into RAM" to "real root
  mounted, real PID 1 running." See `crates/prelude/README.md`.
- **`crates/mkirf`** — the builder. Compiles a directory tree into the
  deterministic initramfs `cpio.gz` the kernel loads. See
  `crates/mkirf/DESIGN.md`.

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
