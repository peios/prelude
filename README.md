# prelude

Peios's initramfs PID 1.

prelude is the first userspace process the kernel executes after unpacking
the initramfs. Its job:

1. Mount the core virtual filesystems (`/proc`, `/sys`, `/dev`).
2. Walk an ordered list of hooks baked into the initramfs by `peinitramfs`
   (the builder, separate project). Each hook does one concrete thing —
   load modules, unlock crypto, activate volumes, mount the real root.
3. `switch_root` into the real root filesystem and `exec` the real PID 1.

prelude is *not* `peinit`. `peinit` is the real-root PID 1: registry-driven
service supervision, jobs, operations, never exits. prelude is the prologue
that gets userspace from "kernel just unpacked initramfs" to "real root is
mounted, run the real init." Different lifecycles, different concerns, two
separate binaries.

## Status

Bootstrap. Implements early mounts and the hook walker. No `switch_root`
yet — that lands when the first real-boot pathway is wired up (M1 step 5
in the boot-stack design doc). Today prelude drops to `/bin/sh` after the
hook list completes, which makes it a drop-in replacement for `protoinit`
in kobicha-style permanent-initramfs setups.

## Hook list format

`/etc/prelude/hooks` is a plain-text file the initramfs builder writes.
One hook per line:

```
<name> <absolute-path-to-executable>
```

Lines starting with `#` are comments. Blank lines are ignored. Order is
the order of execution — the builder topologically sorts the hook DAG at
build time so prelude can be a dumb sequential consumer.

If the file is missing or empty, prelude drops to a shell. This is the
intended behaviour for kobicha-style boots that have nothing to do before
the user can start poking around.

If a hook exits non-zero, prelude logs the failure to stderr and drops to
a shell rather than aborting PID 1. The system stays interactive so the
user can debug.

## Build

```
make
```

Produces a static-musl-PIE binary at
`target/x86_64-unknown-linux-musl/release/prelude`. No external crates;
all syscalls go through `libc` FFI shims defined in `src/main.rs`.

The Makefile invokes the rustup-managed `cargo` directly rather than the
ambient one — on NixOS the default `cargo` comes from a nix-wrapper that
can't find the musl rustlib even when the target is installed. Plain
`cargo build --release` works fine outside Nix.

## Where this fits

Design context: `boot-design.md` in the parent `peios/` workspace.
prelude is M1 step 2 of the boot-stack endgoal-C plan.
