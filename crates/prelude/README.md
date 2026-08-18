# prelude

Peios's initramfs PID 1.

The kernel unpacks the initramfs into a rootfs tmpfs and execs `/init`.
That's prelude. Its job is to get userspace from "the kernel just unpacked
me into RAM" to "the real root is mounted and the real PID 1 is running."

prelude is *not* `peinit`. `peinit` is the real-root PID 1: registry-driven
service supervision, jobs, operations, never exits. prelude is the prologue
that gets us there. Different lifecycles, two separate binaries.

## What it does (Goal One)

For Goal One the boot pipeline is a monolithic hardcoded sequence — no
hooks, no DAG, no configuration. Once `peinitramfs` and the real hook DAG
land we'll grow this into a hook walker.

1. Mount `/proc`, `/sys`, `/dev`.
2. Read `/proc/cmdline`, look for `init=…`.
3. Mount `/sysroot.squashfs` (baked into the initramfs) as squashfs+loop
   at `/sysroot`.
4. Move the `/proc`, `/sys`, `/dev` mounts from the rootfs into `/sysroot`.
5. Cleanup: recursively delete everything on the rootfs's device. Mount
   points (different `st_dev`) — `/sysroot`, the moved kernel vfs — are
   automatically skipped.
6. `chdir /sysroot` → `mount --move . /` → `chroot .` → `chdir /`.
7. Exec the real PID 1. Candidate order: cmdline `init=` first, then the Peios
   runtime-view chain `/bin/peinit2`, `/sbin/init`, `/bin/init`, `/bin/sh`.
   The base-topology hook creates these views before handoff.

On failure, `rd.shell` opens `/usr/bin/sh` from the initramfs; without that
debug flag prelude logs, syncs, and halts.

## Build

```
make
```

Produces a static-musl-PIE binary at
`target/x86_64-unknown-linux-musl/release/prelude`. No external crates;
syscalls go through `libc` FFI shims defined in `src/main.rs`.

The Makefile invokes the rustup-managed `cargo` directly rather than the
ambient one — on NixOS the default `cargo` comes from a nix-wrapper that
can't find the musl rustlib even when the target is installed. Plain
`cargo build --release` works fine outside Nix.

## Where this fits

Design context: `boot-design.md` in the parent `peios/` workspace.
prelude is M1 of the boot-stack endgoal-C plan. Goal One: get a kernel
→ prelude → squashfs → protoinit → shell pipeline running end-to-end in
QEMU.
