# Prelude Architecture

Prelude 0.0.7 is the initramfs process 1. It mounts the kernel virtual
filesystems, schedules boot hooks, checks the resulting root filesystem,
and replaces itself with the real-root init. It does not supervise services.
The executable uses Rust's standard library and direct libc calls; it does
not link the Peios SDK. The separate seed-sd helper owns descriptor seeding.

## Boot sequence

1. Make the mount tree private, then mount `/proc`, `/sys`, and `/dev`.
2. Run `/usr/bin/seed-sd -r /dev`. A failure is a warning; boot continues.
3. Read quiet, terminal, recovery, and breakpoint settings from the kernel
   command line. Select the last nonempty `init=` value.
4. Create `/mnt/rootfs` and run the selected hook sequence. A hook supplies
   the real root; Prelude does not choose a storage driver or filesystem.
5. Verify that `/mnt/rootfs` has a different device identifier from `/`.
6. Move `/proc`, `/sys`, and `/dev` into directories in the mounted root.
7. Remove old initramfs contents on the original device. Other devices are
   left intact. Cleanup failure produces a warning and boot continues.
8. Change directory and root to `/mnt/rootfs`, then change directory to `/`.
9. Try the requested init, followed by `/bin/peinit2`, `/sbin/init`,
   `/bin/init`, and `/bin/sh`. A successful exec retains process number 1.

The handoff uses chroot; it does not use pivot_root. The initramfs root mount
remains as mount-namespace bookkeeping. Hooks and the mounted root must
provide the paths needed by the selected init. The fallback paths are an
existing compatibility contract, not a search through PATH.

## Hook scheduling

mkirf, maintained in peiosutils, writes the hook sequence. Prelude chooses
the highest supported filename version and checks its first-line marker.
Version 1 carries paths; version 2 also carries capability declarations.
The legacy `/hooks.seq` path is a last resort.

The scheduler makes repeated passes in sequence order. A satisfied or
declined hook completes; a deferred hook stays pending. A capability is
settled after every provider and contributor completes. A required
capability also needs at least one successful provider when providers exist.
A capability supplied only by contributors succeeds when all finish,
including contributors that decline. An optional `after` edge waits only
for settlement and permits a capability with no supplier.

A pass with pending work and no completion fails with a hook-by-hook
explanation. Deferred hooks are retried only after progress. This is not a
clock-based retry mechanism. Hooks inherit console descriptors directly;
Prelude does not capture or pump their output.

## Ownership and process boundaries

Boot runs on one thread. Child processes execute one hook or recovery shell;
Prelude waits before proceeding. A hook stopped by a job-control signal is
killed and reaped. A signaled hook is a failure, not a declined capability.
Mount and root changes belong to process 1 and must not be exercised by
ordinary host unit tests.

Console rendering lives in `crates/prelude/src/console.rs`. Its tag layout
matches the shared boot-console convention. The sourced shell helper has its
own implementation so hook output does not depend on another executable.

## Security descriptor boundary

seed-sd sets owner, group, and DACL. Its bootstrap default names SYSTEM as
owner and group and contains exactly three allow entries:

| Principal | Access | Inheritance |
| --- | --- | --- |
| SYSTEM | GenericAll | Objects and containers |
| Administrators | GenericAll | Objects and containers |
| CREATOR OWNER | GenericAll | Objects and containers, inherit only |

The default grants no access to Everyone. This matters for `/dev`: a broad
inherited grant would also reach newly created raw disk nodes. Per-device
exceptions and the real-root runtime policy belong to their callers.

The recursive walker sets each descriptor before reading the node. It stamps
symlinks themselves and does not descend through them. Failures accumulate;
there is no rollback of descriptors already written.

## Qualification boundaries

Host tests cover parsing, scheduling, status decoding, descriptor construction,
and console formatting. They do not establish boot, KACS, mount, cleanup,
or handoff correctness. Those checks require a disposable boot environment.
Static linking and ELF inspection establish executable dependencies; they do
not establish that a target kernel enables a hardening feature.
