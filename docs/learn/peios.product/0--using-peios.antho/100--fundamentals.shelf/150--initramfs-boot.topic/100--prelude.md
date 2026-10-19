---
title: Prelude
type: concept
description: How Prelude prepares the temporary boot environment and hands
  control to the init on the real root filesystem.
---

Prelude starts the userspace part of Peios boot. It runs inside the
initramfs, a small filesystem unpacked into memory, until boot hooks have
made the real root filesystem available. It then replaces itself with the
init that manages the running system.

The two programs keep the same process number, 1, but have different jobs.
Prelude prepares one handoff. The real-root init manages services after it.
Storage discovery, unlocking, and root mounting belong to hooks supplied by
the image's packages.

## From temporary root to real root

Prelude mounts the kernel's process, system, and device filesystems. It
seeds access control on existing device nodes, then reads the sequence of
hooks written by `mkirf`. The sequence tells it which hooks can run and
which capabilities each hook needs.

A hook mounts the real root at `/mnt/rootfs`. Prelude checks that this is a
different filesystem from the temporary root, moves the kernel filesystems
into it, removes the old temporary files where possible, and changes its
root directory. A successful exec transfers control to the selected init.
The complete parameter and path reference is `prelude(8)`.

## Why hook outcomes matter

A hook can finish its work, decline because it does not apply to this
machine, or defer because an input is not ready. Deferral is safe only when
the hook has made no changes. Prelude retries deferred work after another
hook makes progress; it does not retry a failed hook that might have left
partial changes.

Capabilities let a hook depend on a result instead of another hook's name.
For example, several storage hooks can contribute toward preparing storage.
A later hook waits for their contributions before using it. The runtime
format and precise outcome rules are described in `prelude-hooks(5)`.

Hooks can source `/usr/libexec/prelude/hook-log.sh` for consistent status
messages. The helper prints message text literally, so a backslash in a
filename keeps its meaning when color is enabled.

## Access control during boot

The initial device policy grants full access to SYSTEM and Administrators.
An inherit-only CREATOR OWNER entry gives a creator control over the
objects it creates. The policy does not grant Everyone access: a broad
inherited grant could expose raw disks as well as ordinary device nodes.

A failure to seed device descriptors produces a warning and boot continues.
A hook failure or missing real root stops the handoff. Those outcomes need
different responses; a completed boot does not prove every device received
its intended descriptor.
