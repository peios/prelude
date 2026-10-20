---
title: Debugging Initramfs Boot
type: how-to
description: Pause Prelude at a hook or inspect a failed boot from its
  recovery shell.
---

Use Prelude's recovery shell to inspect a boot that fails before the
real-root init starts. A breakpoint lets you inspect or repair the temporary
environment and then continue the same boot.

## Before you start

- Use a disposable test image or a machine you can recover independently.
- Have access to its boot parameters and boot console.
- Include `/usr/bin/sh` and the inspection tools you need in the image.
- Treat the recovery shell as privileged access to the boot environment.

## Stop before the hooks

1. Add `rd.break` to the image's kernel command line and boot it.
2. Wait for Prelude's breakpoint message and shell.
3. Inspect `/system/prelude` and the hook scripts named by its sequence.
   This breakpoint occurs before Prelude reads that sequence, so an edit
   made here takes effect when you resume.
4. Exit the shell to continue boot.

To stop before one hook instead, use `rd.break=` followed by its filename
or complete path. For example, `rd.break=mount-root` matches a hook whose
final path component is `mount-root`. Use the name present in your image.
The full syntax is in `prelude(8)`.

## Inspect a failure

1. Add `rd.shell` to the kernel command line and boot the image.
2. Read the failure message before using the shell. A hook error identifies
   the failed hook; an unsatisfied capability identifies pending work.
3. Inspect the files and mounts that remain at the point of failure. Before
   handoff, the intended real root is `/mnt/rootfs`. After a root switch,
   paths resolve inside the new root.
4. Exit when finished. A failure shell continues to the halt path, not back
   to the failed boot operation.

## Check the result

A successful breakpoint recovery reaches the real-root init. A failure
shell ends at the halt path after you exit. If no shell starts, look for the
reported exec error and check that `/usr/bin/sh` exists in the filesystem
visible at that stage.

Do not start the Prelude executable from an ordinary terminal to reproduce
a boot problem. Its operations include mount changes and removal of files
from the old root.
