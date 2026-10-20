---
title: Writing Boot Hooks
type: how-to
description: Prepare the real root through explicit hook capabilities, outcomes, and console reporting.
---

A boot hook performs a deployment-specific part of early boot, such as
unlocking storage or mounting the real root at `/mnt/rootfs`. Prelude runs
the generated hook sequence before handing control to the real init process.
Put service startup and ongoing supervision in Peinit instead.

## Before you start

- Prepare an initramfs source tree and a disposable boot environment.
- Include each hook's interpreter, tools, and required drivers in that tree.
- Read `mkirf(1)` for image construction and hook metadata syntax.
- Arrange the access policy required by the storage operations you perform.

Hooks run under the bootstrap SYSTEM token. That authority does not remove
kernel access checks or replace the security descriptors needed during boot.
See [Prelude](~peios/using-peios/initramfs-boot/prelude) for the stage's
responsibilities and handoff checks.

## Choose a location and declare dependencies

1. Put a packaged hook under `usr/libexec/prelude/hooks.d/` in the image tree.
   Put an operator-owned hook under `lcl/libexec/prelude/hooks.d/` instead.
2. Give it a distinct filename, an available interpreter in its shebang,
   and executable permissions. An operator hook with the same filename
   replaces the packaged hook at image construction.
3. Declare its capabilities in a comment block:

   ```sh
   #!/usr/bin/sh
   # /// hook
   # contributes = ["rootfs-ready"]
   # ///
   ```

This example declares part of the work needed for the real root. It is not a
complete hook: append the required checks and operation before including it
in an image. File extensions have no special meaning, and numeric prefixes
are only filename tie-breakers, not a dependency mechanism.

## Express what the hook needs and supplies

The metadata distinguishes alternatives from work that must all complete:

| Declaration | Meaning |
|---|---|
| `provides` | Any successful provider can satisfy the capability |
| `contributes` | All contributors must complete their part |
| `requires` | The capability must be achieved before this hook runs |
| `after` | If supplied, wait for the capability's suppliers to settle |

`after` allows an optional milestone to be absent. It does not assert that
the milestone succeeded. Use `requires` when running without the achieved
capability would be incorrect. A capability cannot mix `provides` and
`contributes` suppliers.

Three shared milestones connect independently packaged hooks:

| Capability | Meaning |
|---|---|
| `initramfs-ready` | The initramfs topology and console are usable |
| `rootfs-ready` | The real root is mounted at `/mnt/rootfs` and ready for work |
| `rootfs-strata-ready` | The StrataFS topology exists inside that root |

The builder orders declaring hooks after `initramfs-ready` unless they
supply it or already declare a dependency on it. An image without a supplier
does not gain a missing requirement from this implicit ordering. An explicit
`requires` retains its stronger meaning.

For example, an unlock hook and a root-mount hook can both contribute to
`rootfs-ready`. The mount hook can defer until the unlocked device exists.
This allows independent storage layers to compose without naming every
other hook. Where a prerequisite is known, declare it explicitly.

## Return the right outcome

| Exit | Meaning | Scheduler action |
|---|---|---|
| `0` | The hook completed its work | Record success |
| `69` | The hook has no applicable work | Record a deliberate decline |
| `75` | Inputs are not ready and nothing changed | Retry after other progress |
| Other | An attempted operation failed | Stop boot with the hook's failure |

A declining contributor has completed its part. A declining provider has
not achieved its capability; another provider must succeed if a dependent
hook requires it. Do not report success merely because the hook does not
recognize the machine.

Check for readiness before making changes. Returning `75` promises that
retrying the hook does not repeat a partially completed operation. Once an
operation has been attempted and failed, return a failure instead of hiding
it as a deferral. Prelude stops when a full pass makes no progress while
work remains.

A hook killed by a signal fails. A hook stopped by job control is killed and
reported as stopped; the boot environment does not provide an interactive
job-control session to resume it. Failure does not roll back earlier hooks.

Selected root strategies should diagnose missing required inputs. The
retained live-boot and disk-boot package recipes select one strategy through
conflicting packages; they do not use runtime decline to choose between two
broken configurations. A custom image needs its own explicit selection.

## Report progress and failures

Standard output and standard error go directly to the console. Prelude does
not capture and relabel each line. If the image supplies the level-three
`prelude-hook-abi` helper, source it and use your hook's own name:

```sh
. /usr/libexec/prelude/hook-log.sh
hook_log_init example-root
log "checking root device"
log_ok "root device checked"
log_skip "optional device absent"
log_warn "optional device unavailable"
log_fail "root device check failed"
```

Declare a dependency on `prelude-hook-abi >= 3` when using this helper.
`log_warn` and `log_fail` write to standard error; the other functions write
to standard output. The helper observes the console color convention,
including `TERM=dumb` in the kernel command line.

Use a progress verb for work about to happen and a completed verb only after
success. Logging failure does not itself replace returning a failure status.
Do not log secrets used to unlock storage.

## Build and check the result

1. Check shell syntax with the interpreter used by the image, then build the
   archive with `mkirf`. Resolve warnings about replaced or undeclared hooks.
2. Inspect the generated `/system/prelude/hooks.seq.<n>` files in the image.
   Confirm the chosen paths and capabilities. Do not edit generated sequences.
3. Boot the disposable image. Exercise success, inapplicable hardware,
   missing inputs, deferred work, and operation failure.
4. Confirm that `/mnt/rootfs` is a separate mounted filesystem and that the
   expected init process starts after handoff.

Prelude reads the newest supported sequence version. An unsupported version
produces a warning when a supported fallback exists, or an error when none
exists. The warning remains visible at `peios.quiet=2`. A missing sequence
is an error; an intentionally empty manifest is distinct from a missing one.
Malformed selected manifests also fail rather than silently rescanning hooks.

For discovery and dependency validation during image construction, see
[Building an Initial RAM Filesystem](https://learn.peios.org/peios/using-peios/boot-images/mkirf/).
A successful archive build does not establish that its tools, policy, or
storage configuration can boot.
