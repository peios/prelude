// seed-sd: write the default seed SD onto a path (and, with -r, onto every
// existing descendant too).
//
// One-shot CLI used by prelude and its hooks (and similar early-boot / install
// contexts) to seed the SD on a fresh tmpfs/ext4 root the moment it is
// mounted, before KACS DENY_MISSING sees the empty inode and locks every
// subsequent access on it. build_seed_sd below is the only definition of that
// blob left in-tree (protoinit::seed_writable_sd, which this comment used to
// pair it with, is gone), so changing it changes every seeded tree.
//
// The SD: owner=SYSTEM, group=SYSTEM, DACL = [Allow SYSTEM GenericAll OI|CI,
// Allow BUILTIN\Administrators GenericAll OI|CI]. Inheritable so anything
// created under the mount picks up the same default via KACS's
// inode_init_security inheritance — which means this ACL is, in practice, the
// access policy of the entire tree. See build_seed_sd for why Administrators
// is in it and why nothing broader is.
//
// -r / --recursive also seeds every existing descendant. Each node is seeded
// *before* it is read, so the walk can descend into directories that were
// MISSING (and therefore inaccessible) right up until we seed them — e.g.
// ext4's mkfs-created lost+found, born before the root was seeded. This is
// what an installer wants after mkfs+mount: one call makes the whole target
// tree managed and writable.
//
// It is also what prelude wants for /dev. The kernel seeds the devtmpfs root
// SYSTEM-only before any userspace exists (that is plumbing: it lets
// kdevtmpfs create nodes under DENY_MISSING), and every node created since has
// inherited that one ACE. Re-seeding the root alone would fix nothing already
// there — KACS computes inheritance once, at creation — so the existing nodes
// are re-stamped explicitly. Nodes that appear later inherit from the new
// root.
//
// Symlinks are stamped as themselves and never followed. That is not merely
// "don't leave the tree": /dev/core points at /proc/kcore and /dev/stdin at
// /proc/self/fd/0, and /proc is UNMANAGED, so following would fail every such
// link — while the link inode itself is what `ls -l` has to stat, and it needs
// the seed as much as anything else in the tree.
//
// A recursive walk is best-effort: a node that cannot be stamped is reported
// and the walk continues, because one odd inode is no reason to leave the rest
// of a tree locked. The exit status still says whether everything succeeded.
//
// Requires SeRestorePrivilege in the caller's token where a target's existing
// SD is MISSING (the fresh-mount case): KACS only allows replacing a MISSING
// SD via that privilege. Re-stamping a node that already has an SD needs the
// ordinary WRITE_DAC / WRITE_OWNER rights, which SYSTEM holds as owner.
//
// Usage: seed-sd [-r|--recursive] <path>
//
// Exits 0 on success, 2 on usage error, 1 if any node could not be seeded.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut recursive = false;
    let mut path: Option<String> = None;
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "seed-sd".into());
    for arg in args {
        match arg.as_str() {
            "-r" | "--recursive" => recursive = true,
            _ if path.is_none() => path = Some(arg),
            _ => return usage(&prog),
        }
    }
    let Some(path) = path else {
        return usage(&prog);
    };

    let sd = match build_seed_sd() {
        Ok(sd) => sd,
        Err(e) => {
            eprintln!("seed-sd: build SD: {e}");
            return ExitCode::FAILURE;
        }
    };

    if recursive {
        let failures = seed_recursive(&path, &sd);
        if failures == 0 {
            ExitCode::SUCCESS
        } else {
            eprintln!("seed-sd: {failures} node(s) under {path} could not be seeded");
            ExitCode::FAILURE
        }
    } else {
        match seed_one(&path, &sd) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("seed-sd: {e}");
                ExitCode::FAILURE
            }
        }
    }
}

fn usage(prog: &str) -> ExitCode {
    eprintln!("usage: {prog} [-r|--recursive] <path>");
    ExitCode::from(2)
}

/// Build the default SYSTEM-owned seed SD: Allow SYSTEM and Allow
/// BUILTIN\Administrators, both GenericAll and both OI|CI.
///
/// # Why Administrators is here
///
/// This one ACL is the entire access policy of a freshly seeded tree: it is
/// stamped on the root and every descendant *inherits* it, so what it grants is
/// what every file on the system grants. While SYSTEM was the only principal
/// that could exist, a single Allow-SYSTEM ACE was a complete answer.
///
/// It stopped being one the moment authd could mint a non-SYSTEM token. An
/// administrator signing on receives `BUILTIN\Administrators` and nothing else
/// that appears here, so under the old ACL they could traverse to a file (with
/// `SeChangeNotifyPrivilege`, which bypasses `FILE_TRAVERSE`) and even execute
/// it, but could not enumerate a single directory — nothing bypasses
/// `FILE_LIST_DIRECTORY`. A usable administrator account was impossible.
///
/// Mirrors the default the registry already uses for the same question
/// (`loregd/internal/sd/sd.go`): SYSTEM and Administrators full.
///
/// peinit's `PHASE1_SEED_SDDL` (`src/init/linux/mounts.rs`) is a hand copy of
/// this descriptor for the mounts peinit creates itself. The two MUST stay
/// identical; the last time they drifted, Administrators was added here and
/// not there (PEI-223).
///
/// # What is deliberately *not* here
///
/// No `Authenticated Users` or `BUILTIN\Users` ACE, so an ordinary
/// non-administrator still cannot read a seeded tree. That is not an oversight
/// but a limit of the mechanism: one inheritable template covers the whole
/// tree, so any read granted here is granted on `/root` and on every home
/// directory as much as on `/usr`. "A readable system tree with private home
/// directories" cannot be said in a single inherited ACL; it needs per-subtree
/// descriptors, which is the SD materialisation `peipkg-compose` defers to
/// image finalisation.
///
/// The same limit is why this is the right descriptor for `/dev`'s root even
/// though `/dev/null` must be writable by everyone: whatever the root grants,
/// a hot-plugged raw disk inherits. The permissive exceptions are stamped on
/// the individual static nodes by peinit, not expressed here.
///
/// So this stays a *bootstrap* default — the narrowest thing that makes the
/// system administrable — rather than growing into a policy it cannot express.
fn build_seed_sd() -> Result<Vec<u8>, String> {
    use libp_sd::consts::{
        ACCESS_GENERIC_ALL, ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_OBJECT_INHERIT,
    };
    let inheritable = ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT;
    let system = libp_sd::AceBuilder::allow(libp_sd::WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
        .flags(inheritable);
    let administrators = libp_sd::AceBuilder::allow(
        libp_sd::WellKnownSid::BuiltinAdministrators,
        ACCESS_GENERIC_ALL,
    )
    .flags(inheritable);
    let dacl = libp_sd::AclBuilder::new().ace(system).ace(administrators);
    libp_sd::SdBuilder::new()
        .owner(libp_sd::WellKnownSid::LocalSystem)
        .group(libp_sd::WellKnownSid::LocalSystem)
        .dacl(dacl)
        .build()
        .map_err(|e| format!("{e:?}"))
}

/// Stamp the seed SD (owner + group + dacl) onto one path. A symlink is
/// stamped as itself, never followed.
fn seed_one(path: &str, sd: &[u8]) -> Result<(), String> {
    let info = libp_sd::SecurityInfo::owner().with_group().with_dacl();
    let target = libp_sd::SdTarget::Path {
        dirfd: libp_sd::raw::FDCWD,
        path,
        no_follow_symlinks: true,
    };
    libp_sd::set_sd(&target, info, sd).map_err(|e| format!("set_sd {path}: {e:?}"))
}

/// Seed `path`, then descend into it if it is a directory. `path` is seeded
/// *before* it is read, so a directory that was MISSING (and thus
/// inaccessible) becomes readable the instant it is seeded and the walk can
/// enter it. Symlinks are stamped but never followed, so the walk cannot leave
/// the tree.
///
/// Best-effort: every failure is reported on stderr and counted, and the walk
/// goes on. Returns the number of nodes that could not be seeded. A directory
/// that could not be read counts once and is not descended into.
fn seed_recursive(path: &str, sd: &[u8]) -> usize {
    let mut failures = 0;
    if let Err(e) = seed_one(path, sd) {
        eprintln!("seed-sd: {e}");
        failures += 1;
    }
    let md = match std::fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) => {
            eprintln!("seed-sd: stat {path}: {e}");
            return failures + 1;
        }
    };
    if !md.is_dir() {
        return failures;
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(e) => {
            eprintln!("seed-sd: read_dir {path}: {e}");
            return failures + 1;
        }
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                eprintln!("seed-sd: read_dir {path}: {e}");
                failures += 1;
                continue;
            }
        };
        let child = entry.path();
        let Some(child) = child.to_str() else {
            eprintln!("seed-sd: non-UTF-8 path under {path}");
            failures += 1;
            continue;
        };
        failures += seed_recursive(child, sd);
    }
    failures
}
