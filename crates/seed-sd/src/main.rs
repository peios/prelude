// seed-sd: write a default Allow-SYSTEM-GenericAll SD onto a path (and, with
// -r, onto every existing descendant too).
//
// One-shot CLI used by prelude hooks (and similar early-boot / install
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
// Requires SeRestorePrivilege in the caller's token: each target's existing
// SD is MISSING (that's the whole point of seeding), and KACS only allows
// replacing a MISSING SD via that privilege.
//
// Usage: seed-sd [-r|--recursive] <path>
//
// Exits 0 on success, 2 on usage error, 1 on syscall/build failure.

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

    let result = if recursive {
        seed_recursive(&path, &sd)
    } else {
        seed_one(&path, &sd)
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("seed-sd: {e}");
            ExitCode::FAILURE
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

/// Stamp the seed SD (owner + group + dacl) onto one path.
fn seed_one(path: &str, sd: &[u8]) -> Result<(), String> {
    let info = libp_sd::SecurityInfo::owner().with_group().with_dacl();
    libp_sd::set_sd(&libp_sd::SdTarget::path(path), info, sd)
        .map_err(|e| format!("set_sd {path}: {e:?}"))
}

/// Seed `path`, then descend into it. `path` is seeded *before* it is read, so
/// a directory that was MISSING (and thus inaccessible) becomes readable the
/// instant it is seeded and the walk can enter it. Symlinks are seeded but not
/// followed (we don't descend out of the tree).
fn seed_recursive(path: &str, sd: &[u8]) -> Result<(), String> {
    seed_one(path, sd)?;
    let md = std::fs::symlink_metadata(path).map_err(|e| format!("stat {path}: {e}"))?;
    if !md.is_dir() {
        return Ok(());
    }
    let entries = std::fs::read_dir(path).map_err(|e| format!("read_dir {path}: {e}"))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("read_dir {path}: {e}"))?;
        let child = entry.path();
        let child = child
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 path under {path}"))?;
        seed_recursive(child, sd)?;
    }
    Ok(())
}
