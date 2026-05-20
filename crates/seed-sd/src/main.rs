// seed-sd: write a default Allow-SYSTEM-GenericAll SD onto a path (and, with
// -r, onto every existing descendant too).
//
// One-shot CLI used by prelude hooks (and similar early-boot / install
// contexts) to seed the SD on a fresh tmpfs/ext4 root the moment it is
// mounted, before KACS DENY_MISSING sees the empty inode and locks every
// subsequent access on it. Same blob protoinit::seed_writable_sd writes; the
// difference is invocation surface — this one's a CLI a hook script can call.
//
// The SD: owner=SYSTEM, group=SYSTEM, DACL = [Allow SYSTEM GenericAll OI|CI].
// Inheritable so anything created under the mount picks up the same default
// via KACS's inode_init_security inheritance.
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

/// Build the default Allow-SYSTEM-GenericAll (OI|CI), SYSTEM-owned SD bytes.
fn build_seed_sd() -> Result<Vec<u8>, String> {
    use libp_sd::consts::{
        ACCESS_GENERIC_ALL, ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_OBJECT_INHERIT,
    };
    let allow =
        libp_sd::AceBuilder::allow(libp_sd::WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
            .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT);
    let dacl = libp_sd::AclBuilder::new().ace(allow);
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
