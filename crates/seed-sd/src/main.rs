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
// Allow BUILTIN\Administrators GenericAll OI|CI, Allow CREATOR OWNER
// GenericAll OI|CI|IO]. Inheritable so anything
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
// --sddl overrides the built-in descriptor with one given in SDDL. The
// built-in remains the default and remains the *bootstrap* descriptor
// (build_seed_sd): the narrowest thing that makes a fresh tree administrable.
// A caller that needs the access policy of a *running* system — the live
// root's overlay upper, an installer's target root — passes its own.
//
// Keeping those two distinct is not tidiness. The built-in is also what stamps
// /dev (prelude's seed_dev), where every ACE is inherited by whatever block
// device is hot-plugged next; a read ACE for Everyone there is every
// filesystem ACL on the machine bypassed by opening the raw disk. So the
// default must stay narrow, and the widening happens at the call site that
// wants it.
//
// Usage: seed-sd [-r|--recursive] [--sddl <descriptor>] [--] <path>
//
// Exits 0 on success, 2 on usage error, 1 if any node could not be seeded.

use std::path::Path;
use std::process::ExitCode;

use peios::file::{self, OpenFlags, SecInfo};
use peios::security::{
    AccessMask, AceFlags, AclBuilder, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};

fn main() -> ExitCode {
    let mut recursive = false;
    let mut sddl: Option<String> = None;
    let mut path: Option<String> = None;
    // Everything after a `--` is a path, however it is spelled. Without it
    // there would be no way to name a file that genuinely begins with a dash,
    // since an unrecognised one is now refused.
    let mut end_of_flags = false;
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "seed-sd".into());
    while let Some(arg) = args.next() {
        if end_of_flags {
            if path.is_some() {
                return usage(&prog, &format!("more than one path, at {arg:?}"));
            }
            path = Some(arg);
            continue;
        }
        match arg.as_str() {
            "--" => end_of_flags = true,
            "-r" | "--recursive" => recursive = true,
            // A missing value is a usage error rather than an empty
            // descriptor: silently seeding the built-in default when the
            // caller asked for something else is the failure this whole flag
            // exists to make impossible.
            "--sddl" => match args.next() {
                Some(value) => sddl = Some(value),
                None => return usage(&prog, "--sddl needs a descriptor after it"),
            },
            // An unrecognised flag is a mistake, not a filename.
            //
            // Taking it as the path instead turned `seed-sd --recursiv /mnt`
            // into an ENOENT about a file named after the flag, while /mnt was
            // never touched — and an unseeded tree is MISSING descriptors,
            // which under KACS denies everything to everyone, somewhere else,
            // later. That is the failure the --sddl arm above already refuses
            // to risk; the same reasoning applies here.
            _ if arg.starts_with('-') => {
                return usage(
                    &prog,
                    &format!(
                        "unknown flag {arg:?} (put -- before a path that begins with a dash)"
                    ),
                )
            }
            _ if path.is_none() => path = Some(arg),
            _ => return usage(&prog, &format!("more than one path, at {arg:?}")),
        }
    }
    let Some(path) = path else {
        return usage(&prog, "no path given");
    };

    let sd = match build_sd(sddl.as_deref()) {
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

/// Refuse the command line, saying which of the four mistakes it was.
///
/// The usage line alone cannot: "no path", "two paths", "--sddl with nothing
/// after it" and "unknown flag" all look identical in it, and the reader of a
/// boot log is being asked to spot the difference between what they typed and
/// a grammar. One string apiece is cheap.
fn usage(prog: &str, problem: &str) -> ExitCode {
    eprintln!("seed-sd: {problem}");
    eprintln!("usage: {prog} [-r|--recursive] [--sddl <descriptor>] [--] <path>");
    ExitCode::from(2)
}

/// The descriptor to stamp: the caller's, compiled from SDDL, or the built-in
/// bootstrap default when they did not ask for one.
///
/// A descriptor that does not parse is a hard failure. Falling back to the
/// default would stamp a *narrower* policy than the caller asked for, and the
/// symptom of that arrives much later and somewhere else — a service that
/// cannot reach the filesystem, with nothing pointing back to a typo here.
fn build_sd(sddl: Option<&str>) -> Result<SecurityDescriptor, String> {
    match sddl {
        Some(text) => {
            peios::security::sddl::parse(text).map_err(|error| format!("parse {text:?}: {error}"))
        }
        None => build_seed_sd(),
    }
}

/// Build the default SYSTEM-owned seed SD: Allow SYSTEM and Allow
/// BUILTIN\Administrators, both GenericAll and both OI|CI, plus Allow
/// CREATOR OWNER GenericAll OI|CI|IO (inherit-only).
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
/// peinit's `PHASE1_SEED_SDDL` (`src/init/linux/mounts.rs`) is related but
/// deliberately wider: it also grants Everyone read+execute with CI only,
/// so services can reach their own runtime directories. Both descriptors
/// carry the SYSTEM, Administrators and inherit-only CREATOR OWNER entries;
/// their complete DACLs must not be made identical.
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
/// A caller that needs the access policy of a running system passes `--sddl`
/// instead of widening this, precisely so the /dev case above does not inherit
/// the widening along with it.
fn build_seed_sd() -> Result<SecurityDescriptor, String> {
    let system = Sid::well_known(WellKnown::System);
    let administrators = Sid::well_known(WellKnown::Administrators);
    let creator = Sid::well_known(WellKnown::CreatorOwner);
    let inherited = AceFlags::OBJECT_INHERIT | AceFlags::CONTAINER_INHERIT;
    let full = AccessMask::GENERIC_ALL.bits();
    let acl = AclBuilder::new()
        .allow(&system, full, inherited)
        .allow(&administrators, full, inherited)
        .allow(&creator, full, inherited | AceFlags::INHERIT_ONLY)
        .build()
        .map_err(|error| error.to_string())?;
    SdBuilder::new()
        .owner(&system)
        .group(&system)
        .dacl(&acl)
        .build()
        .map_err(|error| error.to_string())
}

/// Stamp the seed SD (owner + group + dacl) onto one path. A symlink is
/// stamped as itself, never followed.
fn seed_one(path: &str, sd: &SecurityDescriptor) -> Result<(), String> {
    file::set_sd(
        None,
        Path::new(path),
        SecInfo::OWNER | SecInfo::GROUP | SecInfo::DACL,
        sd,
        OpenFlags::SYMLINK_NOFOLLOW.bits() as i32,
    )
    .map_err(|error| format!("set_sd {path}: {error}"))
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
fn seed_recursive(path: &str, sd: &SecurityDescriptor) -> usize {
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

#[cfg(test)]
mod tests {
    use super::{build_sd, build_seed_sd, Sid, WellKnown};

    #[test]
    fn default_descriptor_matches_original_builder_bytes() {
        let actual = build_seed_sd().unwrap();
        assert_eq!(
            actual.as_bytes(),
            include_bytes!("../tests/fixtures/bootstrap.sd")
        );
        let view = actual.view().unwrap();
        assert_eq!(view.owner().unwrap(), &*Sid::well_known(WellKnown::System));
        assert_eq!(view.group().unwrap(), &*Sid::well_known(WellKnown::System));
        assert_eq!(view.dacl().unwrap().len(), 3);
    }

    #[test]
    fn explicit_descriptor_replaces_the_default() {
        let descriptor = build_sd(Some("O:SYG:SYD:(A;;GA;;;SY)")).unwrap();
        assert_ne!(descriptor.as_bytes(), build_seed_sd().unwrap().as_bytes());
        assert_eq!(descriptor.view().unwrap().dacl().unwrap().len(), 1);
    }

    #[test]
    fn invalid_descriptor_is_not_replaced_with_bootstrap_policy() {
        for text in ["", "not a descriptor", "O:not-a-sid", "D:(A;;GA;;;invalid)"] {
            assert!(build_sd(Some(text)).is_err(), "{text:?}");
        }
    }
}
