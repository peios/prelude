// seed-sd: write a default Allow-SYSTEM-GenericAll SD onto a path.
//
// One-shot CLI used by prelude hooks (and similar early-boot shell
// contexts) to seed the SD on a fresh tmpfs root the moment it is
// mounted, before KACS DENY_MISSING sees the empty inode and locks
// every subsequent access on it. Same blob protoinit::seed_writable_sd
// writes; the difference is invocation surface — this one's a CLI a
// hook script can call directly.
//
// The SD: owner=SYSTEM, group=SYSTEM, DACL = [Allow SYSTEM GenericAll
// OI|CI]. Inheritable so anything created under the mount picks up the
// same default via KACS's inode_init_security inheritance.
//
// Requires SeRestorePrivilege in the caller's token because the target's
// existing SD is MISSING (that's the whole point of seeding); KACS
// only allows replacing a MISSING SD via that privilege.
//
// Usage: seed-sd <path>
//
// Exits 0 on success, 2 on usage error, 1 on syscall/build failure.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args();
    let prog = args.next().unwrap_or_else(|| "seed-sd".into());
    let path = match (args.next(), args.next()) {
        (Some(p), None) => p,
        _ => {
            eprintln!("usage: {prog} <path>");
            return ExitCode::from(2);
        }
    };

    use libp_sd::consts::{
        ACCESS_GENERIC_ALL, ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_OBJECT_INHERIT,
    };

    let allow = libp_sd::AceBuilder::allow(
        libp_sd::WellKnownSid::LocalSystem,
        ACCESS_GENERIC_ALL,
    )
    .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT);
    let dacl = libp_sd::AclBuilder::new().ace(allow);
    let sd = match libp_sd::SdBuilder::new()
        .owner(libp_sd::WellKnownSid::LocalSystem)
        .group(libp_sd::WellKnownSid::LocalSystem)
        .dacl(dacl)
        .build()
    {
        Ok(b) => b,
        Err(e) => {
            eprintln!("seed-sd: build SD: {e:?}");
            return ExitCode::FAILURE;
        }
    };
    let info = libp_sd::SecurityInfo::owner()
        .with_group()
        .with_dacl();
    let target = libp_sd::SdTarget::path(&path);
    if let Err(e) = libp_sd::set_sd(&target, info, &sd) {
        eprintln!("seed-sd: set_sd {path}: {e:?}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
