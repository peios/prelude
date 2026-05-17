// prelude
//
// Peios initramfs PID 1. Boot pipeline:
//   - mount the kernel virtual filesystems
//   - run the initramfs hooks, in the order mkirf baked into /hooks.seq
//   - check a hook has mounted the real root at /sysroot
//   - chroot into it and exec the real PID 1
//
// prelude is the invariant skeleton; everything deployment-specific is a
// hook. Mounting the real root is a hook's job — prelude only provides
// the /sysroot mountpoint and verifies the result. It does not resolve
// the hook DAG either: mkirf does that at build time and writes
// /hooks.seq; prelude reads the list and runs it. See boot-design.md.
//
// Built static against musl, no external crates. std for fs/io/env/
// process; raw libc FFI for the syscalls std doesn't expose (mount,
// chroot, reboot, execve, fork, waitpid, sync).

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_ulong};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MS_NOSUID: c_ulong = 2;
const MS_NODEV: c_ulong = 4;
const MS_NOEXEC: c_ulong = 8;
const MS_REC: c_ulong = 16384;
const MS_MOVE: c_ulong = 8192;
const MS_PRIVATE: c_ulong = 1 << 18;

extern "C" {
    fn mount(
        source: *const u8,
        target: *const u8,
        fstype: *const u8,
        flags: c_ulong,
        data: *const u8,
    ) -> c_int;
    fn mkdir(path: *const u8, mode: u32) -> c_int;
    fn chroot(path: *const u8) -> c_int;
    fn chdir(path: *const u8) -> c_int;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int;
    fn reboot(cmd: c_int) -> c_int;
    fn sync();
    fn fork() -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
}

const RB_HALT_SYSTEM: c_int = 0xcdef0123u32 as c_int;
const SYSROOT: &str = "/sysroot";
const FALLBACK_INITS: &[&str] = &["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"];

// The hook manifest mkirf bakes into the initramfs: a version-marker
// line followed by the ordered hook paths.
const HOOK_SEQ: &str = "/hooks.seq";
const HOOK_SEQ_VERSION: &str = "hookseq 1";

fn cstr(s: &str) -> CString {
    CString::new(s).expect("nul in string")
}

fn try_mkdir(path: &str) {
    let p = cstr(path);
    unsafe {
        mkdir(p.as_ptr() as *const u8, 0o755);
    }
}

fn do_mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: c_ulong,
    data: Option<&str>,
) -> std::io::Result<()> {
    let s = cstr(source);
    let t = cstr(target);
    let f = fstype.map(cstr);
    let d = data.map(cstr);
    let f_ptr = f.as_ref().map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);
    let d_ptr = d.as_ref().map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);
    let rc = unsafe {
        mount(
            s.as_ptr() as *const u8,
            t.as_ptr() as *const u8,
            f_ptr,
            flags,
            d_ptr,
        )
    };
    if rc != 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn banner() {
    let lines = [
        "",
        "  ============================================",
        "   prelude  (initramfs PID 1, v0.0.1)",
        "  ============================================",
        "",
    ];
    let mut out = std::io::stdout().lock();
    for l in lines {
        let _ = writeln!(out, "{l}");
    }
    let _ = out.flush();
}

fn log(msg: &str) {
    eprintln!("prelude: {msg}");
}

// Returns the init= value from /proc/cmdline if present.
fn cmdline_init() -> Option<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    for tok in cmdline.split_whitespace() {
        if let Some(v) = tok.strip_prefix("init=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

// Recursively delete everything under `path` that lives on the rootfs's
// device. Mount points (different st_dev) are left alone — that's how
// /proc, /sys, /dev, and /sysroot survive the walk. `path` itself is not
// removed; only its contents.
fn cleanup_old_root(root_dev: u64, path: &Path) -> std::io::Result<()> {
    let entries = fs::read_dir(path)?;
    for entry in entries {
        let entry = entry?;
        let p = entry.path();
        let md = match fs::symlink_metadata(&p) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if md.dev() != root_dev {
            continue;
        }
        if md.file_type().is_dir() {
            if let Err(e) = cleanup_old_root(root_dev, &p) {
                log(&format!("cleanup: descend {} failed: {e}", p.display()));
            }
            if let Err(e) = fs::remove_dir(&p) {
                log(&format!("cleanup: rmdir {} failed: {e}", p.display()));
            }
        } else if let Err(e) = fs::remove_file(&p) {
            log(&format!("cleanup: unlink {} failed: {e}", p.display()));
        }
    }
    Ok(())
}

// Decode a `waitpid` status. `None` means the child exited cleanly;
// `Some(reason)` describes how it failed.
fn wait_failure(status: c_int) -> Option<String> {
    let term_sig = status & 0x7f;
    if term_sig == 0 {
        let code = (status >> 8) & 0xff;
        (code != 0).then(|| format!("exited with status {code}"))
    } else if term_sig == 0x7f {
        Some("stopped".to_string())
    } else {
        Some(format!("killed by signal {term_sig}"))
    }
}

// Read /hooks.seq — the ordered hook list mkirf bakes into the
// initramfs. A missing file means simply "no hooks"; a file whose
// version marker is unrecognised is an error.
fn read_hook_seq() -> std::io::Result<Vec<String>> {
    let text = match fs::read_to_string(HOOK_SEQ) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            log(&format!("{HOOK_SEQ}: not present; no hooks"));
            return Ok(Vec::new());
        }
        Err(e) => return Err(e),
    };
    let mut lines = text.lines();
    match lines.next() {
        Some(HOOK_SEQ_VERSION) => {}
        other => {
            return Err(std::io::Error::other(format!(
                "{HOOK_SEQ}: unrecognised version marker {other:?}"
            )))
        }
    }
    Ok(lines.filter(|l| !l.is_empty()).map(str::to_string).collect())
}

// Fork-exec one hook and wait for it. The hook is a script; the kernel
// honours its `#!/bin/sh` shebang, so /bin/sh must exist in the
// initramfs. A hook that does not exit 0 fails the boot.
fn run_one_hook(path: &str) -> std::io::Result<()> {
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: exec the hook and never fall back into prelude's pipeline.
        let p = cstr(path);
        let argv: [*const u8; 2] = [p.as_ptr() as *const u8, core::ptr::null()];
        let term = cstr("TERM=linux");
        let path_env = cstr("PATH=/bin");
        let envp: [*const u8; 3] = [
            term.as_ptr() as *const u8,
            path_env.as_ptr() as *const u8,
            core::ptr::null(),
        ];
        unsafe { execve(p.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr()) };
        log(&format!(
            "hook {path}: exec failed: {}",
            std::io::Error::last_os_error(),
        ));
        unsafe { _exit(127) };
    }
    let mut status: c_int = 0;
    if unsafe { waitpid(pid, &mut status, 0) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    match wait_failure(status) {
        None => Ok(()),
        Some(reason) => Err(std::io::Error::other(format!("hook {path}: {reason}"))),
    }
}

// Run every hook listed in /hooks.seq, in order. Called before the
// real root is mounted; the kernel virtual filesystems are already up.
fn run_hooks() -> std::io::Result<()> {
    let hooks = read_hook_seq()?;
    if hooks.is_empty() {
        log("no hooks to run");
        return Ok(());
    }
    for hook in &hooks {
        log(&format!("hook: {hook}"));
        run_one_hook(hook)?;
    }
    log(&format!("ran {} hook(s)", hooks.len()));
    Ok(())
}

// The real work. Returns only on failure — success exits via execve.
fn boot() -> std::io::Result<()> {
    // Phase 0: make the rootfs and all descendant mounts private so that
    // mount-move (phase 5) and the root pivot (phase 7) aren't blocked by
    // shared-mount propagation. Modern kernels default new mounts to shared
    // namespace propagation, which makes MS_MOVE return EACCES on mounts
    // marked shared.
    do_mount("none", "/", None, MS_REC | MS_PRIVATE, None)?;

    // Phase 1: kernel virtual filesystems.
    try_mkdir("/proc");
    try_mkdir("/sys");
    try_mkdir("/dev");
    do_mount("proc", "/proc", Some("proc"), MS_NOSUID | MS_NOEXEC | MS_NODEV, None)?;
    do_mount("sysfs", "/sys", Some("sysfs"), MS_NOSUID | MS_NOEXEC | MS_NODEV, None)?;
    do_mount("devtmpfs", "/dev", Some("devtmpfs"), MS_NOSUID, None)?;

    banner();

    // Phase 2: figure out the target init.
    let target_init = match cmdline_init() {
        Some(v) => {
            log(&format!("target init from cmdline: {v}"));
            v
        }
        None => {
            log("no init= on cmdline; will try fallback chain on the new root");
            String::new()
        }
    };

    // Phase 3: run the initramfs hooks. The kernel virtual filesystems
    // are up — a hook may need them. prelude provides an empty /sysroot
    // mountpoint; mounting a real root onto it is a hook's job (the root
    // filesystem varies by deployment, so it is never hardcoded here).
    // mkirf resolved the hook order at build time; we just run the list.
    try_mkdir(SYSROOT);
    run_hooks()?;

    // Phase 4: a hook must have mounted the real root at /sysroot. If it
    // is still on the initramfs's own device, nothing mounted it.
    if fs::metadata(SYSROOT)?.dev() == fs::metadata("/")?.dev() {
        return Err(std::io::Error::other(format!(
            "no hook mounted a root filesystem at {SYSROOT}"
        )));
    }
    log(&format!("root mounted at {SYSROOT}"));

    // Phase 5: move kernel vfs into the new root so the new PID 1 has them.
    // The squashfs is RO and must ship /proc, /sys, /dev as empty
    // mountpoint dirs — build-staging.sh creates them.
    for sub in &["proc", "sys", "dev"] {
        let from = format!("/{sub}");
        let to = format!("{SYSROOT}/{sub}");
        log(&format!("mount-move {from} -> {to}"));
        do_mount(&from, &to, None, MS_MOVE, None).map_err(|e| {
            std::io::Error::new(e.kind(), format!("mount-move {from}: {e}"))
        })?;
    }

    // Phase 6: cleanup the old rootfs. Walks rootfs's st_dev only; the
    // moved mounts and /sysroot all have different st_devs and stay put.
    let root_dev = fs::metadata("/")?.dev();
    if let Err(e) = cleanup_old_root(root_dev, Path::new("/")) {
        log(&format!("cleanup: {e} (continuing)"));
    }

    // Phase 7: chroot into the new root. We don't mount-move the squashfs
    // over the rootfs (`mount(".", "/", MS_MOVE)`) because the kernel
    // disallows moving onto the rootfs. pivot_root has the same constraint.
    // chroot is sufficient for now: PID 1 and all descendants see the
    // squashfs as /. The kernel's "real" rootfs is unreachable but still
    // exists as a namespace bookkeeping artifact (empty after phase 6).
    log("pivot: chdir sysroot");
    let sysroot_c = cstr(SYSROOT);
    let slash_c = cstr("/");
    unsafe {
        if chdir(sysroot_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(std::io::Error::last_os_error().kind(),
                format!("chdir({SYSROOT}): {}", std::io::Error::last_os_error())));
        }
        log("pivot: chroot");
        if chroot(sysroot_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(std::io::Error::last_os_error().kind(),
                format!("chroot({SYSROOT}): {}", std::io::Error::last_os_error())));
        }
        log("pivot: chdir /");
        if chdir(slash_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(std::io::Error::last_os_error().kind(),
                format!("chdir(/): {}", std::io::Error::last_os_error())));
        }
    }

    // Phase 8: exec the real PID 1. Try cmdline init= first, then the
    // kernel's own fallback chain (/sbin/init, /etc/init, /bin/init, /bin/sh).
    let candidates: Vec<&str> = if !target_init.is_empty() {
        let mut v = Vec::with_capacity(FALLBACK_INITS.len() + 1);
        v.push(target_init.as_str());
        v.extend_from_slice(FALLBACK_INITS);
        v
    } else {
        FALLBACK_INITS.to_vec()
    };

    let term = cstr("TERM=linux");
    let envp: [*const u8; 2] = [term.as_ptr() as *const u8, core::ptr::null()];

    for path in &candidates {
        if !Path::new(path).exists() {
            log(&format!("skip {path}: not present"));
            continue;
        }
        log(&format!("exec {path}"));
        let pc = cstr(path);
        let arg0 = cstr(path);
        let argv: [*const u8; 2] = [arg0.as_ptr() as *const u8, core::ptr::null()];
        unsafe {
            execve(pc.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr());
        }
        log(&format!("execve {path} failed: {}", std::io::Error::last_os_error()));
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "no init candidate executable",
    ))
}

fn halt() -> ! {
    log("halting system");
    unsafe {
        sync();
        reboot(RB_HALT_SYSTEM);
    }
    loop {
        std::thread::park();
    }
}

fn main() {
    if let Err(e) = boot() {
        log(&format!("boot failed: {e}"));
    }
    halt();
}

#[cfg(test)]
mod tests {
    use super::wait_failure;

    #[test]
    fn clean_exit_is_not_a_failure() {
        // status 0: exited normally, code 0.
        assert!(wait_failure(0).is_none());
    }

    #[test]
    fn nonzero_exit_is_reported() {
        // exit code lives in bits 8..16 of the status word.
        let reason = wait_failure(1 << 8).expect("a non-zero exit must be a failure");
        assert!(reason.contains("status 1"), "{reason}");
    }

    #[test]
    fn signal_termination_is_reported() {
        // a termination signal lives in the low 7 bits.
        let reason = wait_failure(9).expect("a signal kill must be a failure");
        assert!(reason.contains("signal 9"), "{reason}");
    }
}
