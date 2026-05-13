// prelude
//
// Peios initramfs PID 1. Hardcoded monolithic boot pipeline for Goal One:
// mount kernel virtual filesystems, mount the baked-in squashfs as the new
// root, switch_root, exec the real PID 1.
//
// No hooks, no DAG, no external crates. Once peinitramfs and the real DAG
// land we'll grow this into a hook walker. For now the goal is end-to-end
// validation of switch_root mechanics with the smallest possible prelude.
//
// Built static against musl. std for fs/io/env/process; raw libc FFI for the
// syscalls std doesn't expose (mount, chroot, reboot, execve, sync).

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_long, c_ulong};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MS_RDONLY: c_ulong = 1;
const MS_NOSUID: c_ulong = 2;
const MS_NODEV: c_ulong = 4;
const MS_NOEXEC: c_ulong = 8;
const MS_REC: c_ulong = 16384;
const MS_MOVE: c_ulong = 8192;
const MS_PRIVATE: c_ulong = 1 << 18;

const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;

// Loop ioctls. Numbers stable across architectures (no _IO macros needed —
// these are plain bit constants).
const LOOP_SET_FD: c_ulong = 0x4C00;
const LOOP_CTL_GET_FREE: c_ulong = 0x4C82;

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
    fn open(path: *const u8, flags: c_int) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn ioctl(fd: c_int, request: c_ulong, arg: c_long) -> c_int;
}

const RB_HALT_SYSTEM: c_int = 0xcdef0123u32 as c_int;
const SYSROOT: &str = "/sysroot";
const SYSROOT_IMG: &str = "/sysroot.squashfs";
const FALLBACK_INITS: &[&str] = &["/sbin/init", "/etc/init", "/bin/init", "/bin/sh"];

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

// Attach `backing_path` to a free loop device. Returns the loop device
// path (e.g. "/dev/loop0"). On error the caller should drop to halt;
// we don't bother cleaning up partial state because PID 1 is about to die.
fn setup_loop(backing_path: &str) -> std::io::Result<String> {
    let ctl_path = cstr("/dev/loop-control");
    let ctl_fd = unsafe { open(ctl_path.as_ptr() as *const u8, O_RDWR) };
    if ctl_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let loop_n = unsafe { ioctl(ctl_fd, LOOP_CTL_GET_FREE, 0) };
    unsafe { close(ctl_fd) };
    if loop_n < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let loop_dev = format!("/dev/loop{loop_n}");
    let loop_c = cstr(&loop_dev);
    let loop_fd = unsafe { open(loop_c.as_ptr() as *const u8, O_RDWR) };
    if loop_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let backing_c = cstr(backing_path);
    let backing_fd = unsafe { open(backing_c.as_ptr() as *const u8, O_RDONLY) };
    if backing_fd < 0 {
        let e = std::io::Error::last_os_error();
        unsafe { close(loop_fd) };
        return Err(e);
    }

    let rc = unsafe { ioctl(loop_fd, LOOP_SET_FD, backing_fd as c_long) };
    unsafe { close(backing_fd) };
    unsafe { close(loop_fd) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(loop_dev)
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
    let entries = match fs::read_dir(path) {
        Ok(it) => it,
        Err(e) => return Err(e),
    };
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

// The real work. Returns only on failure — success exits via execve.
fn boot() -> std::io::Result<()> {
    // Phase 0: make the rootfs and all descendant mounts private so that
    // mount-move (phase 4) and the root pivot (phase 6) aren't blocked by
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

    // Phase 3: mount the squashfs new root.
    if !Path::new(SYSROOT_IMG).exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("no {SYSROOT_IMG} in initramfs"),
        ));
    }
    try_mkdir(SYSROOT);
    let loop_dev = setup_loop(SYSROOT_IMG)?;
    log(&format!("loop: {SYSROOT_IMG} -> {loop_dev}"));
    do_mount(&loop_dev, SYSROOT, Some("squashfs"), MS_RDONLY, None)?;
    log(&format!("mounted {loop_dev} at {SYSROOT}"));

    // Phase 4: move kernel vfs into the new root so the new PID 1 has them.
    // The squashfs is RO and must ship /proc, /sys, /dev as empty
    // mountpoint dirs — build-sysroot-squashfs.sh creates them.
    for sub in &["proc", "sys", "dev"] {
        let from = format!("/{sub}");
        let to = format!("{SYSROOT}/{sub}");
        log(&format!("mount-move {from} -> {to}"));
        do_mount(&from, &to, None, MS_MOVE, None).map_err(|e| {
            std::io::Error::new(e.kind(), format!("mount-move {from}: {e}"))
        })?;
    }

    // Phase 5: cleanup the old rootfs. Walks rootfs's st_dev only; the
    // moved mounts and /sysroot all have different st_devs and stay put.
    let root_dev = fs::metadata("/")?.dev();
    if let Err(e) = cleanup_old_root(root_dev, Path::new("/")) {
        log(&format!("cleanup: {e} (continuing)"));
    }

    // Phase 6: chroot into the new root. We don't mount-move the squashfs
    // over the rootfs (`mount(".", "/", MS_MOVE)`) because the kernel
    // disallows moving onto the rootfs. pivot_root has the same constraint.
    // chroot is sufficient for Goal One: PID 1 and all descendants see the
    // squashfs as /. The kernel's "real" rootfs is unreachable but still
    // exists as a namespace bookkeeping artifact (empty after phase 5).
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

    // Phase 7: exec the real PID 1. Try cmdline init= first, then the
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
