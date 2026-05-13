// prelude
//
// Peios initramfs PID 1. Mounts /proc /sys /dev, walks the hook list at
// /etc/prelude/hooks, then drops to /bin/sh. switch_root lands later
// (M1 step 5 of boot-design.md).
//
// Built static against musl. No external crates: keeps the boot artifact
// auditable and the build trivial. std is used where it's already there
// (fs, process::Command, io); raw libc FFI covers the syscalls std
// doesn't expose (mount, reboot, sync, execve).

#![allow(clippy::missing_safety_doc)]

use core::ffi::{c_int, c_ulong};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::process::Command;

const MS_NOSUID: c_ulong = 2;
const MS_NODEV: c_ulong = 4;
const MS_NOEXEC: c_ulong = 8;

extern "C" {
    fn mount(
        source: *const u8,
        target: *const u8,
        fstype: *const u8,
        flags: c_ulong,
        data: *const u8,
    ) -> c_int;
    fn mkdir(path: *const u8, mode: u32) -> c_int;
    fn execve(path: *const u8, argv: *const *const u8, envp: *const *const u8) -> c_int;
    fn reboot(cmd: c_int) -> c_int;
    fn sync();
}

const RB_HALT_SYSTEM: c_int = 0xcdef0123u32 as c_int;
const HOOK_LIST_PATH: &str = "/etc/prelude/hooks";

fn cstr(s: &str) -> CString {
    CString::new(s).expect("nul in string")
}

fn try_mount(source: &str, target: &str, fstype: &str, flags: c_ulong) {
    let s = cstr(source);
    let t = cstr(target);
    let f = cstr(fstype);
    let rc = unsafe {
        mount(
            s.as_ptr() as *const u8,
            t.as_ptr() as *const u8,
            f.as_ptr() as *const u8,
            flags,
            core::ptr::null(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        eprintln!("prelude: mount {target} ({fstype}) failed: {err}");
    }
}

fn try_mkdir(path: &str) {
    let p = cstr(path);
    unsafe {
        mkdir(p.as_ptr() as *const u8, 0o755);
    }
}

fn banner() {
    let lines = [
        "",
        "  ============================================",
        "   prelude  (initramfs PID 1, v0.0.1)",
        "   walks hooks, then hands off",
        "  ============================================",
        "",
    ];
    let mut out = std::io::stdout().lock();
    for l in lines {
        let _ = writeln!(out, "{l}");
    }
    let _ = out.flush();
}

struct Hook {
    name: String,
    path: String,
}

fn parse_hooks(contents: &str) -> Vec<Hook> {
    let mut hooks = Vec::new();
    for (lineno, raw) in contents.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let name = parts.next().unwrap_or("").trim();
        let path = parts.next().map(|p| p.trim()).unwrap_or("");
        if name.is_empty() || path.is_empty() {
            eprintln!(
                "prelude: malformed hook line {} (expected '<name> <path>'): {raw:?}",
                lineno + 1
            );
            continue;
        }
        hooks.push(Hook {
            name: name.to_string(),
            path: path.to_string(),
        });
    }
    hooks
}

fn run_hooks() -> Result<(), String> {
    let contents = match fs::read_to_string(HOOK_LIST_PATH) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("prelude: no hook list at {HOOK_LIST_PATH}; nothing to run");
            return Ok(());
        }
        Err(e) => return Err(format!("could not read {HOOK_LIST_PATH}: {e}")),
    };

    let hooks = parse_hooks(&contents);
    if hooks.is_empty() {
        eprintln!("prelude: hook list is empty; nothing to run");
        return Ok(());
    }

    for hook in &hooks {
        eprintln!("prelude: running hook {} ({})", hook.name, hook.path);
        let status = match Command::new(&hook.path).status() {
            Ok(s) => s,
            Err(e) => return Err(format!("hook {}: spawn failed: {e}", hook.name)),
        };
        if !status.success() {
            let how = match status.code() {
                Some(c) => format!("exit {c}"),
                None => "killed by signal".to_string(),
            };
            return Err(format!("hook {}: {how}", hook.name));
        }
    }
    Ok(())
}

fn drop_to_shell() -> ! {
    let shell = cstr("/bin/sh");
    let arg0 = cstr("sh");
    let argv: [*const u8; 2] = [arg0.as_ptr() as *const u8, core::ptr::null()];
    let term = cstr("TERM=linux");
    let envp: [*const u8; 2] = [term.as_ptr() as *const u8, core::ptr::null()];

    let rc = unsafe { execve(shell.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr()) };
    let err = std::io::Error::last_os_error();
    eprintln!("prelude: execve /bin/sh failed (rc={rc}): {err}");
    halt();
}

fn halt() -> ! {
    eprintln!("prelude: halting");
    unsafe {
        sync();
        reboot(RB_HALT_SYSTEM);
    }
    loop {
        std::thread::park();
    }
}

fn main() {
    try_mkdir("/proc");
    try_mkdir("/sys");
    try_mkdir("/dev");

    try_mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV);
    try_mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV);
    try_mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID);

    banner();

    if let Err(reason) = run_hooks() {
        eprintln!("prelude: hook execution failed: {reason}");
        eprintln!("prelude: dropping to shell for debug");
    }

    // No switch_root yet (M1 step 5). After hooks run, drop to a shell.
    // Makes prelude a drop-in replacement for protoinit in kobicha-style
    // permanent-initramfs setups.
    drop_to_shell();
}
