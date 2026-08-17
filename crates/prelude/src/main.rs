// prelude
//
// Peios initramfs PID 1. Boot pipeline:
//   - mount the kernel virtual filesystems
//   - run the initramfs hooks, in the order mkirf baked into the hook
//     sequence under /system/prelude
//   - check a hook has mounted the real root at /sysroot
//   - chroot into it and exec the real PID 1
//
// prelude is the invariant skeleton; everything deployment-specific is a
// hook. Mounting the real root is a hook's job — prelude only provides
// the /sysroot mountpoint and verifies the result. It does not resolve
// the hook DAG either: mkirf does that at build time and writes
// /system/prelude/hooks.seq.<n>; prelude reads the newest version it
// understands and runs it. See boot-design.md.
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
const FALLBACK_INITS: &[&str] = &["/bin/peinit2", "/sbin/init", "/bin/init", "/bin/sh"];

// The debug shell prelude drops to under rd.shell / rd.break. dash claims
// /usr/bin/sh. The initramfs has no /bin view before its hooks mount runtime
// topology, so exec package storage directly; PID 1 also carries no PATH.
const RESCUE_SHELL: &str = "/usr/bin/sh";

// The hook manifests mkirf bakes into the initramfs. The format version is
// in the FILE NAME — /system/prelude/hooks.seq.<n> — because mkirf and
// prelude ship in two independently versioned packages (mkirf is a
// peiosutils applet), so an image may pair a new writer with an old reader.
// Emitting every version it can express lets one image satisfy both, which
// a single file with an in-band marker cannot do.
//
// The first line still carries the marker, as a self-check: the name says
// what the file should be, the marker says what it is, and a disagreement
// is a hard error rather than a silently misparsed sequence.
const HOOK_SEQ_DIR: &str = "/system/prelude";
const HOOK_SEQ_STEM: &str = "hooks.seq.";
// The newest format this prelude can parse. A sequence numbered above this
// is a warning if something usable is also present, and an error if not.
const HOOK_SEQ_MAX: u32 = 2;
// Where mkirf used to write the sequence, before the version moved into the
// name. Read as a last resort so an image built by an older mkirf still
// boots; never written any more.
const HOOK_SEQ_LEGACY: &str = "/hooks.seq";
const HOOK_SEQ_VERSION: &str = "hookseq 1";
const HOOK_SEQ_V2_VERSION: &str = "hookseq 2";

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
    let f_ptr = f
        .as_ref()
        .map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);
    let d_ptr = d
        .as_ref()
        .map_or(core::ptr::null(), |c| c.as_ptr() as *const u8);
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

// Whether `flag` appears on the cmdline as a bare token (e.g. rd.shell).
// prelude takes its debug knobs from /proc/cmdline, like init=, because it is
// PID 1 and the kernel runs it with no argv to speak of.
fn cmdline_has(cmdline: &str, flag: &str) -> bool {
    cmdline.split_whitespace().any(|tok| tok == flag)
}

// Parsed `rd.break[=<hook>]` breakpoints (dracut's `rd.break=<stage>`, keyed on
// prelude's hooks instead of named stages). Bare `rd.break` stops before any
// hook runs; `rd.break=<hook>` — comma-separated, repeatable — stops just
// before the named hook, matched on its hook path or its file name. On
// exit from the break shell the boot continues, so it is a breakpoint, not a
// failure.
#[derive(Default)]
struct Breakpoints {
    before_any: bool,
    hooks: Vec<String>,
}

impl Breakpoints {
    fn from_cmdline(cmdline: &str) -> Self {
        let mut b = Breakpoints::default();
        for tok in cmdline.split_whitespace() {
            if tok == "rd.break" {
                b.before_any = true;
            } else if let Some(v) = tok.strip_prefix("rd.break=") {
                b.hooks
                    .extend(v.split(',').filter(|s| !s.is_empty()).map(str::to_string));
            }
        }
        b
    }

    // Any breakpoint set — also what puts prelude in "shell on failure" mode.
    fn any(&self) -> bool {
        self.before_any || !self.hooks.is_empty()
    }

    // Whether to break just before running `hook` (a hook path). Matches
    // the full path or the bare file name, so rd.break=mount-root catches
    // /hooks/mount-root.
    fn breaks_before(&self, hook: &str) -> bool {
        let base = hook.rsplit('/').next().unwrap_or(hook);
        self.hooks.iter().any(|n| n == hook || n == base)
    }
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

// Every hook sequence present in the image, as (version, path). Version 0
// stands for the legacy unsuffixed /hooks.seq, which sorts below every
// numbered one — it is the oldest thing we can read.
fn find_hook_seqs() -> Vec<(u32, String)> {
    let mut found: Vec<(u32, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir(HOOK_SEQ_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(suffix) = name.strip_prefix(HOOK_SEQ_STEM) else {
                continue;
            };
            // A non-numeric suffix is not a version of anything; ignore it
            // rather than guess, and let the "nothing readable" path report
            // it if it was the only candidate.
            let Ok(version) = suffix.parse::<u32>() else {
                continue;
            };
            found.push((version, format!("{HOOK_SEQ_DIR}/{name}")));
        }
    }
    if fs::metadata(HOOK_SEQ_LEGACY).is_ok() {
        found.push((0, HOOK_SEQ_LEGACY.to_string()));
    }
    found.sort_by_key(|(version, _)| *version);
    found
}

// The sequence chosen from what the image offers, plus any newer one that
// was passed over.
#[derive(Debug)]
struct SeqChoice<'a> {
    version: u32,
    path: &'a str,
    // Set when a sequence newer than HOOK_SEQ_MAX exists alongside the one
    // chosen — the caller warns, since the boot is running a manifest the
    // image does not consider its newest.
    newer: Option<(u32, &'a str)>,
}

// Pick the highest-numbered sequence this prelude can parse.
//
// `found` must be sorted ascending by version. Errors describe the two ways
// there is nothing to run, and they are different failures: an image whose
// sequences are all from the future needs a newer prelude, while an image
// with no sequence at all was not built by any mkirf that writes them.
fn select_hook_seq(found: &[(u32, String)]) -> Result<SeqChoice<'_>, String> {
    let newest = found.last();
    let Some((version, path)) = found.iter().rev().find(|(v, _)| *v <= HOOK_SEQ_MAX) else {
        return Err(match newest {
            Some((newest, path)) => format!(
                "{path}: hook sequence version {newest} is newer than this prelude \
                 supports (max {HOOK_SEQ_MAX}), and no supported sequence is present"
            ),
            None => format!(
                "{HOOK_SEQ_DIR}/{HOOK_SEQ_STEM}*: no hook sequence to execute \
                 (mkirf writes one for every image, including a hookless one)"
            ),
        });
    };
    Ok(SeqChoice {
        version: *version,
        path,
        newer: newest
            .filter(|(v, _)| *v > HOOK_SEQ_MAX)
            .map(|(v, p)| (*v, p.as_str())),
    })
}

// Read the best hook sequence the image offers: the highest-numbered one
// this prelude can parse.
//
// mkirf emits a sequence unconditionally, including an empty one for an
// image with no hooks, so "no sequence at all" means something is wrong
// with the image rather than that there is nothing to do. That distinction
// matters: treating an absent file as "no hooks" would turn a
// misnamed or missing manifest into a boot that mounts no root and reports
// the failure far from its cause.
fn read_hook_seq() -> std::io::Result<Vec<String>> {
    let found = find_hook_seqs();
    let choice = select_hook_seq(&found).map_err(std::io::Error::other)?;
    let (version, path) = (choice.version, choice.path);

    // A newer sequence alongside a usable one is survivable — it just means
    // the image was built by an mkirf that knows more than we do — but say
    // so, because the boot is not running the manifest the image considers
    // authoritative.
    if let Some((newest, newest_path)) = choice.newer {
        log(&format!(
            "warning: {newest_path} is version {newest}, newer than this prelude \
             supports (max {HOOK_SEQ_MAX}); using {path}"
        ));
    }

    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    let marker = lines.next();

    // The name selects the file; the marker confirms it. They must agree.
    let expected = match version {
        0 | 1 => HOOK_SEQ_VERSION,
        2 => HOOK_SEQ_V2_VERSION,
        _ => unreachable!("filtered to <= HOOK_SEQ_MAX above"),
    };
    if marker != Some(expected) {
        return Err(std::io::Error::other(format!(
            "{path}: expected version marker {expected:?}, found {marker:?}"
        )));
    }

    log(&format!("hook sequence: {path}"));
    match version {
        0 | 1 => Ok(lines.filter(|l| !l.is_empty()).map(str::to_string).collect()),
        _ => parse_hook_seq_v2(path, lines),
    }
}

// Parse the version-2 body: one stanza per hook, in resolved order.
//
//     hook /hooks/topology.sh
//     contributes early-topology
//     hook /hooks/mount-root.sh
//     provides root-mounted
//     requires early-topology
//
// The declaration lines are validated but not yet acted on: this prelude
// runs the stanzas top to bottom, which is exactly what version 1 encoded.
// Scheduling from the declarations is a later change; parsing them strictly
// now means an image cannot carry a manifest we would misread then.
fn parse_hook_seq_v2<'a>(
    path: &str,
    lines: impl Iterator<Item = &'a str>,
) -> std::io::Result<Vec<String>> {
    let mut order: Vec<String> = Vec::new();
    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let lineno = i + 2; // the marker was line 1
        let (key, rest) = match line.split_once(' ') {
            Some((k, r)) => (k, r.trim()),
            None => (line, ""),
        };
        match key {
            "hook" => {
                if rest.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "{path}: line {lineno}: `hook` with no path"
                    )));
                }
                order.push(rest.to_string());
            }
            "provides" | "contributes" | "requires" | "after" => {
                if order.is_empty() {
                    return Err(std::io::Error::other(format!(
                        "{path}: line {lineno}: `{key}` before any `hook` line"
                    )));
                }
            }
            other => {
                return Err(std::io::Error::other(format!(
                    "{path}: line {lineno}: unknown key `{other}`"
                )))
            }
        }
    }
    Ok(order)
}

// Fork-exec one hook and wait for it. The hook is a script; the kernel
// honours its `#!/usr/bin/sh` shebang, which resolves through dash's sh claim.
// The hook runs with PATH=/usr/bin so it finds peiosutils and friends without
// depending on a root-level view that does not yet exist.
// A hook that does not exit 0 fails the boot.
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
        let path_env = cstr("PATH=/usr/bin");
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

// Drop to an interactive shell, returning to the caller when it exits. Used by
// the rd.shell (on failure) and rd.break (breakpoint) debug knobs. The kernel
// virtual filesystems are up by every call site, so the shell is usable. It is
// forked, not exec'd, so prelude stays PID 1 — a breakpoint resumes the boot on
// exit, and a failure shell lets prelude halt cleanly with no "killed init".
fn rescue_shell(reason: &str) {
    log(reason);
    let pid = unsafe { fork() };
    if pid < 0 {
        log(&format!(
            "rescue: fork failed: {}",
            std::io::Error::last_os_error()
        ));
        return;
    }
    if pid == 0 {
        let p = cstr(RESCUE_SHELL);
        let arg0 = cstr("sh");
        let interactive = cstr("-i");
        let argv: [*const u8; 3] = [
            arg0.as_ptr() as *const u8,
            interactive.as_ptr() as *const u8,
            core::ptr::null(),
        ];
        let term = cstr("TERM=linux");
        let path_env = cstr("PATH=/usr/bin");
        let envp: [*const u8; 3] = [
            term.as_ptr() as *const u8,
            path_env.as_ptr() as *const u8,
            core::ptr::null(),
        ];
        unsafe { execve(p.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr()) };
        log(&format!(
            "rescue: exec {RESCUE_SHELL} failed: {}",
            std::io::Error::last_os_error(),
        ));
        unsafe { _exit(127) };
    }
    let mut status: c_int = 0;
    if unsafe { waitpid(pid, &mut status, 0) } < 0 {
        log(&format!(
            "rescue: waitpid failed: {}",
            std::io::Error::last_os_error()
        ));
        return;
    }
    log("rescue shell exited");
}

// Run every hook the sequence lists, in order. Called before the
// real root is mounted; the kernel virtual filesystems are already up.
// `breaks` may pause before the first hook (bare rd.break) or before a named
// one (rd.break=<hook>), dropping to a shell that resumes on exit.
fn run_hooks(breaks: &Breakpoints) -> std::io::Result<()> {
    let hooks = read_hook_seq()?;
    if breaks.before_any {
        rescue_shell("rd.break: stopping before any hooks (exit to continue)");
    }
    if hooks.is_empty() {
        log("no hooks to run");
        return Ok(());
    }
    for hook in &hooks {
        if breaks.breaks_before(hook) {
            rescue_shell(&format!(
                "rd.break: stopping before hook {hook} (exit to continue)"
            ));
        }
        log(&format!("hook: {hook}"));
        run_one_hook(hook)?;
    }
    log(&format!("ran {} hook(s)", hooks.len()));
    Ok(())
}

// The real work. Returns only on failure — success exits via execve. A
// breakpoint (rd.break) pauses mid-hooks but then resumes, so it does not
// change that contract.
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
    do_mount(
        "proc",
        "/proc",
        Some("proc"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
    )?;
    do_mount(
        "sysfs",
        "/sys",
        Some("sysfs"),
        MS_NOSUID | MS_NOEXEC | MS_NODEV,
        None,
    )?;
    do_mount("devtmpfs", "/dev", Some("devtmpfs"), MS_NOSUID, None)?;

    banner();

    // Debug breakpoints: read the cmdline now that /proc is mounted. (main runs
    // before any mount, so /proc/cmdline is not readable there — only here on.)
    let breaks =
        Breakpoints::from_cmdline(&fs::read_to_string("/proc/cmdline").unwrap_or_default());

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
    run_hooks(&breaks)?;

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
        do_mount(&from, &to, None, MS_MOVE, None)
            .map_err(|e| std::io::Error::new(e.kind(), format!("mount-move {from}: {e}")))?;
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
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("chdir({SYSROOT}): {}", std::io::Error::last_os_error()),
            ));
        }
        log("pivot: chroot");
        if chroot(sysroot_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("chroot({SYSROOT}): {}", std::io::Error::last_os_error()),
            ));
        }
        log("pivot: chdir /");
        if chdir(slash_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("chdir(/): {}", std::io::Error::last_os_error()),
            ));
        }
    }

    // Phase 8: exec the real PID 1. Try cmdline init= first, then the
    // Peios package-storage fallback chain. Root-level runtime views are not
    // assumed to exist until the real init has started.
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
        log(&format!(
            "execve {path} failed: {}",
            std::io::Error::last_os_error()
        ));
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
        // rd.shell (or any rd.break) drops to a shell on failure instead of
        // halting. /proc is mounted by the time boot reaches a failure, so the
        // cmdline is readable here — it was not at process start, before any
        // mounts, which is why the read lives here and not in boot's caller.
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if cmdline_has(&cmdline, "rd.shell") || Breakpoints::from_cmdline(&cmdline).any() {
            rescue_shell(&format!("rd.shell: boot failed: {e} (exit to halt)"));
        }
    }
    halt();
}

#[cfg(test)]
mod tests {
    use super::{
        cmdline_has, parse_hook_seq_v2, select_hook_seq, wait_failure, Breakpoints,
        FALLBACK_INITS, RESCUE_SHELL,
    };

    /// Build the (version, path) list `select_hook_seq` expects: sorted
    /// ascending by version, as `find_hook_seqs` returns it.
    fn seqs(versions: &[u32]) -> Vec<(u32, String)> {
        let mut v: Vec<(u32, String)> = versions
            .iter()
            .map(|n| (*n, format!("/system/prelude/hooks.seq.{n}")))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0));
        v
    }

    // --- hook sequence selection -----------------------------------------

    #[test]
    fn the_highest_supported_version_wins() {
        let found = seqs(&[1, 2]);
        let c = select_hook_seq(&found).unwrap();
        assert_eq!(c.version, 2);
        assert!(c.newer.is_none());
    }

    #[test]
    fn the_legacy_unsuffixed_sequence_is_the_last_resort() {
        // Version 0 stands for /hooks.seq, which every numbered one outranks.
        let found = vec![(0, "/hooks.seq".to_string()), (1, "/system/prelude/hooks.seq.1".to_string())];
        assert_eq!(select_hook_seq(&found).unwrap().version, 1);

        let only_legacy = vec![(0, "/hooks.seq".to_string())];
        let c = select_hook_seq(&only_legacy).unwrap();
        assert_eq!(c.version, 0);
        assert_eq!(c.path, "/hooks.seq");
    }

    #[test]
    fn a_newer_sequence_beside_a_usable_one_is_reported_not_fatal() {
        let found = seqs(&[1, 2, 3]);
        let c = select_hook_seq(&found).unwrap();
        assert_eq!(c.version, 2);
        assert_eq!(c.newer.map(|(v, _)| v), Some(3));
    }

    #[test]
    fn only_newer_sequences_is_an_error_naming_the_version() {
        let found = seqs(&[3, 4]);
        let err = select_hook_seq(&found).unwrap_err();
        assert!(err.contains("newer than this prelude supports"), "{err}");
        assert!(err.contains('4'), "{err}");
    }

    #[test]
    fn no_sequence_at_all_is_an_error_not_an_empty_boot() {
        // mkirf writes a sequence for every image, so an absent one means a
        // broken image rather than "nothing to do". Booting on quietly would
        // mount no root and fail far from the cause.
        let err = select_hook_seq(&[]).unwrap_err();
        assert!(err.contains("no hook sequence to execute"), "{err}");
    }

    // --- version 2 parsing -----------------------------------------------

    #[test]
    fn v2_stanzas_yield_hook_paths_in_file_order() {
        let body = "hook /hooks/topology.sh\n\
                    contributes early-topology\n\
                    hook /hooks/mount-root.sh\n\
                    provides root-mounted\n\
                    requires early-topology\n\
                    after network-up\n";
        let order = parse_hook_seq_v2("t", body.lines()).unwrap();
        assert_eq!(order, ["/hooks/topology.sh", "/hooks/mount-root.sh"]);
    }

    #[test]
    fn v2_accepts_a_hook_with_no_declarations() {
        let order = parse_hook_seq_v2("t", "hook /hooks/a.sh\nhook /hooks/b.sh\n".lines()).unwrap();
        assert_eq!(order, ["/hooks/a.sh", "/hooks/b.sh"]);
    }

    #[test]
    fn v2_rejects_a_declaration_before_any_hook() {
        let err = parse_hook_seq_v2("t", "provides x\n".lines()).unwrap_err();
        assert!(err.to_string().contains("before any `hook` line"), "{err}");
    }

    #[test]
    fn v2_rejects_an_unknown_key() {
        let err = parse_hook_seq_v2("t", "hook /hooks/a.sh\nprovydes x\n".lines()).unwrap_err();
        assert!(err.to_string().contains("unknown key"), "{err}");
    }

    #[test]
    fn v2_rejects_a_hook_line_with_no_path() {
        let err = parse_hook_seq_v2("t", "hook\n".lines()).unwrap_err();
        assert!(err.to_string().contains("no path"), "{err}");
    }

    #[test]
    fn v2_reports_the_line_number_counting_the_marker() {
        // The marker is consumed before parsing, so line numbers have to be
        // offset by one or every error points at the wrong line.
        let err = parse_hook_seq_v2("t", "hook /hooks/a.sh\nbogus x\n".lines()).unwrap_err();
        assert!(err.to_string().contains("line 3"), "{err}");
    }

    #[test]
    fn target_inits_use_runtime_views_but_initramfs_rescue_does_not() {
        assert_eq!(FALLBACK_INITS.first(), Some(&"/bin/peinit2"));
        assert_eq!(RESCUE_SHELL, "/usr/bin/sh");
        assert!(
            FALLBACK_INITS
                .iter()
                .all(|path| path.starts_with("/bin/") || path.starts_with("/sbin/")),
            "target init paths must execute through the real root's runtime views: {FALLBACK_INITS:?}"
        );
    }

    #[test]
    fn cmdline_has_matches_bare_token_only() {
        assert!(cmdline_has("console=ttyS0 rd.shell panic=-1", "rd.shell"));
        assert!(!cmdline_has("console=ttyS0 panic=-1", "rd.shell"));
        // a value form is not a bare flag
        assert!(!cmdline_has("rd.shell=1", "rd.shell"));
    }

    #[test]
    fn bare_rd_break_stops_before_any_hook() {
        let b = Breakpoints::from_cmdline("quiet rd.break ro");
        assert!(b.before_any);
        assert!(b.hooks.is_empty());
        assert!(b.any());
    }

    #[test]
    fn named_rd_break_collects_comma_separated_hooks() {
        let b = Breakpoints::from_cmdline("rd.break=mount-root,pre-pivot rd.break=cleanup");
        assert!(!b.before_any);
        assert_eq!(b.hooks, ["mount-root", "pre-pivot", "cleanup"]);
    }

    #[test]
    fn breaks_before_matches_path_or_basename() {
        let b = Breakpoints::from_cmdline("rd.break=mount-root");
        assert!(b.breaks_before("/hooks/mount-root")); // by basename
        assert!(b.breaks_before("mount-root")); // by full id
        assert!(!b.breaks_before("/hooks/other"));
    }

    #[test]
    fn no_break_directive_is_inert() {
        let b = Breakpoints::from_cmdline("console=ttyS0 panic=-1");
        assert!(!b.any());
        assert!(!b.breaks_before("/hooks/anything"));
    }

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
