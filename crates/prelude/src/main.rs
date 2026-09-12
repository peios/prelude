// prelude
//
// Peios initramfs PID 1. Boot pipeline:
//   - mount the kernel virtual filesystems
//   - run the initramfs hooks, in the order mkirf baked into the hook
//     sequence under /system/prelude
//   - check a hook has mounted the real root at /mnt/rootfs
//   - chroot into it and exec the real PID 1
//
// prelude is the invariant skeleton; everything deployment-specific is a
// hook. Mounting the real root is a hook's job — prelude only provides
// the /mnt/rootfs mountpoint and verifies the result. It does not resolve
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
use std::sync::atomic::{AtomicBool, Ordering};

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
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
}

// waitpid: also return for a child that STOPPED rather than terminated.
// Without it a stopped child is not a wait event at all and the caller blocks.
const WUNTRACED: c_int = 2;
const SIGKILL: c_int = 9;

const RB_HALT_SYSTEM: c_int = 0xcdef0123u32 as c_int;
// errno 39 — a directory that still holds entries. Expected when those entries
// are mounts the cleanup walk deliberately preserved.
const ENOTEMPTY: i32 = 39;
// Where a hook mounts the real root, and what prelude chroots into.
//
// Under /mnt because that is where the layout puts transient mounts. The
// initramfs root previously carried /sysroot, /sysroot.lower, /sysroot.rw and
// /medium as top-level directories, which is namespace pollution in a root
// that exists for two seconds and has a layout of its own.
const ROOTFS: &str = "/mnt/rootfs";
const FALLBACK_INITS: &[&str] = &["/bin/peinit2", "/sbin/init", "/bin/init", "/bin/sh"];

// The debug shell prelude drops to under rd.shell / rd.break. dash claims
// /usr/bin/sh. The initramfs has no /bin view before its hooks mount runtime
// topology, so exec package storage directly; PID 1 also carries no PATH.
const RESCUE_SHELL: &str = "/usr/bin/sh";

// The seeding helper that ships beside prelude in the same package. Exec'd by
// absolute path for the same reason as the rescue shell: no views, no PATH.
const SEED_SD: &str = "/usr/bin/seed-sd";

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

// What a hook's exit status means. A hook is a shell script, so its exit
// code is the only channel it has, and two outcomes beyond success/failure
// need saying.
//
// The values are borrowed from sysexits.h rather than invented, for the
// practical reason that 0-2 are what any failing command returns and
// 126/127/128+n are the shell's own, so a small dedicated range is the only
// place a deliberate signal cannot be confused with an accident.
//
//   EX_UNAVAILABLE  "not applicable on this machine" — the hook declines,
//                   and is not counted toward the capabilities it declared.
//   EX_TEMPFAIL     "not yet" — the hook's inputs are not ready, it has done
//                   NOTHING, and prelude should try it again later.
//
// The distinction between DECLINED and DEFERRED and plain failure is what
// makes re-running safe: a deferring hook contracts to have made no change,
// which is exactly the guarantee a failed hook cannot give.
const HOOK_DECLINED: i32 = 69;
const HOOK_DEFERRED: i32 = 75;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// The hook did its part. Its `provides` are achieved; its
    /// `contributes` are one step closer to complete.
    Satisfied,
    /// The hook had nothing to do here. For an alternative (`provides`) it
    /// abstains and some other provider must satisfy the capability; for a
    /// conjunction (`contributes`) it completes trivially, because "nothing
    /// needed doing" is a way of being done.
    Declined,
    /// The hook cannot run yet and has changed nothing. Re-queued.
    Deferred,
}

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

// Re-seed /dev with the bootstrap SD, recursively, the moment devtmpfs is
// mounted.
//
// The kernel stamps the devtmpfs root SYSTEM-only at init (devtmpfs_init, see
// pkm's devtmpfs-seed-root-sd.patch). That is plumbing, not policy: it exists
// so kdevtmpfs can create nodes at all under DENY_MISSING, and SYSTEM-only is
// the right descriptor for that one job. But every node kdevtmpfs has created
// since inherited that single ACE, so on an unseeded /dev an administrator
// cannot list the directory, open /dev/null, or touch the disk the installer
// is about to format (PEI-208). Policy belongs in userspace, where "seed the
// tree, then re-stamp the exceptions" is cheap; in the kernel it is nuanced
// machinery in a high-risk place.
//
// seed-sd -r stamps the root and every existing node with the same descriptor
// it puts on a fresh tmpfs root (SYSTEM and Administrators, GenericAll,
// inheritable), so nodes that appear later — hot-plug, partitions rescanned
// after `part` writes a table — inherit the same thing. That root descriptor
// is deliberately conservative: whatever it grants, a raw disk nobody has met
// yet also grants. The permissive exceptions (/dev/null and its kin, writable
// by everyone) are per-node policy and are peinit's to stamp, not prelude's.
//
// Failure is logged and the boot continues. A SYSTEM-only /dev is a degraded
// system, not an unbootable one — the recovery console still works there —
// and refusing to boot over it would turn a permissions defect into an outage.
fn seed_dev() {
    match spawn_and_wait(SEED_SD, &["-r", "/dev"]) {
        Ok(status) if (status >> 8) & 0xff == 0 => log_ok("seeded /dev"),
        Ok(status) => log_err(&format!(
            "seed-sd -r /dev exited with status {}; /dev stays SYSTEM-only for nodes it could not stamp",
            (status >> 8) & 0xff
        )),
        Err(e) => log_err(&format!("seed /dev: {e}; /dev stays SYSTEM-only")),
    }
}

// ---------------------------------------------------------------------------
// The console line format
//
// Shared with peinit by SPECIFICATION, not by code. prelude is a size-critical
// initramfs PID 1 with zero dependencies, and the only crate it could share
// with peinit (peios-rs) binds libpeios over FFI — coupling the initramfs PID 1
// to the kernel-boundary library to save forty lines of string formatting is a
// bad trade. The format is documented in the docs tree; these forty lines are
// prelude's implementation of it, and peinit's `console_style` is peinit's.
//
// Keep the two in step: the tag words, the field width and the banner width are
// the contract, and a hook script rendering a third copy is held to it too.
// ---------------------------------------------------------------------------

/// Width of the tag field between the brackets.
const TAG_WIDTH: usize = 6;
/// Total banner width, including the two leading spaces. Fits inside 80
/// columns, which is what both a VT and a serial console give you.
const BANNER_WIDTH: usize = 64;

/// What happened, as far as the console is concerned.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    /// Progress with no outcome yet. An empty bracket: it holds the column
    /// while receding, so OK and FAILED are what catch the eye.
    None,
    /// It worked. The verb should agree — "mounted /bin", never "mounting".
    Ok,
    /// Something is wrong but the boot continues.
    Warn,
    /// Something did not work.
    Failed,
}

impl Tag {
    fn word(self) -> &'static str {
        match self {
            Tag::None => "",
            Tag::Ok => "OK",
            Tag::Warn => "WARN",
            Tag::Failed => "FAILED",
        }
    }

    fn sgr(self) -> Option<&'static str> {
        match self {
            Tag::None => None,
            Tag::Ok => Some("1;32"),
            Tag::Warn => Some("1;33"),
            Tag::Failed => Some("1;31"),
        }
    }
}

/// Whether to emit SGR escapes. systemd's rule: colour unless the terminal is
/// declared dumb. prelude has no inherited TERM (it is PID 1), so the kernel
/// command line is the only place an operator can say so.
static COLOUR: AtomicBool = AtomicBool::new(true);

fn init_colour(cmdline: &str) {
    let dumb = cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("TERM="))
        .next_back()
        .is_some_and(|value| value == "dumb");
    COLOUR.store(!dumb, Ordering::Relaxed);
}

fn render(tag: Tag, component: &str, message: &str) -> String {
    render_with(tag, component, message, COLOUR.load(Ordering::Relaxed))
}

/// The renderer proper, colour passed in so the layout is testable without a
/// process-wide flag that parallel tests would race on.
fn render_with(tag: Tag, component: &str, message: &str, colour: bool) -> String {
    let word = tag.word();
    let spare = TAG_WIDTH.saturating_sub(word.len());
    let left = spare / 2;
    let right = spare - left;
    let tagged = match (colour, tag.sgr()) {
        (true, Some(sgr)) => format!("\x1b[{sgr}m{word}\x1b[0m"),
        _ => word.to_string(),
    };
    format!(
        "[{}{}{}] {component}: {message}",
        " ".repeat(left),
        tagged,
        " ".repeat(right)
    )
}

/// The stage banner: punctuation between one PID 1 and the next.
///
/// prelude's says the initramfs is in charge; peinit prints the matching one
/// when the real root takes over. Same width and same shape, so the two read as
/// a sequence rather than as two unrelated decorations.
fn banner() {
    // Status, not news: the banner is the first thing a blackout should remove.
    if BLACKOUT.load(Ordering::Relaxed) {
        return;
    }
    let text = banner_text(
        "prelude · initramfs · PID 1",
        concat!("v", env!("CARGO_PKG_VERSION")),
        COLOUR.load(Ordering::Relaxed),
    );
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(text.as_bytes());
    let _ = out.flush();
}

fn banner_text(stage: &str, version: &str, colour: bool) -> String {
    let rule = "═".repeat(BANNER_WIDTH - 2);
    // Character count, not byte length: the rule and the separator are both
    // multi-byte.
    let used = 3 + stage.chars().count() + version.chars().count();
    let gap = " ".repeat(BANNER_WIDTH.saturating_sub(used).max(1));
    if colour {
        format!(
            "\n  \x1b[2m{rule}\x1b[0m\n   \x1b[1m{stage}\x1b[0m{gap}\x1b[2m{version}\x1b[0m\n  \x1b[2m{rule}\x1b[0m\n\n"
        )
    } else {
        format!("\n  {rule}\n   {stage}{gap}{version}\n  {rule}\n\n")
    }
}

/// `peios.quiet=2` — the console blackout, honoured here because prelude writes
/// to the same console peinit does and a half-silenced boot is not silence.
///
/// Only level 2 reaches prelude. The other half of the policy — staying out of
/// a terminal a service owns — has no meaning before any service exists, and
/// prelude exits before the first one starts.
static BLACKOUT: AtomicBool = AtomicBool::new(false);

/// Read the blackout preference. Must be called once /proc is mounted; before
/// that the cmdline is unreadable and prelude logs unconditionally, which is
/// the right default for output that would otherwise be lost.
fn init_quiet(cmdline: &str) {
    let blackout = cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("peios.quiet="))
        .next_back()
        .is_some_and(|value| value == "2");
    BLACKOUT.store(blackout, Ordering::Relaxed);
}

/// Ordinary progress with no outcome yet. Silenced by `peios.quiet=2`.
fn log(msg: &str) {
    log_tagged(Tag::None, msg);
}

/// Something worked. Silenced by `peios.quiet=2` exactly as [`log`] is: a
/// success is progress, and the tag is presentation rather than news.
fn log_ok(msg: &str) {
    log_tagged(Tag::Ok, msg);
}

fn log_tagged(tag: Tag, msg: &str) {
    if BLACKOUT.load(Ordering::Relaxed) {
        return;
    }
    eprint!("{}", render(tag, "prelude", &format!("{msg}\n")));
}

/// Something is wrong but the boot continues. Never silenced, like [`log_err`].
fn log_warn(msg: &str) {
    eprint!("{}", render(Tag::Warn, "prelude", &format!("{msg}\n")));
}

/// Something went wrong. Never silenced: a blackout is a preference about
/// noise, not an instruction to hide a failure — and prelude's failures cost
/// the boot.
fn log_err(msg: &str) {
    eprint!("{}", render(Tag::Failed, "prelude", &format!("{msg}\n")));
}

// Returns the init= value from /proc/cmdline if present.
//
// The LAST occurrence wins, as it does for every repeated kernel parameter and
// for the two other knobs prelude reads (`peios.quiet=` and `TERM=`). Appending
// is how a boot parameter is overridden — by a bootloader entry, a UKI addon, a
// test harness, or an operator typing at the boot prompt — so an appended
// `init=/bin/sh` on a line that already names one has to be the one that counts.
//
// An empty value is filtered out before the last is taken, so `init=` on its own
// remains no value at all: `init=/bin/sh init=` uses /bin/sh.
fn cmdline_init() -> Option<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline_init_from(&cmdline)
}

// The parser proper, taking the command line as an argument so it is testable
// without /proc.
fn cmdline_init_from(cmdline: &str) -> Option<String> {
    cmdline
        .split_whitespace()
        .filter_map(|tok| tok.strip_prefix("init="))
        .filter(|v| !v.is_empty())
        .next_back()
        .map(str::to_string)
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
// /proc, /sys, /dev, and /mnt/rootfs survive the walk. `path` itself is not
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
                log_warn(&format!("cleanup: descend {} failed: {e}", p.display()));
            }
            // ENOTEMPTY here is the expected outcome for a directory whose
            // contents are all preserved mounts — /mnt holds the rootfs
            // overlay, the medium and the overlay's two layers, every one of
            // them skipped above for being on another device. The parent of a
            // mount we are deliberately keeping cannot be removed, and saying
            // so on every boot reads like a fault.
            //
            // Any other errno still gets reported. A directory left non-empty
            // by a failed unlink reaches here too, but that unlink logged its
            // own error, so the cause is not lost by staying quiet about the
            // consequence.
            match fs::remove_dir(&p) {
                Ok(()) => {}
                Err(e) if e.raw_os_error() == Some(ENOTEMPTY) => {}
                Err(e) => log_warn(&format!("cleanup: rmdir {} failed: {e}", p.display())),
            }
        } else if let Err(e) = fs::remove_file(&p) {
            log_warn(&format!("cleanup: unlink {} failed: {e}", p.display()));
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

// One hook as the sequence describes it: where it lives, and what it says
// about its own ordering. A version-1 sequence yields these with every
// declaration empty — that format carries an order and nothing else, so
// every hook is immediately ready and they run exactly as listed.
#[derive(Debug, Default, Clone)]
struct SeqHook {
    path: String,
    provides: Vec<String>,
    contributes: Vec<String>,
    requires: Vec<String>,
    after: Vec<String>,
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
fn read_hook_seq() -> std::io::Result<Vec<SeqHook>> {
    let found = find_hook_seqs();
    let choice = select_hook_seq(&found).map_err(std::io::Error::other)?;
    let (version, path) = (choice.version, choice.path);

    // A newer sequence alongside a usable one is survivable — it just means
    // the image was built by an mkirf that knows more than we do — but say
    // so, because the boot is not running the manifest the image considers
    // authoritative.
    // log_warn, not log: this carries the `[ WARN ]` tag every other prelude
    // warning carries, and survives the `peios.quiet=2` blackout. Production
    // images boot quiet, and a blackout is a preference about noise rather than
    // an instruction to hide the fact that the boot is not running the manifest
    // the image considers authoritative.
    if let Some((newest, newest_path)) = choice.newer {
        log_warn(&format!(
            "{newest_path} is version {newest}, newer than this prelude \
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
        0 | 1 => Ok(lines
            .filter(|l| !l.is_empty())
            .map(|l| SeqHook {
                path: l.to_string(),
                ..SeqHook::default()
            })
            .collect()),
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
) -> std::io::Result<Vec<SeqHook>> {
    let mut hooks: Vec<SeqHook> = Vec::new();
    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let lineno = i + 2; // the marker was line 1
        let (key, rest) = match line.split_once(' ') {
            Some((k, r)) => (k, r.trim()),
            None => (line, ""),
        };
        if key == "hook" {
            if rest.is_empty() {
                return Err(std::io::Error::other(format!(
                    "{path}: line {lineno}: `hook` with no path"
                )));
            }
            hooks.push(SeqHook {
                path: rest.to_string(),
                ..SeqHook::default()
            });
            continue;
        }
        let Some(open) = hooks.last_mut() else {
            return Err(std::io::Error::other(format!(
                "{path}: line {lineno}: `{key}` before any `hook` line"
            )));
        };
        let slot = match key {
            "provides" => &mut open.provides,
            "contributes" => &mut open.contributes,
            "requires" => &mut open.requires,
            "after" => &mut open.after,
            other => {
                return Err(std::io::Error::other(format!(
                    "{path}: line {lineno}: unknown key `{other}`"
                )))
            }
        };
        slot.extend(rest.split_whitespace().map(str::to_string));
    }
    Ok(hooks)
}

// Fork-exec `path` with `args` and wait for it. The child gets the same
// minimal environment every hook gets: TERM, and PATH=/usr/bin so it finds
// peiosutils and friends without depending on a root-level view that does not
// yet exist. Returns the raw wait status; callers interpret the exit code.
//
// A signal or a stop is surfaced as an error whatever the code would have
// been — a child killed mid-write has not "declined" anything.
fn spawn_and_wait(path: &str, args: &[&str]) -> std::io::Result<c_int> {
    let pid = unsafe { fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        // Child: exec and never fall back into prelude's pipeline.
        let p = cstr(path);
        let arg_cs: Vec<_> = args.iter().map(|a| cstr(a)).collect();
        let mut argv: Vec<*const u8> = Vec::with_capacity(args.len() + 2);
        argv.push(p.as_ptr() as *const u8);
        argv.extend(arg_cs.iter().map(|c| c.as_ptr() as *const u8));
        argv.push(core::ptr::null());
        let term = cstr("TERM=linux");
        let path_env = cstr("PATH=/usr/bin");
        let envp: [*const u8; 3] = [
            term.as_ptr() as *const u8,
            path_env.as_ptr() as *const u8,
            core::ptr::null(),
        ];
        unsafe { execve(p.as_ptr() as *const u8, argv.as_ptr(), envp.as_ptr()) };
        log(&format!(
            "{path}: exec failed: {}",
            std::io::Error::last_os_error(),
        ));
        unsafe { _exit(127) };
    }
    let mut status: c_int = 0;
    // WUNTRACED, so a child that STOPS is a wait event rather than silence.
    // Without it `waitpid` returns only on termination, and a hook that takes a
    // job-control stop leaves prelude blocked with nothing in the initramfs
    // able to resume it: no job control, no other process, no timeout.
    if unsafe { waitpid(pid, &mut status, WUNTRACED) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if status & 0x7f == 0x7f {
        // The child is stopped, not gone. Nothing will ever send it SIGCONT, so
        // kill it and reap it here rather than carry a stopped process — and a
        // zombie after it — into the new root's namespace.
        unsafe { kill(pid, SIGKILL) };
        let mut reaped: c_int = 0;
        unsafe { waitpid(pid, &mut reaped, 0) };
    }
    if status & 0x7f != 0 {
        let reason = wait_failure(status).unwrap_or_else(|| "terminated abnormally".to_string());
        return Err(std::io::Error::other(format!("{path}: {reason}")));
    }
    Ok(status)
}

// Run one hook and wait for it. The hook is a script; the kernel honours its
// `#!/usr/bin/sh` shebang, which resolves through dash's sh claim.
// A hook that does not exit 0 fails the boot.
fn run_one_hook(path: &str) -> std::io::Result<Outcome> {
    let status = spawn_and_wait(path, &[])
        .map_err(|e| std::io::Error::new(e.kind(), format!("hook {e}")))?;
    match (status >> 8) & 0xff {
        0 => Ok(Outcome::Satisfied),
        HOOK_DECLINED => Ok(Outcome::Declined),
        HOOK_DEFERRED => Ok(Outcome::Deferred),
        code => Err(std::io::Error::other(format!(
            "hook {path}: exited with status {code}"
        ))),
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
    schedule_hooks(&hooks, breaks, run_one_hook)
}

// Whether every supplier of `cap` has finished — nothing that could still
// contribute to it is outstanding.
//
// This is what `after` waits on. A capability nothing supplies is settled
// vacuously, which is exactly what makes `after` safe to name against a
// milestone this image does not have.
fn cap_settled(hooks: &[SeqHook], state: &[Option<Outcome>], cap: &str) -> bool {
    hooks
        .iter()
        .zip(state)
        .filter(|(h, _)| h.provides.iter().chain(&h.contributes).any(|c| c == cap))
        .all(|(_, s)| matches!(s, Some(Outcome::Satisfied) | Some(Outcome::Declined)))
}

// Whether `cap` has actually been achieved, which is stricter than settled
// and is what `requires` waits on.
//
// The two supply kinds answer it differently, and the difference IS the
// distinction between them:
//
//   provides     alternatives. Achieved once ANY provider is satisfied. If
//                every provider declined, the capability is settled and
//                never achieved — nobody was willing to be the one.
//   contributes  a conjunction. Achieved once every contributor has
//                finished, whether by doing its part or by declining,
//                since "nothing needed doing here" is a way of being done.
fn cap_achieved(hooks: &[SeqHook], state: &[Option<Outcome>], cap: &str) -> bool {
    if !cap_settled(hooks, state, cap) {
        return false;
    }
    let provided = hooks.iter().any(|h| h.provides.iter().any(|c| c == cap));
    if !provided {
        return true;
    }
    hooks
        .iter()
        .zip(state)
        .any(|(h, s)| h.provides.iter().any(|c| c == cap) && *s == Some(Outcome::Satisfied))
}

// Whether hook `i` can run now.
fn hook_ready(hooks: &[SeqHook], state: &[Option<Outcome>], i: usize) -> bool {
    let h = &hooks[i];
    h.requires.iter().all(|c| cap_achieved(hooks, state, c))
        && h.after.iter().all(|c| cap_settled(hooks, state, c))
}

// Why the boot cannot continue, named hook by hook. Called only when a pass
// completed nothing and work remains, so every message here describes a
// genuine dead end rather than a hook that is merely waiting its turn.
fn stuck_reason(hooks: &[SeqHook], state: &[Option<Outcome>]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (i, h) in hooks.iter().enumerate() {
        if matches!(state[i], Some(Outcome::Satisfied) | Some(Outcome::Declined)) {
            continue;
        }
        let mut why: Vec<String> = Vec::new();
        for cap in &h.requires {
            if cap_settled(hooks, state, cap) {
                if !cap_achieved(hooks, state, cap) {
                    why.push(format!("`{cap}` — every provider declined it"));
                }
            } else {
                why.push(format!("`{cap}` — not achieved"));
            }
        }
        for cap in &h.after {
            if !cap_settled(hooks, state, cap) {
                why.push(format!("`{cap}` — not settled"));
            }
        }
        if why.is_empty() {
            // Ready every time it was tried, and deferred every time.
            why.push("deferred with nothing left to wait for".to_string());
        }
        lines.push(format!("  {}: {}", h.path, why.join("; ")));
    }
    format!("hooks cannot proceed:\n{}", lines.join("\n"))
}

// Run the hooks, scheduling from their declarations rather than replaying a
// fixed list.
//
// Repeated passes in sequence order, running whatever is ready. A hook that
// DEFERS is left pending and tried again on a later pass; only a terminal
// outcome counts as progress. A pass that completes nothing while work
// remains is a dead end, not a reason to keep spinning.
//
// Worst case is O(n²) runs, and that is affordable precisely because
// deferral means the hook did nothing: re-running it is free in a way that
// re-running a FAILED hook could never be, since a failure may have left a
// half-assembled array or burned an unlock attempt behind it.
//
// The runner is a parameter so the scheduling can be tested without forking
// anything.
fn schedule_hooks(
    hooks: &[SeqHook],
    breaks: &Breakpoints,
    mut run: impl FnMut(&str) -> std::io::Result<Outcome>,
) -> std::io::Result<()> {
    let mut state: Vec<Option<Outcome>> = vec![None; hooks.len()];
    let mut ran = 0usize;

    loop {
        let mut progressed = false;
        for i in 0..hooks.len() {
            if matches!(state[i], Some(Outcome::Satisfied) | Some(Outcome::Declined)) {
                continue;
            }
            if !hook_ready(hooks, &state, i) {
                continue;
            }
            let path = &hooks[i].path;
            if breaks.breaks_before(path) {
                rescue_shell(&format!(
                    "rd.break: stopping before hook {path} (exit to continue)"
                ));
            }
            log(&format!("hook: {path}"));
            let outcome = run(path)?;
            ran += 1;
            match outcome {
                Outcome::Satisfied => progressed = true,
                Outcome::Declined => {
                    log(&format!("hook {path}: declined (not applicable here)"));
                    progressed = true;
                }
                Outcome::Deferred => log(&format!("hook {path}: deferred (will retry)")),
            }
            state[i] = Some(outcome);
        }

        if state
            .iter()
            .all(|s| matches!(s, Some(Outcome::Satisfied) | Some(Outcome::Declined)))
        {
            log_ok(&format!("ran {ran} hook invocation(s)"));
            return Ok(());
        }
        if !progressed {
            return Err(std::io::Error::other(stuck_reason(hooks, &state)));
        }
    }
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
    seed_dev();

    // The cmdline becomes readable here and not before — main runs ahead of any
    // mount. Quiet is read first so the banner and everything after it can
    // honour it; the handful of lines before this point are unconditional
    // because prelude cannot obey a preference it has not read.
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    init_quiet(&cmdline);
    init_colour(&cmdline);

    banner();

    // Debug breakpoints, from the same read.
    let breaks = Breakpoints::from_cmdline(&cmdline);

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
    // are up — a hook may need them. prelude provides an empty /mnt/rootfs
    // mountpoint; mounting a real root onto it is a hook's job (the root
    // filesystem varies by deployment, so it is never hardcoded here).
    // mkirf resolved the hook order at build time; we just run the list.
    // /mnt may not exist in an initramfs whose base filesystem predates it.
    try_mkdir("/mnt");
    try_mkdir(ROOTFS);
    run_hooks(&breaks)?;

    // Phase 4: a hook must have mounted the real root at /mnt/rootfs. If it
    // is still on the initramfs's own device, nothing mounted it.
    if fs::metadata(ROOTFS)?.dev() == fs::metadata("/")?.dev() {
        return Err(std::io::Error::other(format!(
            "no hook mounted a root filesystem at {ROOTFS}"
        )));
    }
    log_ok(&format!("root mounted at {ROOTFS}"));

    // Phase 5: move kernel vfs into the new root so the new PID 1 has them.
    // The squashfs is RO and must ship /proc, /sys, /dev as empty
    // mountpoint dirs — build-staging.sh creates them.
    for sub in &["proc", "sys", "dev"] {
        let from = format!("/{sub}");
        let to = format!("{ROOTFS}/{sub}");
        log(&format!("mount-move {from} -> {to}"));
        do_mount(&from, &to, None, MS_MOVE, None)
            .map_err(|e| std::io::Error::new(e.kind(), format!("mount-move {from}: {e}")))?;
    }

    // Phase 6: cleanup the old rootfs. Walks rootfs's st_dev only; the
    // moved mounts and /mnt/rootfs all have different st_devs and stay put.
    let root_dev = fs::metadata("/")?.dev();
    if let Err(e) = cleanup_old_root(root_dev, Path::new("/")) {
        log_warn(&format!("cleanup: {e} (continuing)"));
    }

    // Phase 7: chroot into the new root. We don't mount-move the squashfs
    // over the rootfs (`mount(".", "/", MS_MOVE)`) because the kernel
    // disallows moving onto the rootfs. pivot_root has the same constraint.
    // chroot is sufficient for now: PID 1 and all descendants see the
    // squashfs as /. The kernel's "real" rootfs is unreachable but still
    // exists as a namespace bookkeeping artifact (empty after phase 6).
    log("pivot: chdir rootfs");
    let rootfs_c = cstr(ROOTFS);
    let slash_c = cstr("/");
    unsafe {
        if chdir(rootfs_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("chdir({ROOTFS}): {}", std::io::Error::last_os_error()),
            ));
        }
        log("pivot: chroot");
        if chroot(rootfs_c.as_ptr() as *const u8) != 0 {
            return Err(std::io::Error::new(
                std::io::Error::last_os_error().kind(),
                format!("chroot({ROOTFS}): {}", std::io::Error::last_os_error()),
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
        log_err(&format!("boot failed: {e}"));
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
        cmdline_has, cmdline_init_from, parse_hook_seq_v2, schedule_hooks, select_hook_seq,
        wait_failure, Breakpoints, Outcome, SeqHook, FALLBACK_INITS, RESCUE_SHELL,
    };
    use std::cell::RefCell;

    fn paths(hooks: &[SeqHook]) -> Vec<&str> {
        hooks.iter().map(|h| h.path.as_str()).collect()
    }

    /// A hook declaring the four keys, for scheduler tests.
    fn h(
        path: &str,
        provides: &[&str],
        contributes: &[&str],
        requires: &[&str],
        after: &[&str],
    ) -> SeqHook {
        let own = |v: &[&str]| v.iter().map(|s| s.to_string()).collect();
        SeqHook {
            path: path.to_string(),
            provides: own(provides),
            contributes: own(contributes),
            requires: own(requires),
            after: own(after),
        }
    }

    /// Run the scheduler against scripted outcomes, returning the order in
    /// which hooks were actually invoked (repeats included, so deferral is
    /// visible).
    ///
    /// `script` maps a hook path to the outcomes it returns on successive
    /// invocations; the last entry repeats once exhausted.
    fn drive(
        hooks: &[SeqHook],
        script: &[(&str, &[Outcome])],
    ) -> (std::io::Result<()>, Vec<String>) {
        let calls = RefCell::new(Vec::<String>::new());
        let result = schedule_hooks(hooks, &Breakpoints::default(), |path| {
            let mut calls = calls.borrow_mut();
            let n = calls.iter().filter(|c| *c == path).count();
            calls.push(path.to_string());
            let outcomes = script
                .iter()
                .find(|(p, _)| *p == path)
                .map(|(_, o)| *o)
                .unwrap_or(&[Outcome::Satisfied]);
            Ok(outcomes[n.min(outcomes.len() - 1)])
        });
        let calls = calls.into_inner();
        (result, calls)
    }

    // --- the scheduler ---------------------------------------------------

    #[test]
    fn a_sequence_with_no_declarations_runs_in_order() {
        // What a version-1 sequence yields: no edges, so the listed order is
        // the order, and nothing about the scheduler may disturb it.
        let hooks = vec![
            h("/hooks/a.sh", &[], &[], &[], &[]),
            h("/hooks/b.sh", &[], &[], &[], &[]),
            h("/hooks/c.sh", &[], &[], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[]);
        assert!(r.is_ok());
        assert_eq!(calls, ["/hooks/a.sh", "/hooks/b.sh", "/hooks/c.sh"]);
    }

    #[test]
    fn a_requirer_waits_for_its_provider_despite_sequence_position() {
        let hooks = vec![
            h("/hooks/consumer.sh", &[], &[], &["cap"], &[]),
            h("/hooks/provider.sh", &["cap"], &[], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[]);
        assert!(r.is_ok());
        assert_eq!(calls, ["/hooks/provider.sh", "/hooks/consumer.sh"]);
    }

    #[test]
    fn every_contributor_runs_before_the_capability_is_achieved() {
        let hooks = vec![
            h("/hooks/consumer.sh", &[], &[], &["cap"], &[]),
            h("/hooks/part-a.sh", &[], &["cap"], &[], &[]),
            h("/hooks/part-b.sh", &[], &["cap"], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[]);
        assert!(r.is_ok());
        assert_eq!(
            calls,
            ["/hooks/part-a.sh", "/hooks/part-b.sh", "/hooks/consumer.sh"]
        );
    }

    #[test]
    fn one_satisfied_alternative_is_enough() {
        // live-boot/disk-boot: both provide the capability, one declines.
        let hooks = vec![
            h("/hooks/live.sh", &["root-mounted"], &[], &[], &[]),
            h("/hooks/disk.sh", &["root-mounted"], &[], &[], &[]),
            h("/hooks/after.sh", &[], &[], &["root-mounted"], &[]),
        ];
        let (r, calls) = drive(&hooks, &[("/hooks/disk.sh", &[Outcome::Declined])]);
        assert!(r.is_ok(), "{:?}", r.err());
        assert_eq!(calls.last().unwrap(), "/hooks/after.sh");
    }

    #[test]
    fn every_alternative_declining_is_a_named_failure() {
        // The case that currently surfaces as prelude's vague "nothing
        // mounted /mnt/rootfs": no hook was willing to be the one.
        let hooks = vec![
            h("/hooks/live.sh", &["root-mounted"], &[], &[], &[]),
            h("/hooks/disk.sh", &["root-mounted"], &[], &[], &[]),
            h("/hooks/after.sh", &[], &[], &["root-mounted"], &[]),
        ];
        let (r, _) = drive(
            &hooks,
            &[
                ("/hooks/live.sh", &[Outcome::Declined]),
                ("/hooks/disk.sh", &[Outcome::Declined]),
            ],
        );
        let err = r.unwrap_err().to_string();
        assert!(err.contains("every provider declined"), "{err}");
        assert!(err.contains("root-mounted"), "{err}");
        assert!(err.contains("/hooks/after.sh"), "{err}");
    }

    #[test]
    fn a_declining_contributor_still_completes_the_conjunction() {
        // "Nothing needed doing here" is a way of being done — unlike an
        // alternative, where declining is an abstention.
        let hooks = vec![
            h("/hooks/consumer.sh", &[], &[], &["cap"], &[]),
            h("/hooks/part-a.sh", &[], &["cap"], &[], &[]),
            h("/hooks/part-b.sh", &[], &["cap"], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[("/hooks/part-b.sh", &[Outcome::Declined])]);
        assert!(r.is_ok(), "{:?}", r.err());
        assert!(calls.contains(&"/hooks/consumer.sh".to_string()));
    }

    #[test]
    fn a_deferred_hook_is_retried_after_something_else_progresses() {
        // The layered-decryption shape: the inner hook cannot act until the
        // outer one has produced its device, and says so rather than failing.
        let hooks = vec![
            h("/hooks/inner.sh", &[], &["unlocked"], &[], &[]),
            h("/hooks/outer.sh", &[], &["unlocked"], &[], &[]),
        ];
        let (r, calls) = drive(
            &hooks,
            &[("/hooks/inner.sh", &[Outcome::Deferred, Outcome::Satisfied])],
        );
        assert!(r.is_ok(), "{:?}", r.err());
        assert_eq!(
            calls,
            [
                "/hooks/inner.sh", // defers
                "/hooks/outer.sh", // makes progress
                "/hooks/inner.sh", // retried, succeeds
            ]
        );
    }

    #[test]
    fn a_hook_that_only_ever_defers_is_a_named_failure_not_a_spin() {
        let hooks = vec![h("/hooks/waiting.sh", &[], &[], &[], &[])];
        let (r, calls) = drive(&hooks, &[("/hooks/waiting.sh", &[Outcome::Deferred])]);
        let err = r.unwrap_err().to_string();
        assert!(err.contains("nothing left to wait for"), "{err}");
        assert!(err.contains("/hooks/waiting.sh"), "{err}");
        // Tried once per pass, and the pass that made no progress ends it.
        assert_eq!(calls.len(), 1);
    }

    #[test]
    fn after_orders_against_a_supplied_capability() {
        let hooks = vec![
            h("/hooks/late.sh", &[], &[], &[], &["net"]),
            h("/hooks/net.sh", &["net"], &[], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[]);
        assert!(r.is_ok());
        assert_eq!(calls, ["/hooks/net.sh", "/hooks/late.sh"]);
    }

    #[test]
    fn after_an_unsupplied_capability_just_runs() {
        let hooks = vec![h("/hooks/late.sh", &[], &[], &[], &["absent"])];
        let (r, calls) = drive(&hooks, &[]);
        assert!(r.is_ok(), "{:?}", r.err());
        assert_eq!(calls, ["/hooks/late.sh"]);
    }

    #[test]
    fn after_is_satisfied_when_every_provider_declines() {
        // `after` asks about ordering, not about the capability existing —
        // so unlike `requires`, a fully-declined capability releases it.
        let hooks = vec![
            h("/hooks/late.sh", &[], &[], &[], &["net"]),
            h("/hooks/net.sh", &["net"], &[], &[], &[]),
        ];
        let (r, calls) = drive(&hooks, &[("/hooks/net.sh", &[Outcome::Declined])]);
        assert!(r.is_ok(), "{:?}", r.err());
        assert_eq!(calls, ["/hooks/net.sh", "/hooks/late.sh"]);
    }

    #[test]
    fn a_failing_hook_stops_the_boot_immediately() {
        let hooks = vec![
            h("/hooks/a.sh", &[], &[], &[], &[]),
            h("/hooks/b.sh", &[], &[], &[], &[]),
        ];
        let calls = RefCell::new(Vec::<String>::new());
        let r = schedule_hooks(&hooks, &Breakpoints::default(), |path| {
            calls.borrow_mut().push(path.to_string());
            if path == "/hooks/a.sh" {
                Err(std::io::Error::other("boom"))
            } else {
                Ok(Outcome::Satisfied)
            }
        });
        assert!(r.is_err());
        // b.sh must not have run: a failure is not a deferral.
        assert_eq!(calls.into_inner(), ["/hooks/a.sh"]);
    }

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
        let found = vec![
            (0, "/hooks.seq".to_string()),
            (1, "/system/prelude/hooks.seq.1".to_string()),
        ];
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
        let hooks = parse_hook_seq_v2("t", body.lines()).unwrap();
        assert_eq!(
            paths(&hooks),
            ["/hooks/topology.sh", "/hooks/mount-root.sh"]
        );
        // The declarations are retained, not just counted — the scheduler
        // orders from them.
        assert_eq!(hooks[0].contributes, ["early-topology"]);
        assert_eq!(hooks[1].provides, ["root-mounted"]);
        assert_eq!(hooks[1].requires, ["early-topology"]);
        assert_eq!(hooks[1].after, ["network-up"]);
    }

    #[test]
    fn v2_takes_several_capabilities_on_one_line() {
        let hooks =
            parse_hook_seq_v2("t", "hook /hooks/a.sh\nrequires one two three\n".lines()).unwrap();
        assert_eq!(hooks[0].requires, ["one", "two", "three"]);
    }

    #[test]
    fn v2_accepts_a_hook_with_no_declarations() {
        let hooks = parse_hook_seq_v2("t", "hook /hooks/a.sh\nhook /hooks/b.sh\n".lines()).unwrap();
        assert_eq!(paths(&hooks), ["/hooks/a.sh", "/hooks/b.sh"]);
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
    fn the_last_init_on_the_cmdline_wins() {
        // The kernel's own rule for a repeated parameter, and the rule
        // `init_quiet` and `init_colour` already follow — so appending an
        // override to an existing line works, which is how a recovery boot is
        // asked for.
        assert_eq!(
            cmdline_init_from("init=/bin/peinit2 ro init=/bin/sh").as_deref(),
            Some("/bin/sh")
        );
        assert_eq!(
            cmdline_init_from("console=ttyS0 init=/bin/peinit2").as_deref(),
            Some("/bin/peinit2")
        );
        assert_eq!(cmdline_init_from("console=ttyS0 ro"), None);
    }

    #[test]
    fn an_empty_init_value_is_no_value_at_all() {
        // Filtered before the last is taken, so a trailing `init=` does not
        // erase a real one earlier on the line — it is simply not a value.
        assert_eq!(cmdline_init_from("init="), None);
        assert_eq!(cmdline_init_from("init= init="), None);
        assert_eq!(
            cmdline_init_from("init=/bin/sh init=").as_deref(),
            Some("/bin/sh")
        );
        assert_eq!(
            cmdline_init_from("init= init=/bin/sh").as_deref(),
            Some("/bin/sh")
        );
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

    #[test]
    fn a_stopped_child_is_reported_and_not_read_as_an_exit() {
        // A stop is 0x7f in the low seven bits with the stopping signal above
        // it — the one status where the "exit code" field holds a signal
        // number, so decoding it as an exit would report a status of 19.
        let reason = wait_failure((19 << 8) | 0x7f).expect("a stopped child must be a failure");
        assert_eq!(reason, "stopped");
    }
}

#[cfg(test)]
mod quiet_tests {
    use super::{init_quiet, BLACKOUT};
    use std::sync::atomic::Ordering;

    /// Only level 2 reaches prelude. Levels 0 and 1 differ in whether peinit
    /// may write into a terminal a service owns, and prelude exits before any
    /// service exists — so neither changes anything here.
    #[test]
    fn only_level_two_blacks_prelude_out() {
        for (cmdline, expected) in [
            ("peios.quiet=2", true),
            ("peios.quiet=1", false),
            ("peios.quiet=0", false),
            ("", false),
            ("peios.quiet=", false),
            ("peios.quiet=yes", false),
            ("quiet", false),
        ] {
            init_quiet(cmdline);
            assert_eq!(
                BLACKOUT.load(Ordering::Relaxed),
                expected,
                "cmdline {cmdline:?}",
            );
        }
    }

    /// Last occurrence wins, matching the kernel's own handling of a repeated
    /// parameter and peinit's parser.
    #[test]
    fn the_last_quiet_token_wins() {
        init_quiet("peios.quiet=2 root=/dev/vda peios.quiet=0");
        assert!(!BLACKOUT.load(Ordering::Relaxed));

        init_quiet("peios.quiet=0 peios.quiet=2");
        assert!(BLACKOUT.load(Ordering::Relaxed));

        init_quiet("");
    }
}

#[cfg(test)]
mod format_tests {
    use super::{banner_text, init_colour, render_with, Tag, BANNER_WIDTH, COLOUR};
    use std::sync::atomic::Ordering;

    // -----------------------------------------------------------------------
    // The console line format.
    //
    // These assertions duplicate peinit's `console_style` tests on purpose. The
    // format is shared by specification rather than by code (see the comment on
    // the renderer), so the only thing keeping the two implementations honest is
    // that both are held to the same expected strings. If you change a tag word
    // or a width here, change it there.
    // -----------------------------------------------------------------------

    #[test]
    fn tag_words_render_inside_a_fixed_bracket() {
        for (tag, expected) in [
            (Tag::None, "[      ] "),
            (Tag::Ok, "[  OK  ] "),
            (Tag::Warn, "[ WARN ] "),
            (Tag::Failed, "[FAILED] "),
        ] {
            let line = render_with(tag, "prelude", "x\n", false);
            assert_eq!(line, format!("{expected}prelude: x\n"));
        }
    }

    /// Colour must change the bytes and never the layout, so a serial log and a
    /// VT agree about where the message starts.
    #[test]
    fn colour_does_not_move_the_column() {
        let plain = render_with(Tag::Ok, "prelude", "x\n", false);
        let coloured = render_with(Tag::Ok, "prelude", "x\n", true);
        assert_ne!(plain, coloured);
        let stripped: String = {
            let mut out = String::new();
            let mut chars = coloured.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    for c in chars.by_ref() {
                        if c == 'm' {
                            break;
                        }
                    }
                } else {
                    out.push(c);
                }
            }
            out
        };
        assert_eq!(stripped, plain);
    }

    #[test]
    fn untagged_progress_is_never_coloured() {
        assert!(!render_with(Tag::None, "prelude", "x\n", true).contains('\x1b'));
    }

    /// prelude's banner and peinit's must be the same width, or the pair reads
    /// as two unrelated decorations rather than as one sequence.
    #[test]
    fn the_banner_is_a_fixed_width() {
        let text = banner_text("prelude · initramfs · PID 1", "v0.0.1", false);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].is_empty() && lines[4].is_empty());
        for line in &lines[1..4] {
            assert_eq!(line.chars().count(), BANNER_WIDTH, "{line:?}");
        }
    }

    #[test]
    fn term_dumb_on_the_cmdline_disables_colour() {
        let previous = COLOUR.load(Ordering::Relaxed);
        init_colour("console=ttyS0 TERM=dumb loglevel=4");
        assert!(!COLOUR.load(Ordering::Relaxed));
        init_colour("console=ttyS0 loglevel=4");
        assert!(COLOUR.load(Ordering::Relaxed));
        // Last wins, as the kernel resolves a repeated parameter.
        init_colour("TERM=linux TERM=dumb");
        assert!(!COLOUR.load(Ordering::Relaxed));
        COLOUR.store(previous, Ordering::Relaxed);
    }
}
