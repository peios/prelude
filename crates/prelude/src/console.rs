//! Boot-console rendering shared with hooks and peinit by specification.

use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

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

pub(super) fn init_colour(cmdline: &str) {
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
pub(super) fn banner() {
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
pub(super) fn init_quiet(cmdline: &str) {
    let blackout = cmdline
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("peios.quiet="))
        .next_back()
        .is_some_and(|value| value == "2");
    BLACKOUT.store(blackout, Ordering::Relaxed);
}

/// Ordinary progress with no outcome yet. Silenced by `peios.quiet=2`.
pub(super) fn log(msg: &str) {
    log_tagged(Tag::None, msg);
}

/// Something worked. Silenced by `peios.quiet=2` exactly as [`log`] is: a
/// success is progress, and the tag is presentation rather than news.
pub(super) fn log_ok(msg: &str) {
    log_tagged(Tag::Ok, msg);
}

fn log_tagged(tag: Tag, msg: &str) {
    if BLACKOUT.load(Ordering::Relaxed) {
        return;
    }
    eprint!("{}", render(tag, "prelude", &format!("{msg}\n")));
}

/// Something is wrong but the boot continues. Never silenced, like [`log_err`].
pub(super) fn log_warn(msg: &str) {
    eprint!("{}", render(Tag::Warn, "prelude", &format!("{msg}\n")));
}

/// Something went wrong. Never silenced: a blackout is a preference about
/// noise, not an instruction to hide a failure — and prelude's failures cost
/// the boot.
pub(super) fn log_err(msg: &str) {
    eprint!("{}", render(Tag::Failed, "prelude", &format!("{msg}\n")));
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
