//! `--watch` mode: rebuild the initramfs whenever the source tree changes.
//!
//! `/system/boot/prelude/` is meant to behave like an ordinary directory
//! — edit a file in it and the initramfs is current again, with no
//! rebuild command and no coupling to the package manager. The watcher
//! is what makes that true.
//!
//! mkirf in watch mode is a foreground loop: it runs until killed.
//! Supervising and restarting it is a service manager's job, not
//! mkirf's (boot-design.md §3.5, §5.9). A rebuild that fails is logged
//! but does not stop the watch, so fixing the offending file recovers
//! on the next change.

use std::error::Error;
use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use notify::{RecursiveMode, Watcher};

/// Watch `src` and rebuild `out` after every change, debounced.
///
/// Builds once on startup so the watch never begins from a stale
/// archive, then watches `src` recursively until the process is killed.
pub fn watch(src: &Path, out: &Path, debounce_secs: u64) -> Result<(), Box<dyn Error>> {
    if out_inside_src(src, out) {
        return Err("--watch: <out-file> must not be inside <src-dir> — \
                    each rebuild would retrigger the watch endlessly"
            .into());
    }
    let debounce = Duration::from_secs(debounce_secs);

    // Build once up front: the watch must not start from a stale cpio.
    rebuild(src, out);

    let (tx, rx) = mpsc::channel::<notify::Result<notify::Event>>();
    let mut watcher = notify::recommended_watcher(move |event| {
        // A send failure only means the receive loop has already exited,
        // in which case there is nothing left to do.
        let _ = tx.send(event);
    })?;
    watcher.watch(src, RecursiveMode::Recursive)?;
    eprintln!(
        "mkirf: watching {} (debounce {debounce_secs}s) — Ctrl-C to stop",
        src.display(),
    );

    loop {
        // Block for the first event of a burst.
        match rx.recv() {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                eprintln!("mkirf: watch error: {e}");
                continue;
            }
            Err(_) => return Ok(()), // watcher dropped — nothing more to do
        }
        // Drain the burst: rebuild only once the tree has been quiet for
        // the full debounce window.
        while rx.recv_timeout(debounce).is_ok() {}
        rebuild(src, out);
    }
}

/// Run one build, logging the outcome. In watch mode a failed build —
/// say, a hook edited into a dependency cycle — must not kill the
/// watcher, so the error is reported but not propagated.
fn rebuild(src: &Path, out: &Path) {
    if let Err(e) = crate::run(src, out) {
        eprintln!("mkirf: rebuild failed: {e}");
    }
}

/// Whether `out` would be written inside the watched `src` tree — which
/// would make every rebuild trigger another. Best-effort: if the paths
/// cannot be canonicalised, they are assumed distinct.
fn out_inside_src(src: &Path, out: &Path) -> bool {
    let Ok(src) = src.canonicalize() else {
        return false;
    };
    // `out` itself need not exist yet, but its parent directory must.
    let Some(parent) = out.parent() else {
        return false;
    };
    matches!(parent.canonicalize(), Ok(p) if p.starts_with(&src))
}
