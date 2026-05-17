//! mkirf — compile a directory tree into a deterministic initramfs cpio.gz.
//!
//! `mkirf <src-dir> <out-file>` walks `<src-dir>`, whose contents map 1:1
//! onto `/` inside the initramfs, and writes a gzip-compressed newc cpio
//! archive to `<out-file>`. The output is byte-deterministic: identical
//! input trees produce identical archives. See `DESIGN.md`.

mod cpio;
mod hooks;
mod walk;
mod watch;

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use flate2::{Compression, GzBuilder};

/// Parsed command line: `[--watch] [--debounce <secs>] <src-dir> <out-file>`.
struct Config {
    watch: bool,
    debounce_secs: u64,
    src: PathBuf,
    out: PathBuf,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = match parse_args(&args) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("mkirf: {e}");
            eprintln!("usage: mkirf [--watch] [--debounce <secs>] <src-dir> <out-file>");
            return ExitCode::from(2);
        }
    };

    let result = if cfg.watch {
        watch::watch(&cfg.src, &cfg.out, cfg.debounce_secs)
    } else {
        run(&cfg.src, &cfg.out)
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkirf: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parse `[--watch] [--debounce <secs>] <src-dir> <out-file>`. Flags may
/// appear in any position relative to the two positional arguments.
fn parse_args(args: &[String]) -> Result<Config, String> {
    let mut watch = false;
    let mut debounce_secs: u64 = 5;
    let mut positional: Vec<&str> = Vec::new();

    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--watch" => watch = true,
            "--debounce" => {
                let v = args.next().ok_or("--debounce needs a value in seconds")?;
                debounce_secs = v
                    .parse()
                    .map_err(|_| format!("--debounce: `{v}` is not a number of seconds"))?;
            }
            flag if flag.starts_with("--") => return Err(format!("unknown flag `{flag}`")),
            path => positional.push(path),
        }
    }

    let [src, out] = positional.as_slice() else {
        return Err("expected <src-dir> and <out-file>".into());
    };
    Ok(Config {
        watch,
        debounce_secs,
        src: PathBuf::from(*src),
        out: PathBuf::from(*out),
    })
}

fn run(src: &Path, out: &Path) -> Result<(), Box<dyn Error>> {
    let meta = fs::metadata(src).map_err(|e| format!("{}: {e}", src.display()))?;
    if !meta.is_dir() {
        return Err(format!("{}: not a directory", src.display()).into());
    }

    validate_layout(src)?;

    let mut entries = walk::walk(src)?;

    // Resolve the hook DAG and inject the generated hooks.seq manifest as
    // a synthetic entry — it is not a file in the source tree.
    let order = resolve_hooks(src)?;
    entries.push(cpio::Entry {
        name: b"hooks.seq".to_vec(),
        body: cpio::Body::Inline {
            data: hooks::render_seq(&order),
            executable: false,
        },
    });
    // walk() returns sorted entries; the injected one must be re-sorted
    // into archive order (every directory before its descendants).
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    // Write to a sibling temp file and rename into place, so a failed or
    // interrupted run never leaves a half-written initramfs behind.
    let tmp = temp_path(out);
    if let Err(e) = write_archive_gz(&tmp, &entries) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))?;

    let size = fs::metadata(out).map(|m| m.len()).unwrap_or(0);
    eprintln!(
        "mkirf: wrote {} ({} entries, {size} bytes)",
        out.display(),
        entries.len(),
    );
    Ok(())
}

/// Check the source tree is a layout prelude can boot.
///
/// It must carry an executable `init` (the initramfs PID 1), and must
/// not already contain a `hooks.seq` — mkirf generates that file, and a
/// pre-existing one would collide with the synthetic entry.
fn validate_layout(src: &Path) -> Result<(), Box<dyn Error>> {
    let init = src.join("init");
    match fs::metadata(&init) {
        Ok(m) if m.is_file() => {
            if m.mode() & 0o111 == 0 {
                return Err(format!("{}: `init` is not executable", src.display()).into());
            }
        }
        Ok(_) => {
            return Err(format!("{}: `init` is not a regular file", src.display()).into())
        }
        Err(_) => {
            return Err(
                format!("{}: no `init` — an initramfs needs a PID 1", src.display()).into(),
            )
        }
    }
    if src.join("hooks.seq").exists() {
        return Err(format!(
            "{}: contains a `hooks.seq`; mkirf generates that file",
            src.display(),
        )
        .into());
    }
    Ok(())
}

/// Discover and resolve the hook DAG under `<src>/hooks/`, returning the
/// execution order as cpio-absolute paths. A missing `hooks/` directory
/// simply means the initramfs has no hooks.
fn resolve_hooks(src: &Path) -> Result<Vec<String>, Box<dyn Error>> {
    let hooks_dir = src.join("hooks");
    if !hooks_dir.is_dir() {
        return Ok(Vec::new());
    }
    let hooks = hooks::discover(&hooks_dir)?;
    let resolved = hooks::resolve(&hooks)?;
    for w in &resolved.warnings {
        eprintln!("mkirf: warning: {w}");
    }
    Ok(resolved.order)
}

/// Compress the archive of `entries` into the gzip file at `path`.
fn write_archive_gz(path: &Path, entries: &[cpio::Entry]) -> Result<(), Box<dyn Error>> {
    let file = File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // gzip with mtime 0 and no embedded filename — the `gzip -n` equivalent,
    // so identical input yields byte-identical output. See DESIGN.md §5/§6.
    let mut gz = GzBuilder::new()
        .mtime(0)
        .write(BufWriter::new(file), Compression::new(9));
    cpio::write_archive(&mut gz, entries)?;
    gz.finish()?.flush()?;
    Ok(())
}

/// A sibling path of `out`, used as the atomic-rename staging file.
fn temp_path(out: &Path) -> PathBuf {
    let mut name = out.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".mkirf-tmp-{}", std::process::id()));
    out.with_file_name(name)
}
