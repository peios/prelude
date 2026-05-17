//! mkirf — compile a directory tree into a deterministic initramfs cpio.gz.
//!
//! `mkirf <src-dir> <out-file>` walks `<src-dir>`, whose contents map 1:1
//! onto `/` inside the initramfs, and writes a gzip-compressed newc cpio
//! archive to `<out-file>`. The output is byte-deterministic: identical
//! input trees produce identical archives. See `DESIGN.md`.

mod cpio;
mod walk;

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use flate2::{Compression, GzBuilder};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: mkirf <src-dir> <out-file>");
        return ExitCode::from(2);
    }
    match run(Path::new(&args[1]), Path::new(&args[2])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mkirf: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(src: &Path, out: &Path) -> Result<(), Box<dyn Error>> {
    let meta = fs::metadata(src).map_err(|e| format!("{}: {e}", src.display()))?;
    if !meta.is_dir() {
        return Err(format!("{}: not a directory", src.display()).into());
    }

    let entries = walk::walk(src)?;

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
