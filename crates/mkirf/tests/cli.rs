//! End-to-end tests exercising the real `mkirf` binary.

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use flate2::read::GzDecoder;
use tempfile::tempdir;

/// Path to the `mkirf` binary, provided by Cargo to integration tests.
const MKIRF: &str = env!("CARGO_BIN_EXE_mkirf");

fn sample_tree(root: &Path) {
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::write(root.join("init"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(root.join("init"), PermissionsExt::from_mode(0o755)).unwrap();
    fs::write(root.join("usr/bin/tool"), b"binary contents").unwrap();
}

#[test]
fn produces_a_gzip_archive() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    sample_tree(&src);
    let out = dir.path().join("initramfs.cpio.gz");

    let status = Command::new(MKIRF).arg(&src).arg(&out).status().unwrap();
    assert!(status.success());

    let bytes = fs::read(&out).unwrap();
    assert_eq!(&bytes[..2], &[0x1f, 0x8b], "gzip magic");
}

#[test]
fn output_is_byte_identical_across_runs() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    sample_tree(&src);

    let a = dir.path().join("a.cpio.gz");
    let b = dir.path().join("b.cpio.gz");
    assert!(Command::new(MKIRF).arg(&src).arg(&a).status().unwrap().success());
    assert!(Command::new(MKIRF).arg(&src).arg(&b).status().unwrap().success());
    assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
}

#[test]
fn rejects_a_missing_source() {
    let dir = tempdir().unwrap();
    let status = Command::new(MKIRF)
        .arg(dir.path().join("does-not-exist"))
        .arg(dir.path().join("out.cpio.gz"))
        .status()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn rejects_a_wrong_argument_count() {
    assert!(!Command::new(MKIRF).status().unwrap().success());
}

#[test]
fn archive_extracts_with_gnu_cpio() {
    // An independent check against a real cpio reader. Skipped where the
    // `cpio` tool is not installed.
    if Command::new("cpio").arg("--version").output().is_err() {
        eprintln!("skipping archive_extracts_with_gnu_cpio: `cpio` not found");
        return;
    }

    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    sample_tree(&src);
    fs::set_permissions(src.join("usr/bin/tool"), PermissionsExt::from_mode(0o755)).unwrap();

    let out = dir.path().join("initramfs.cpio.gz");
    assert!(Command::new(MKIRF).arg(&src).arg(&out).status().unwrap().success());

    let dest = dir.path().join("extracted");
    fs::create_dir(&dest).unwrap();
    let extracted = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "gzip -dc '{}' | cpio -idm -D '{}'",
            out.display(),
            dest.display(),
        ))
        .status()
        .unwrap();
    assert!(extracted.success(), "GNU cpio failed to extract the archive");

    assert_eq!(fs::read(dest.join("init")).unwrap(), b"#!/bin/sh\n");
    assert_eq!(fs::read(dest.join("usr/bin/tool")).unwrap(), b"binary contents");
    let mode = fs::metadata(dest.join("usr/bin/tool"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0o111, "executable bit survived the round trip");
}

/// Decompress a gzip blob to its raw bytes.
fn gunzip(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    GzDecoder::new(bytes).read_to_end(&mut out).unwrap();
    out
}

#[test]
fn hooks_seq_lists_hooks_in_dependency_order() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    sample_tree(&src);

    // `a-consumer` requires the capability `z-producer` provides, so the
    // resolved order must place the producer first — overriding the name
    // order, which would otherwise put `a-consumer` first.
    let hooks = src.join("hooks");
    fs::create_dir(&hooks).unwrap();
    fs::write(
        hooks.join("z-producer.sh"),
        "#!/bin/sh\n# /// hook\n# provides = [\"ready\"]\n# ///\n",
    )
    .unwrap();
    fs::write(
        hooks.join("a-consumer.sh"),
        "#!/bin/sh\n# /// hook\n# requires = [\"ready\"]\n# ///\n",
    )
    .unwrap();

    let out = dir.path().join("initramfs.cpio.gz");
    assert!(Command::new(MKIRF).arg(&src).arg(&out).status().unwrap().success());

    // hooks.seq is stored uncompressed within the cpio; find its body in
    // the decompressed archive.
    let archive = gunzip(&fs::read(&out).unwrap());
    let seq = b"hookseq 1\n/hooks/z-producer.sh\n/hooks/a-consumer.sh\n";
    assert!(
        archive.windows(seq.len()).any(|w| w == seq),
        "hooks.seq not present in dependency order",
    );
}

#[test]
fn rejects_a_source_without_init() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    fs::write(src.join("not-init"), b"x").unwrap();

    let status = Command::new(MKIRF)
        .arg(&src)
        .arg(dir.path().join("out.cpio.gz"))
        .status()
        .unwrap();
    assert!(!status.success(), "a source with no `init` must be rejected");
}

/// Poll `cond` until it returns true or `timeout` elapses.
fn wait_for(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn watch_rebuilds_when_the_source_changes() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("src");
    fs::create_dir(&src).unwrap();
    sample_tree(&src);
    let out = dir.path().join("initramfs.cpio.gz");

    let mut child = Command::new(MKIRF)
        .args(["--watch", "--debounce", "1"])
        .arg(&src)
        .arg(&out)
        .spawn()
        .unwrap();

    // Watch mode builds once on startup.
    let started = wait_for(Duration::from_secs(20), || out.exists());
    let first = started.then(|| fs::read(&out).unwrap());

    // A change to the source tree must trigger a rebuild.
    fs::write(src.join("added-file"), b"new content").unwrap();
    let rebuilt = match &first {
        Some(first) => wait_for(Duration::from_secs(20), || {
            fs::read(&out).map(|now| &now != first).unwrap_or(false)
        }),
        None => false,
    };

    let _ = child.kill();
    let _ = child.wait();

    assert!(started, "watch did not produce an initial build");
    assert!(rebuilt, "watch did not rebuild after a source change");
}
