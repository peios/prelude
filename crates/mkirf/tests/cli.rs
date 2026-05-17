//! End-to-end tests exercising the real `mkirf` binary.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::tempdir;

/// Path to the `mkirf` binary, provided by Cargo to integration tests.
const MKIRF: &str = env!("CARGO_BIN_EXE_mkirf");

fn sample_tree(root: &Path) {
    fs::create_dir_all(root.join("usr/bin")).unwrap();
    fs::write(root.join("init"), b"#!/bin/sh\n").unwrap();
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
