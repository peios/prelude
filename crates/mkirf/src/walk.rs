//! Walk a source directory into the ordered list of cpio entries.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

use crate::cpio::{Body, Entry};

/// Collect every object beneath `root` into archive entries.
///
/// `root` itself is not emitted — it is the archive's `/`. The returned
/// list is sorted by archive path in `LC_ALL=C` byte order, which places
/// every directory before its descendants: the order the kernel's
/// initramfs unpacker requires. See DESIGN.md §5.
pub fn walk(root: &Path) -> io::Result<Vec<Entry>> {
    let mut entries = Vec::new();
    collect(root, root, &mut entries)?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<Entry>) -> io::Result<()> {
    for child in fs::read_dir(dir).map_err(|e| at(e, dir))? {
        let child = child.map_err(|e| at(e, dir))?;
        let path = child.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| at(e, &path))?;
        let ft = meta.file_type();

        let name = path
            .strip_prefix(root)
            .expect("child path is always beneath root")
            .as_os_str()
            .as_bytes()
            .to_vec();

        if ft.is_dir() {
            out.push(Entry { name, body: Body::Directory });
            collect(&path, root, out)?;
        } else if ft.is_symlink() {
            let target = fs::read_link(&path).map_err(|e| at(e, &path))?;
            out.push(Entry {
                name,
                body: Body::Symlink {
                    target: target.as_os_str().as_bytes().to_vec(),
                },
            });
        } else if ft.is_file() {
            out.push(Entry {
                name,
                body: Body::File {
                    source: path,
                    size: meta.len(),
                    executable: meta.mode() & 0o111 != 0,
                },
            });
        } else if ft.is_char_device() || ft.is_block_device() {
            let rdev = meta.rdev();
            out.push(Entry {
                name,
                body: Body::Device {
                    block: ft.is_block_device(),
                    major: dev_major(rdev),
                    minor: dev_minor(rdev),
                },
            });
        } else if ft.is_fifo() {
            out.push(Entry { name, body: Body::Fifo });
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{}: unsupported file type (socket?)", path.display()),
            ));
        }
    }
    Ok(())
}

/// Wrap an I/O error with the path on which it occurred.
fn at(e: io::Error, path: &Path) -> io::Error {
    io::Error::new(e.kind(), format!("{}: {e}", path.display()))
}

// Linux device-number decoding, matching glibc's `gnu_dev_major`/`minor`.
fn dev_major(dev: u64) -> u64 {
    ((dev >> 8) & 0xfff) | ((dev >> 32) & !0xfff_u64)
}
fn dev_minor(dev: u64) -> u64 {
    (dev & 0xff) | ((dev >> 12) & !0xff_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use tempfile::tempdir;

    fn names(entries: &[Entry]) -> Vec<String> {
        entries
            .iter()
            .map(|e| String::from_utf8_lossy(&e.name).into_owned())
            .collect()
    }

    #[test]
    fn root_itself_is_not_emitted() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("file"), b"x").unwrap();
        assert_eq!(names(&walk(dir.path()).unwrap()), ["file"]);
    }

    #[test]
    fn directories_precede_their_contents() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("usr/bin")).unwrap();
        fs::write(dir.path().join("usr/bin/sh"), b"").unwrap();
        fs::write(dir.path().join("init"), b"").unwrap();
        // LC_ALL=C byte order: every directory lands before its descendants.
        assert_eq!(
            names(&walk(dir.path()).unwrap()),
            ["init", "usr", "usr/bin", "usr/bin/sh"],
        );
    }

    #[test]
    fn executable_bit_is_detected() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("plain"), b"").unwrap();
        fs::write(dir.path().join("exe"), b"").unwrap();
        fs::set_permissions(dir.path().join("plain"), PermissionsExt::from_mode(0o644)).unwrap();
        fs::set_permissions(dir.path().join("exe"), PermissionsExt::from_mode(0o755)).unwrap();

        for e in walk(dir.path()).unwrap() {
            match (e.name.as_slice(), &e.body) {
                (b"exe", Body::File { executable, .. }) => assert!(*executable),
                (b"plain", Body::File { executable, .. }) => assert!(!*executable),
                _ => panic!("unexpected entry: {:?}", e.name),
            }
        }
    }

    #[test]
    fn symlink_target_is_captured() {
        let dir = tempdir().unwrap();
        symlink("../usr/bin/busybox", dir.path().join("sh")).unwrap();
        match &walk(dir.path()).unwrap()[0].body {
            Body::Symlink { target } => {
                assert_eq!(target.as_slice(), b"../usr/bin/busybox")
            }
            _ => panic!("expected a symlink entry"),
        }
    }

    #[test]
    fn sockets_are_rejected() {
        let dir = tempdir().unwrap();
        let _sock =
            std::os::unix::net::UnixListener::bind(dir.path().join("sock")).unwrap();
        let err = walk(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
