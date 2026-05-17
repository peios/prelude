//! Native newc ("new ASCII") cpio archive writer.
//!
//! mkirf emits the newc format directly rather than shelling out to `cpio`:
//! it will eventually run as a long-lived service on Peios, and byte-level
//! control over the output is required for the determinism guarantee. See
//! `DESIGN.md` §3.

use std::io::{self, Write};
use std::path::PathBuf;

/// newc magic number — "new ASCII" format, no header checksum.
const MAGIC: &[u8; 6] = b"070701";

/// Name of the final entry, which marks the end of the archive.
const TRAILER_NAME: &[u8] = b"TRAILER!!!";

// st_mode file-type bits.
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;
const S_IFBLK: u32 = 0o060000;
const S_IFIFO: u32 = 0o010000;

/// One filesystem object to be placed in the archive.
#[derive(Debug)]
pub struct Entry {
    /// Path inside the archive: relative, '/'-separated, no leading slash
    /// (e.g. `b"usr/bin/prelude"`).
    pub name: Vec<u8>,
    pub body: Body,
}

/// The kind-specific content of an [`Entry`].
#[derive(Debug)]
pub enum Body {
    Directory,
    /// A regular file. `source` is opened and streamed at archive-write
    /// time; `size` is recorded in the header and is the exact byte count
    /// copied.
    File {
        source: PathBuf,
        size: u64,
        executable: bool,
    },
    /// A symbolic link; `target` is the link body, stored verbatim.
    Symlink { target: Vec<u8> },
    /// A character- or block-special device node.
    Device { block: bool, major: u64, minor: u64 },
    /// A FIFO (named pipe).
    Fifo,
}

impl Body {
    /// The canonicalised `st_mode`: real file-type bits, normalised
    /// permissions.
    ///
    /// The source tree is authoritative for file type and — for regular
    /// files — executability. Nothing else: read/write permission bits are
    /// not Peios's access mechanism, so they are normalised to a constant.
    /// See DESIGN.md §4.
    fn mode(&self) -> u32 {
        match self {
            Body::Directory => S_IFDIR | 0o755,
            Body::Symlink { .. } => S_IFLNK | 0o777,
            Body::Fifo => S_IFIFO | 0o644,
            Body::Device { block, .. } => {
                (if *block { S_IFBLK } else { S_IFCHR }) | 0o644
            }
            Body::File { executable, .. } => {
                S_IFREG | if *executable { 0o755 } else { 0o644 }
            }
        }
    }
}

/// Write `entries` as a newc cpio stream to `w`, followed by the trailer.
///
/// `entries` must already be in archive order — every directory preceding
/// its descendants (see [`crate::walk`]). All inode, ownership, and
/// timestamp fields are emitted as zero; see DESIGN.md §4.
pub fn write_archive<W: Write>(w: &mut W, entries: &[Entry]) -> io::Result<()> {
    for entry in entries {
        write_entry(w, entry)?;
    }
    // The trailer is a single entry named "TRAILER!!!" carrying no data.
    write_header(w, TRAILER_NAME, 0, 0, 0, 0)
}

fn write_entry<W: Write>(w: &mut W, entry: &Entry) -> io::Result<()> {
    let mode = entry.body.mode();

    let (filesize, rdevmajor, rdevminor) = match &entry.body {
        Body::Directory | Body::Fifo => (0, 0, 0),
        Body::Device { major, minor, .. } => (0, *major, *minor),
        Body::Symlink { target } => (target.len() as u64, 0, 0),
        Body::File { size, .. } => (*size, 0, 0),
    };

    write_header(w, &entry.name, mode, filesize, rdevmajor, rdevminor)?;

    match &entry.body {
        Body::Symlink { target } => {
            w.write_all(target)?;
            write_pad(w, target.len() as u64)?;
        }
        Body::File { source, size, .. } => {
            let mut file = std::fs::File::open(source).map_err(|e| {
                io::Error::new(e.kind(), format!("{}: {e}", source.display()))
            })?;
            let copied = io::copy(&mut file, w)?;
            if copied != *size {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "{}: file changed during archiving ({} -> {copied} bytes)",
                        source.display(),
                        size,
                    ),
                ));
            }
            write_pad(w, *size)?;
        }
        Body::Directory | Body::Device { .. } | Body::Fifo => {}
    }
    Ok(())
}

/// Write a 110-byte newc header followed by the NUL-terminated name and the
/// padding that advances to a 4-byte boundary.
fn write_header<W: Write>(
    w: &mut W,
    name: &[u8],
    mode: u32,
    filesize: u64,
    rdevmajor: u64,
    rdevminor: u64,
) -> io::Result<()> {
    let namesize = name.len() as u64 + 1; // includes the trailing NUL

    let mut hdr = Vec::with_capacity(110);
    hdr.extend_from_slice(MAGIC);
    field(&mut hdr, 0)?; //            c_ino       — zeroed for determinism
    field(&mut hdr, mode as u64)?; //  c_mode
    field(&mut hdr, 0)?; //            c_uid       — meaningless in Peios
    field(&mut hdr, 0)?; //            c_gid       — meaningless in Peios
    field(&mut hdr, 1)?; //            c_nlink     — hardlinks packed as copies
    field(&mut hdr, 0)?; //            c_mtime     — zeroed for determinism
    field(&mut hdr, filesize)?; //     c_filesize
    field(&mut hdr, 0)?; //            c_devmajor  — zeroed for determinism
    field(&mut hdr, 0)?; //            c_devminor  — zeroed for determinism
    field(&mut hdr, rdevmajor)?; //    c_rdevmajor
    field(&mut hdr, rdevminor)?; //    c_rdevminor
    field(&mut hdr, namesize)?; //     c_namesize
    field(&mut hdr, 0)?; //            c_check     — always 0 in newc
    debug_assert_eq!(hdr.len(), 110);

    w.write_all(&hdr)?;
    w.write_all(name)?;
    w.write_all(&[0])?;

    write_pad(w, 110 + namesize)
}

/// Append one newc header field: an 8-digit, zero-padded, lowercase-hex
/// number. newc fields are 32 bits wide.
fn field(buf: &mut Vec<u8>, value: u64) -> io::Result<()> {
    if value > u32::MAX as u64 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("cpio field value {value} exceeds 32 bits"),
        ));
    }
    write!(buf, "{value:08x}").expect("writing to a Vec cannot fail");
    Ok(())
}

/// Write NUL bytes to advance from `written` bytes to the next 4-byte
/// boundary.
fn write_pad<W: Write>(w: &mut W, written: u64) -> io::Result<()> {
    let pad = (4 - written % 4) % 4;
    w.write_all(&[0u8; 3][..pad as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One entry recovered from an archive by the test-side reader.
    struct Parsed {
        name: Vec<u8>,
        ino: u64,
        mode: u64,
        uid: u64,
        gid: u64,
        nlink: u64,
        mtime: u64,
        rdevmajor: u64,
        rdevminor: u64,
        data: Vec<u8>,
    }

    fn pad(n: usize) -> usize {
        (4 - n % 4) % 4
    }

    /// A minimal, independent newc reader used to inspect what the writer
    /// produced. Kept deliberately separate from the writer so the tests
    /// catch a writer that is merely self-consistent.
    fn parse(buf: &[u8]) -> Vec<Parsed> {
        let mut entries = Vec::new();
        let mut pos = 0;
        loop {
            let hdr = &buf[pos..pos + 110];
            assert_eq!(&hdr[..6], MAGIC, "bad newc magic");
            let field = |i: usize| -> u64 {
                let raw = &hdr[6 + i * 8..6 + i * 8 + 8];
                u64::from_str_radix(std::str::from_utf8(raw).unwrap(), 16).unwrap()
            };
            let (ino, mode, uid, gid, nlink, mtime, filesize) =
                (field(0), field(1), field(2), field(3), field(4), field(5), field(6));
            let (rdevmajor, rdevminor) = (field(9), field(10));
            let namesize = field(11) as usize;
            pos += 110;

            let name = buf[pos..pos + namesize - 1].to_vec(); // without trailing NUL
            pos += namesize + pad(110 + namesize);

            let data = buf[pos..pos + filesize as usize].to_vec();
            pos += filesize as usize + pad(filesize as usize);

            if name == TRAILER_NAME {
                break;
            }
            entries.push(Parsed {
                name, ino, mode, uid, gid, nlink, mtime, rdevmajor, rdevminor, data,
            });
        }
        entries
    }

    fn pack(entries: &[Entry]) -> Vec<u8> {
        let mut buf = Vec::new();
        write_archive(&mut buf, entries).unwrap();
        buf
    }

    #[test]
    fn empty_archive_is_just_a_trailer() {
        let buf = pack(&[]);
        assert!(parse(&buf).is_empty());
        assert!(buf.windows(TRAILER_NAME.len()).any(|w| w == TRAILER_NAME));
    }

    #[test]
    fn ownership_and_timestamps_are_zeroed() {
        let buf = pack(&[
            Entry { name: b"dir".to_vec(), body: Body::Directory },
            Entry {
                name: b"link".to_vec(),
                body: Body::Symlink { target: b"dir".to_vec() },
            },
        ]);
        for e in parse(&buf) {
            assert_eq!(e.ino, 0);
            assert_eq!(e.uid, 0);
            assert_eq!(e.gid, 0);
            assert_eq!(e.mtime, 0);
            assert_eq!(e.nlink, 1);
        }
    }

    #[test]
    fn directory_mode_is_canonical() {
        let buf = pack(&[Entry { name: b"d".to_vec(), body: Body::Directory }]);
        let e = &parse(&buf)[0];
        assert_eq!(e.name, b"d");
        assert_eq!(e.mode, u64::from(S_IFDIR | 0o755));
    }

    #[test]
    fn regular_file_mode_reflects_executability() {
        let plain = Body::File { source: PathBuf::new(), size: 0, executable: false };
        let exe = Body::File { source: PathBuf::new(), size: 0, executable: true };
        assert_eq!(plain.mode(), S_IFREG | 0o644);
        assert_eq!(exe.mode(), S_IFREG | 0o755);
    }

    #[test]
    fn symlink_stores_its_target_verbatim() {
        let target = b"../usr/bin/busybox".to_vec();
        let buf = pack(&[Entry {
            name: b"bin/sh".to_vec(),
            body: Body::Symlink { target: target.clone() },
        }]);
        let e = &parse(&buf)[0];
        assert_eq!(e.mode, u64::from(S_IFLNK | 0o777));
        assert_eq!(e.data, target);
    }

    #[test]
    fn device_node_records_its_rdev() {
        let buf = pack(&[Entry {
            name: b"dev/null".to_vec(),
            body: Body::Device { block: false, major: 1, minor: 3 },
        }]);
        let e = &parse(&buf)[0];
        assert_eq!(e.mode, u64::from(S_IFCHR | 0o644));
        assert_eq!((e.rdevmajor, e.rdevminor), (1, 3));
    }

    #[test]
    fn output_is_deterministic() {
        let sample = || {
            vec![
                Entry { name: b"a".to_vec(), body: Body::Directory },
                Entry {
                    name: b"a/link".to_vec(),
                    body: Body::Symlink { target: b"x".to_vec() },
                },
                Entry {
                    name: b"dev/null".to_vec(),
                    body: Body::Device { block: false, major: 1, minor: 3 },
                },
            ]
        };
        assert_eq!(pack(&sample()), pack(&sample()));
    }

    #[test]
    fn archive_is_four_byte_aligned() {
        let buf = pack(&[Entry {
            name: b"odd-length-name".to_vec(),
            body: Body::Directory,
        }]);
        assert_eq!(buf.len() % 4, 0);
    }
}
