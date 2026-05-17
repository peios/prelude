# mkirf — Design

`mkirf` compiles a directory tree into a deterministic initramfs
`cpio.gz` — the in-memory root filesystem the kernel unpacks at boot.

**Status:** v1 implemented.

---

## 1. Scope

v1 is a one-shot packer:

```
mkirf <src-dir> <out-file>
```

- `<src-dir>` is the **literal cpio root** — its contents map 1:1 onto
  `/` inside the initramfs. mkirf does not understand profiles, hooks,
  or any boot-layout convention; it packs whatever directory it is given.
- `<out-file>` is the gzip-compressed newc cpio archive.

Deferred, explicitly out of v1:

- **`--watch`** — rebuild on directory change. When it lands it will be
  a long-running mode supervised by peinit as an ordinary service, not a
  self-daemonising mkirf.
- **structure verification** — checking the tree is something the
  initramfs PID 1 can actually consume. This is defined by what that
  PID 1 expects, so it waits on the prelude rewrite.
- **`--compress=zstd`**, **UKI output** — later additions, no structural
  change required.

## 2. Why mkirf is design-independent

"Populated directory → deterministic `cpio.gz`" is a pure function. It
does not depend on the hook DAG, profiles, the squashfs-vs-tmpfs rootfs
question, or how prelude is structured — all of which are still under
review. This is why mkirf can be built ahead of the prelude rewrite.

Its first consumer is prelude's initramfs — currently a minimal tree,
its eventual shape pending the prelude rewrite. mkirf does not care
either way.

## 3. The archive: newc, emitted natively

newc ("new ASCII", magic `070701`) is the format the kernel's initramfs
unpacker reads. mkirf emits it **directly** — it does not shell out to
GNU `cpio`:

- mkirf will eventually run on Peios as a service (`--watch`); depending
  on a `cpio` binary being installed would be a seam.
- Native emission gives full control of the byte layout, which is
  required for the determinism guarantee (§5). GNU `cpio --reproducible`
  is *not* byte-stable on its own — it zeroes device/inode numbers but
  leaves file mtimes alone.

Per-entry layout: a 110-byte ASCII-hex header (6-byte magic + 13
fixed-width fields), the NUL-terminated path, header+path padded to a
4-byte boundary, then file data padded to a 4-byte boundary. The archive
ends with a single entry named `TRAILER!!!`.

## 4. What gets emitted per file

The source tree is authoritative for **file type** and **executability**,
and nothing else. Everything identity- or permission-shaped is normalised.

| newc field        | value                       | rationale |
|-------------------|-----------------------------|-----------|
| type (in `mode`)  | preserved                   | essential — regular / dir / symlink / device |
| exec bit (`mode`) | preserved from source       | the file's intrinsic "this is executable" flag — the Peios `.exe` gate. Load-bearing: a non-executable prelude binary will not boot |
| r/w bits (`mode`) | normalised                  | Peios access is SD-routed, not POSIX-mode; uid 0 is exempt from r/w mode checks anyway |
| `uid` / `gid`     | `0`                         | meaningless in Peios — identity is the owner SID. A constant; asserts nothing |
| `mtime`           | `0`                         | determinism |
| `ino`             | `0`                         | determinism; with `nlink = 1` the kernel treats every entry as independent |
| `nlink`           | `1`                         | v1 packs hardlinks as independent copies (§4.2) |

`mode` is canonicalised by type:

- regular file → `0644`, or `0755` if the source file has any execute bit
- directory   → `0755`
- symlink     → `0777` (conventional; the kernel ignores symlink perms)

### 4.1 Security descriptors

mkirf is **entirely SD-agnostic**. The cpio is a pre-SD transport: it
carries bytes, file type, and the execute bit — nothing identity-shaped.
Security descriptors come into being on the *unpack* side; inside the
initramfs everything is owned by SYSTEM. mkirf neither reads nor writes
SDs and has no concept of them.

### 4.2 Symlinks and hardlinks

- **Symlinks** are stored as symlinks — the target is the link body,
  never followed. Kernel module trees and multi-call binaries rely on
  this.
- **Hardlinks** are packed as independent copies in v1 (`nlink = 1`).
  newc can encode shared inodes; dedup is a pure size optimisation and
  is deferred.

### 4.3 Device nodes

If the source tree contains device nodes, they are encoded faithfully
(newc carries `rdev`). mkirf does not *create* device nodes and has no
manifest for declaring them — the modern path is `CONFIG_DEVTMPFS_MOUNT`,
where the kernel populates `/dev` itself and the tree needs only an empty
`/dev` directory. A manifest escape-hatch can be added later if a feature
ever needs a static node.

## 5. Determinism

An identical input tree (same content, type, and execute bits) produces
**byte-identical** output. This is a hard requirement — it underpins
skip-rebuild cache keys and, later, UKI signing.

Guaranteed by:

- normalising `uid` / `gid` / `mtime` / `ino` as in §4;
- enumerating entries in a stable order — `LC_ALL=C` byte order on the
  path;
- gzip with no embedded mtime or filename (the `gzip -n` equivalent).

## 6. Compression

gzip for v1 — universally present in kernel decompressor configs, and the
format the reproducibility approach is settled against. `--compress=zstd`
is a future addition with no structural change (the kernel decompresses
both, given the right config).

## 7. Implementation notes

- Rust, in the `prelude` workspace as the `mkirf` crate. Static-musl
  binary, consistent with prelude / peinit / peiosutils.
- Dependencies kept minimal: likely just a pure-Rust gzip crate
  (`flate2` / `miniz_oxide`). newc is hand-written; parsing two
  positional arguments is `std::env::args`.
