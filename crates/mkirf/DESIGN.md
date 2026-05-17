# mkirf — Design

`mkirf` compiles a directory tree into a deterministic initramfs
`cpio.gz` — the in-memory root filesystem the kernel unpacks at boot.

**Status:** v1 + hook DAG implemented.

---

## 1. Scope

```
mkirf [--watch] [--debounce <secs>] <src-dir> <out-file>
```

- `<src-dir>` is the **literal cpio root** — its contents map 1:1 onto
  `/` inside the initramfs.
- `<out-file>` is the gzip-compressed newc cpio archive.

mkirf does two things with that directory:

1. **Packs it** into a deterministic `cpio.gz` (§3–§6).
2. **Resolves the hook DAG and validates the layout** (§8) — it
   understands the prelude initramfs convention: an executable `/init`,
   and hook scripts under `hooks/` whose ordering metadata it sorts into
   a baked `hooks.seq`.

By default it does this once and exits. `--watch` makes it a long-lived
mode: rebuild whenever the source tree changes (§9). That is what lets
`/system/boot/prelude/` behave like an ordinary directory — edit a file,
the initramfs is current again — rather than a build artifact.

Deferred:

- **`--compress=zstd`** — later addition, no structural change required.
- **UKI output** — wrapping kernel + cpio + cmdline into a signed-ready
  `.efi`; a boot-stack M3 milestone.

## 2. mkirf and the boot design

The **packing** half of mkirf — "populated directory → deterministic
`cpio.gz`" — is a pure function, independent of the boot design. v1 was
built on that basis, ahead of the prelude rewrite.

The **hook DAG** half (§8) is not independent: mkirf parses hook
metadata, topologically sorts it, validates it, and bakes `hooks.seq`
into the cpio. That couples mkirf to the prelude initramfs convention,
deliberately — the alternative was for prelude to sort at boot, and
build-time resolution was chosen instead (boot-design.md §3.6). mkirf is
a boot-stack component, not a general-purpose cpio tool.

Why a build-time sort is sound despite Peios otherwise preferring
dynamic resolution: the initramfs is immutable once mkirf seals the
cpio, so the hook order is static data by boot time with no divergence
surface, and mkirf is unconditionally in the build path.

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
- Dependencies kept minimal: just `flate2` for gzip. newc is
  hand-written; the hook metadata parser is hand-written (§8.1);
  parsing two positional arguments is `std::env::args`.

## 8. The hook DAG

prelude runs **hooks** — shell scripts under `<src>/hooks/` — inside the
initramfs before switch_root. They must run in dependency order; mkirf
resolves that order at build time and bakes it into `hooks.seq`. See
boot-design.md §3.6 for the design rationale.

### 8.1 Discovery and metadata

Every regular file directly under `hooks/` is a hook — the directory is
not searched recursively, and the file extension is not significant (the
shebang is). Each hook declares its ordering in a co-located fenced
comment block, PEP 723-style:

```sh
#!/bin/sh
# /// hook
# provides = ["crypto-unlocked"]
# requires = ["modules-loaded"]
# ///
```

The block is opened by a line `# /// hook` and closed by `# ///`; every
line between is `#`-prefixed. With those prefixes stripped the content
is a small TOML subset — top-level `key = ["string", ...]` assignments,
`key` being `provides` or `requires` (arrays of capability names).

mkirf parses this subset with a **hand-rolled parser** — no `toml`
crate. The grammar is two array-of-string keys; a strict, small parser
keeps the dependency set minimal, and anything it accepts is still valid
TOML. It is strict by design: an unknown key, a malformed array, an
unclosed or duplicated block — all fail the build.

### 8.2 Resolution

Hooks split into two groups:

- **Constrained** — declaring any `provides` or `requires`. Ordered by
  their capability DAG: Kahn's algorithm, ties broken by file name in
  `LC_ALL=C` byte order.
- **Unconstrained** — both lists empty, whether the block is absent or
  present-but-empty. These run *after* all constrained hooks, in name
  order — the escape hatch (§3.6).

A hook with no block at all is valid but earns a build-time **warning**:
a forgotten block looks identical to a deliberate one, so it is made
visible. An explicit empty block suppresses the warning.

### 8.3 Validation

mkirf fails the build on:

- a **dependency cycle** among constrained hooks;
- a **`requires` that no hook `provides`**;
- the layout not being prelude-bootable — no executable `/init`, or a
  `hooks.seq` already present in the source tree (mkirf generates it).

### 8.4 hooks.seq

The resolved order is written to `hooks.seq` at the cpio root, injected
as a synthetic entry — it is *not* a file in the source tree, so the
source directory is never mutated. Format: a version-marker line
(`hookseq 1`), then one cpio-absolute hook path per line in execution
order. prelude reads this file and runs the list; it does no DAG
resolution of its own.

## 9. Watch mode

`--watch` rebuilds the initramfs whenever the source tree changes, so
`/system/boot/prelude/` stays current without a manual rebuild command
and without coupling rebuilds to the package manager — a direct edit to
the directory must rebuild too, which a peipkg-transaction trigger could
never catch.

- mkirf builds **once on startup**, so the watch never begins from a
  stale archive, then watches `<src-dir>` recursively.
- Changes are **debounced** — `--debounce <secs>`, default 5. A rebuild
  fires once the tree has been quiet for the window, so an editor or a
  package transaction writing a burst of files yields one rebuild.
- A rebuild that **fails** (a hook edited into a cycle, say) is logged
  and the watch continues — fixing the file recovers on the next
  change. Only a one-shot build exits non-zero on failure.

mkirf in watch mode is a **foreground process**; it does not daemonise.
Supervising it — starting it at boot, restarting it if it dies — is a
service manager's job, and Peios has none yet, so `--watch` is built but
not yet wired into the running system (boot-design.md §5.9). Recursive
watching is handled by the `notify` crate.
