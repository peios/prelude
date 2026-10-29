# Building Prelude

Use pekit to build Prelude's two programs and run their tests. Pekit builds
each crate on its own, so a change rebuilds only the crates it reaches. The
supported development host is x86-64 Linux.

## Before you start

You need pekit and Git. Everything else is pinned and fetched by pekit on
the first build: the Bootlin C toolchains, Rust 1.98.1 with Clippy and the
musl standard library, Python 3.14, busybox, libclang, and the crates
`Cargo.lock` selects. The first build needs network access; later builds
find what they need in pekit's store, and every step runs without network
access in a sandbox that holds only its declared inputs.

The build files use the gcslib libraries named in `workspace.gcsl` and the
build files, and the libraries of peios-rs and the Peios SDK. `pekit lock`
pins their commits in `pekit.lock`.

## Build

```sh
pekit build prelude seed_sd
```

| Target | Output |
|---|---|
| `prelude` | The initramfs's process 1 |
| `seed_sd` | `seed-sd`, which seeds bootstrap security descriptors |

Pekit prints where each output is, under `pekit-out/<target>/`. Both
programs are static, position-independent musl executables: they have no
ELF interpreter and need no shared library. They are linked with full
RELRO and immediate binding.

Programs are built with the workspace's release profile, which is tuned for
size: optimization level `z`, full link-time optimization, one
code-generation unit, and aborting panics.

Do not run the `prelude` program on a development host. It changes mounts
and roots, deletes the old initramfs, and halts on failure. `seed-sd`
changes access control; run it only on deliberately selected targets.

## Test

```sh
pekit test
```

| Test | Check |
|---|---|
| `prelude` | prelude's unit tests: hook-sequence parsing, hook scheduling, the command line, and console output |
| `seed_sd` | seed-sd's unit tests |
| `hook_log` | The hook logger, sourced by busybox's `sh`, keeps messages literal and each status on its stream |
| `clippy` | Clippy's checks of every target of both programs, with every warning denied |

No test runs process 1 or applies a descriptor to host files. The seed-sd
tests compare its default descriptor to bytes captured from the original
builder and check invalid arguments without changing the file system. A
test whose inputs did not change is found in the store and not run again.

For the full contributor check, install the pinned PSC tools into a
directory outside the repository, then run the shared entry point:

```sh
python3 tools/prepare-style-tools.py "$HOME/.cache/prelude-style"
export PEIOS_STYLE_BIN="$HOME/.cache/prelude-style/bin"
tools/check
```

`tools/check` checks owned source formatting and lint with rustfmt, Ruff,
ShellCheck, shfmt, and Prettier, then runs `pekit test`. The style checks
use the host's Rust 1.98.1 formatter through rustup. The tool versions and
hashes are recorded in `tools/style-tools.lock.json`. GitHub's workflow
runs the style checks alone; builds and tests run with pekit.

## How the build is planned

`build.gcsl` plans the Cargo workspace for `x86_64-unknown-linux-musl` with
the gcslib rust library's `workspace`: Cargo works out each program's build,
unit by unit, and pekit compiles each unit as a step. Planning reads the
manifests, `Cargo.lock`, and which files exist, never the sources, so
editing a source plans nothing again.

Keep Rust dependency versions in the Cargo manifests and `Cargo.lock`, and
update the lockfile deliberately with Cargo. seed-sd uses the `peios` crate
with its `static` feature. `peios-sys` generates its bindings from the SDK's
headers with bindgen and links libpeios's static archive for musl, so it is
given what peios-rs's library says a static musl program needs,
`static_musl_crate_settings()`.

The SDK's library builds that archive from the SDK's own files and renames
its private Rust runtime symbols. Without that step, the archive's
allocator and panic runtime would collide with seed-sd's own. The commits
`pekit.lock` pins say which SDK and which peios-rs; the rust library fails a
build whose `Cargo.lock` takes peios-rs's crates at another commit than
`pekit.lock` pins its library at.

## Not built with pekit yet

Packages, debug information and debug-source packages, and builds with the
native Peios toolchain, which hardens programs with control-flow
enforcement technology (CET), are not yet built with pekit. The package
definitions, their validation, and the native build settings from the
Bazel build are kept outside this repository until they are. Boot,
descriptor application, recovery, and root handoff still need qualification
on a disposable Peios kernel; see `tests/integration/`.

## Documentation checks

```sh
TRAIL=/path/to/trail python3 tools/check-docs.py
```

The check lints and strictly renders the component Learn tree to a temporary
directory and renders all manuals. Panorama merges `docs/learn/` into its
Peios product. Cross-component boot and hook-writing guidance remains in
learn-staging; see `docs/learn-migration.md` for the ownership review.
