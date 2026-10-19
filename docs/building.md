# Building Prelude

Prelude builds on Linux x86_64 with Bazel 8.4.2 and Rust 1.98.1. The launcher
verifies the Bazel binary against `build/bazel.sha256`. MODULE.bazel pins the
Rust toolchains and build rules. Cargo.lock pins the Rust dependency graph.

## Prepare the development environment

Install a C compiler, binutils, libclang development files, Python 3.11 or
later, pkg-config, gzip, groff, rustup, and Git. Style-tool preparation also
uses Python venv support and Node.js with npm. Bazel downloads its pinned
Rust toolchain; Cargo checks need the pinned toolchain installed in rustup.

Clone `peios/peios-sdk` into a separate checkout and select commit
`d56e86fbc922b83873006752600f8de7bc12cb84`. The SDK's source must be clean.
The maintained Rust wrapper is pinned to peios-rs commit
`26ac6968cec4cb7f887198aa3fb9268096660831` in Cargo.toml.

Prepare two explicit SDK roots outside either source checkout:

```sh
python3 tools/prepare-sdk.py ../peios-sdk /tmp/prelude-sdk-gnu \
    --target x86_64-unknown-linux-gnu
python3 tools/prepare-sdk.py ../peios-sdk /tmp/prelude-sdk-musl \
    --target x86_64-unknown-linux-musl
```

The script builds the SDK archive and copies matching headers, dependency
notices, target identity, and source/checksum metadata. It refuses an
existing output directory. GNU and musl archives are not interchangeable.
SDK preparation also builds the GNU SDK package stage to collect notices.
The SDK stage requires its own documented development dependencies.

The static SDK isolates its private Rust runtime symbols. Linking a raw
Cargo staticlib without that finishing step can collide with the consuming
Rust executable's allocator and panic runtime.

## Run development checks

```sh
python3 tools/prepare-style-tools.py /tmp/prelude-style
export PEIOS_SDK=/tmp/prelude-sdk-gnu
export PEIOS_STYLE_BIN=/tmp/prelude-style/bin
tools/check
```

This runs PSC formatting/lint checks, the GNU Bazel tests, and owned Cargo
Clippy checks. Neither main boot nor descriptor application is executed.
The seed-sd tests compare its default descriptor to bytes captured from the
original builder and check invalid arguments without filesystem mutation.

To test and package the static development binaries:

```sh
export PEIOS_SDK=/tmp/prelude-sdk-musl
./bazel test --config=musl //...
./bazel build --config=musl //:packages
```

Package writer and blob-checking tools run on the GNU execution platform.
They are intentionally incompatible with musl as direct target binaries.
The boot executables use musl. Package transitions preserve size optimization,
fat LTO, one codegen unit, and abort-on-panic behavior.

## Package outputs

`bazel-bin/packages.store` contains canonical PPK blobs and manifests plus
an index and build provenance. The package family uses version `0.0.7-1`:

| Package | Content |
| --- | --- |
| `dev.peios.prelude` | Both executables, hook logger, manuals, and notices |
| `dev.peios.prelude-debuginfo` | Split symbols and GNU build-ID paths |
| `dev.peios.prelude-debugsource` | Declared Rust source and generated bindings |
| `dev.peios.prelude-source` | Maintained source and build inputs |

The runtime is homed in the initramfs. Its package metadata provides `init`
and hook ABI 3, declares a shell dependency, and records `/init` as a claim
for `/usr/sbin/prelude`. Claims and dependency metadata remain in provenance
sidecars because the canonical manifest format contains files only. Building
a store does not resolve dependencies, create `/init`, compose an initramfs,
sign packages, or publish a release.

The debug-source package references the matching SDK debug-source package
for code embedded from libpeios.a. SDK.json records the exact SDK commit and
archive checksum; the package version alone is not source provenance.

Package validation checks both binaries for static PIE, no ELF interpreter,
no shared-library dependencies, RELRO, immediate binding, a nonexecutable
stack, build IDs, split debug links, and mapped source paths. The shell helper
is installed as a sourced file with mode 0644. No validation runs process 1.

## Native Peios toolchain

`--config=peios` selects the installed Peios Rust compiler and musl standard
library, enables control-flow protection, and uses local build actions.
Set `PEIOS_RUSTC` to the compiler path if it is not `/usr/bin/rustc`.
Prepare a static SDK archive with the same toolchain and musl target first:

```sh
# In the pinned SDK checkout, inside the native build environment:
./bazel build --config=peios --config=musl //libpeios:static
```

Export that archive with Prelude's `tools/prepare-sdk.py --native --archive
ARCHIVE --notices-stage SDK_STAGE --target x86_64-unknown-linux-musl`, supplying
the pinned SDK source and a new destination as the two positional arguments.
`SDK_STAGE` is a GNU SDK package stage from the same source revision, used
for notices. The caller is responsible for the supplied archive's build
provenance; the export records its bytes and the declared mode. Packaging
rejects a mismatch between the SDK and Prelude development/native modes.

For an isolated environment without network access, acquire dependencies on
the connected host with the musl development SDK selected:

```sh
tools/offline-build acquire /tmp/prelude-inputs
```

Transfer the source, snapshot, target-matched native SDK, and native toolchain
to the build environment. Keep the snapshot read-only and set PEIOS_SDK to
the native SDK there. The working directory must be the Prelude source root.

```sh
tools/offline-build test /inputs/prelude /work/prelude
```

The consumer checks the module lock, creates a writable repository view, and
disables repository downloads. The native compiler and SDK remain explicit
local inputs; the snapshot does not create a complete operating-system
build environment.

Musl startup does not enable shadow stack. Compiler instrumentation does not
establish runtime CET enforcement, and static PIE does not require RELR.
Package records keep `release_ready` and `signed` false. Boot, KACS descriptor
application, recovery, and root handoff require disposable Peios-kernel
qualification before a release can be claimed.

## Documentation checks

```sh
TRAIL=/path/to/trail python3 tools/check-docs.py
```

The check lints and strictly renders the component Learn tree to a temporary
directory and renders all manuals. Panorama merges `docs/learn/` into its
Peios product. Cross-component boot and hook-writing guidance remains in
learn-staging; see `docs/learn-migration.md` for the ownership review.
