# Prelude Coding Style

Follow PSC's common rules and Rust, shell, and Python profiles.
Use four spaces and a 100-column Rust formatter target. Keep the selected
Rust edition and formatter pinned in the build configuration.

Preserve boot-hook status codes, sequence versions, descriptor bytes, package
identities, and init paths during mechanical cleanup. Discuss changes to
these contracts separately. Keep pure parsing and scheduling testable without
mounting filesystems or running process 1 on the development host.

Unsafe calls explain pointer lifetimes and process assumptions at the call
site. The boot process is single-threaded; adding threads requires reviewing
every fork and process-wide filesystem operation. Keep diagnostic messages
and deliberate degraded-boot behavior visible at the responsible boundary.

Manuals live under `docs/man/`, following the component migration convention.
Historical material under `docs/archive/` records its original state and is
not an active build recipe or a formatting target. Vendored sources retain
their source project's style.
