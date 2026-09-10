// libp-wire — Peios on-wire primitives shared across the libp-rs domain
// crates. Mirrors libp-go's `wire` package: the Security Identifier (SID),
// the KMES event header, and the shared `ParseError` they decode into.
//
// Typed constant groups (e.g. `GroupAttributes`, `Origin`) take their
// *values* from the generated `peios-uapi` crate (`KACS_*` / `KMES_*`) but
// present an ergonomic, type-safe surface — the uapi-vs-libc split. The
// byte-level parsers are preserved verbatim from the kernel ABI.
//
// no_std + alloc.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod error;
mod event;
mod sid;

pub use error::ParseError;
pub use event::{EventHeader, Origin, origin_name};
pub use sid::{GroupAttributes, Sid, SidRef, SubAuthorityIter, sid_byte_len, well_known_label};
