//! Generated Rust mirror of the PKM kernel ABI.
//!
//! Every declaration here is generated from the C headers in pkm/uapi/pkm/
//! by gen.sh — those headers are the single source of truth. Do not edit
//! ztypes.rs or zconst.rs by hand; run ./gen.sh to regenerate them.
//!
//! This is the raw, mechanical binding layer: C names are kept verbatim
//! (`struct kacs_query_args` -> `kacs_query_args`, `KACS_TOKEN_QUERY` ->
//! `KACS_TOKEN_QUERY`). Ergonomic, idiomatic wrappers — and the
//! hand-written wire parsers and syscall mechanism — belong in libp-rs,
//! which will consume this crate.
//!
//! `no_std`, no allocation: this crate is only type and constant
//! definitions.

#![no_std]
#![allow(non_camel_case_types)]

mod zconst;
mod ztypes;

pub use zconst::*;
pub use ztypes::*;
