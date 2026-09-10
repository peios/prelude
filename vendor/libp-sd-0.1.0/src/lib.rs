// libp-sd: Security Descriptor construction + KACS SD syscall wrappers.
//
// Three things:
//
//   - Re-exports of the SD parse types from `peios-uapi` (so consumers
//     have one place to `use` from).
//   - `WellKnownSid` — a typed enum over the well-known SIDs, with
//     `matches` / `to_sid` / `from_sid` / `label`.
//   - Fluent builders (`SdBuilder`, `AclBuilder`, `AceBuilder`) that
//     emit self-relative SECURITY_DESCRIPTOR / ACL / ACE wire bytes.
//   - `get_sd` / `set_sd` syscall wrappers.
//
// `no_std + alloc` by default; the `std` feature adds
// `From<Error> for std::io::Error`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod abi;
mod access_check;
mod build;
mod claims;
mod codec;
mod condition;
mod error;
mod inherit;
mod object_tree;
pub mod raw;
mod sd;
pub mod sddl;
mod wellknown;

pub use access_check::{AccessCheckRequest, AccessDecision, NodeDecision};
pub use build::{AceBuilder, AclBuilder, SdBuilder};
pub use claims::{ClaimAttribute, ClaimValue};
pub use condition::{CompareOp, Condition, MemberOp, Operand};
pub use error::Error;
pub use inherit::{compute_inherited_aces, reinherit};
pub use object_tree::{ObjectTypeNode, encode_object_tree};
pub use sd::{SdTarget, SecurityInfo, get_sd, set_sd, strip_inherited_aces};
pub use sddl::{AclKind, ParsedAcl, SddlError};
pub use wellknown::WellKnownSid;

/// The SD parse types + decode helpers — the wire codec lives in libp-sd
/// (`codec`), with constant values sourced from the generated `peios-uapi`
/// crate. `GenericMapping` is the canonical generic-access mapping (also
/// the builder-facing form for [`AccessCheckRequest`]).
pub use codec::{
    Ace, AceIter, AceRef, Acl, GenericMapping, SecurityDescriptor, ace_flag_names, ace_type_name,
    ace_type_is_simple_mask_sid, access_mask_names, control_bit_names,
};
/// The SID types come from `libp-wire`, the shared on-wire-primitives crate.
pub use libp_wire::{Sid, SidRef};

/// The full SD codec surface for callers building/inspecting descriptors:
/// the `*_SECURITY_INFORMATION`, `SE_*` control, `ACCESS_*` mask, `ACE_TYPE_*`,
/// and `ACE_FLAG_*` constants, plus the `*_names` decode helpers. Constant
/// values are sourced from the generated `peios-uapi` crate.
pub mod consts {
    pub use crate::codec::*;
}

/// Crate-local `Result<T, Error>` alias.
pub type Result<T> = core::result::Result<T, Error>;
