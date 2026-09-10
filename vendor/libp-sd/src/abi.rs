// Raw KACS AccessCheck ABI — re-exported from the generated `peios-uapi`
// crate under libp-sd's historical CamelCase names so the safe builders in
// `access_check`/`object_tree`/`claims` keep a single import surface.
//
// The structs are the kernel's exact on-wire layouts (size/offset asserted
// in `peios-uapi`'s generated layout checks); the claim constants name the
// `@Local` claims-array discriminants and attribute flags.

/// `kacs_access_check_args` — the 136-byte AccessCheck argument block.
pub use peios_uapi::kacs_access_check_args as KacsAccessCheckArgs;
/// `kacs_node_result` — one per-node result of `access_check_list`.
pub use peios_uapi::kacs_node_result as KacsNodeResult;
/// `kacs_object_type_entry` — one flat object-type-tree entry (20 bytes).
pub use peios_uapi::kacs_object_type_entry as KacsObjectTypeEntry;

/// Full fixed width of `kacs_access_check_args` (the size the kernel copies).
pub use peios_uapi::KACS_ACCESS_CHECK_ARGS_SIZE;

// ---------------------------------------------------------------------------
// Claim-attribute value-type discriminants (the `@Local` claims array).
// ---------------------------------------------------------------------------

pub const CLAIM_TYPE_INT64: u16 = peios_uapi::KACS_CLAIM_TYPE_INT64 as u16;
pub const CLAIM_TYPE_UINT64: u16 = peios_uapi::KACS_CLAIM_TYPE_UINT64 as u16;
pub const CLAIM_TYPE_STRING: u16 = peios_uapi::KACS_CLAIM_TYPE_STRING as u16;
pub const CLAIM_TYPE_SID: u16 = peios_uapi::KACS_CLAIM_TYPE_SID as u16;
pub const CLAIM_TYPE_BOOLEAN: u16 = peios_uapi::KACS_CLAIM_TYPE_BOOLEAN as u16;
pub const CLAIM_TYPE_OCTET: u16 = peios_uapi::KACS_CLAIM_TYPE_OCTET as u16;
