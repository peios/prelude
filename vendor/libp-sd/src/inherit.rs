// ACE inheritance derivation (MS-DTYP §2.5.3.4).
//
// `compute_inherited_aces` is the parsed-ACL primitive — given a parent
// DACL and whether the child is a container, returns the ACEs the child
// inherits. `reinherit` is the wire-bytes sugar that strips inherited
// ACEs from a child SD and appends freshly-derived ones from a parent SD.
//
// Used by the `sd propagate` walk in the userspace `sd` tool, and by
// anything else that needs to push parent inheritance down a hierarchy
// (registry, future eventd object trees). Kernel exposes no
// reinheritance primitive — this is the canonical userspace shape.

use crate::Result;
use crate::build::{AceBuilder, AclBuilder, SdBuilder};
use crate::error::Error;
use alloc::vec::Vec;
use crate::codec::{
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_INHERITED,
    ACE_FLAG_NO_PROPAGATE_INHERIT, ACE_FLAG_OBJECT_INHERIT, Acl, SE_DACL_AUTO_INHERITED,
    SE_DACL_PROTECTED, SE_SACL_AUTO_INHERITED, SE_SACL_PROTECTED, SE_SELF_RELATIVE,
    SecurityDescriptor,
};
use libp_wire::ParseError;

/// All four inheritance-control flags as one mask — cleared on a child
/// copy when the ACE is "consumed" (file child, or NP).
const ALL_INHERIT_FLAGS: u8 = ACE_FLAG_OBJECT_INHERIT
    | ACE_FLAG_CONTAINER_INHERIT
    | ACE_FLAG_NO_PROPAGATE_INHERIT
    | ACE_FLAG_INHERIT_ONLY;

/// Compute the ACEs a child inherits from `parent_dacl`. Implements
/// MS-DTYP §2.5.3.4.1 `ComputeInheritedACEsFromACE`:
///
/// - A parent ACE with neither `OBJECT_INHERIT` (OI) nor `CONTAINER_INHERIT`
///   (CI) is not inheritable and produces nothing.
/// - For a **file** child (`child_is_container = false`):
///   - OI set → one inherited ACE with all four inheritance flags cleared
///     (the ACE applies to the file; files don't propagate further).
///   - OI not set → nothing.
/// - For a **container** child:
///   - CI set:
///     - `NO_PROPAGATE_INHERIT` (NP) set → one ACE with all inheritance
///       flags cleared (applies here, doesn't further propagate).
///     - NP not set → one ACE with NP and `INHERIT_ONLY` cleared, OI and
///       CI preserved (applies here AND continues propagation).
///   - CI not set, OI set:
///     - NP set → nothing (OI doesn't apply to containers, NP stops
///       further propagation, so the child sees nothing).
///     - NP not set → one ACE with `INHERIT_ONLY` set and OI preserved
///       (doesn't apply to this container, but propagates to files
///       within and OI-inheritable to deeper containers).
///
/// All returned ACEs have `ACE_FLAG_INHERITED` set. Non-inheritance
/// flags (audit `SA`/`FA`, the parent's own `INHERITED` bit) are
/// preserved.
///
/// Parser errors in `parent_dacl` are silently skipped — a malformed
/// ACE doesn't propagate (and the caller can validate the parent SD
/// independently if needed).
pub fn compute_inherited_aces(parent_dacl: &Acl<'_>, child_is_container: bool) -> Vec<AceBuilder> {
    let mut out = Vec::new();
    for ace_result in parent_dacl.aces_iter() {
        let Ok(ace) = ace_result else { continue };
        let f = ace.flags;
        let oi = f & ACE_FLAG_OBJECT_INHERIT != 0;
        let ci = f & ACE_FLAG_CONTAINER_INHERIT != 0;
        let np = f & ACE_FLAG_NO_PROPAGATE_INHERIT != 0;

        if !oi && !ci {
            continue;
        }

        let new_flags: u8 = if !child_is_container {
            if !oi {
                continue;
            }
            (f & !ALL_INHERIT_FLAGS) | ACE_FLAG_INHERITED
        } else if np {
            if ci {
                (f & !ALL_INHERIT_FLAGS) | ACE_FLAG_INHERITED
            } else {
                continue;
            }
        } else if ci {
            (f & !(ACE_FLAG_NO_PROPAGATE_INHERIT | ACE_FLAG_INHERIT_ONLY)) | ACE_FLAG_INHERITED
        } else {
            // OI alone, no NP, container child.
            (f & !ACE_FLAG_NO_PROPAGATE_INHERIT) | ACE_FLAG_INHERIT_ONLY | ACE_FLAG_INHERITED
        };

        out.push(AceBuilder::from_ace_ref(&ace).flags(new_flags));
    }
    out
}

/// Reinherit a child SD from its parent. Strips ACEs with
/// `ACE_FLAG_INHERITED` from the child's DACL, then appends the
/// freshly-computed inherited set from `parent_sd`.
///
/// Both inputs must be self-relative; output is self-relative. Owner,
/// group, and SACL of the child pass through verbatim. Control bits
/// `SE_DACL_AUTO_INHERITED` / `SE_DACL_PROTECTED` /
/// `SE_SACL_AUTO_INHERITED` / `SE_SACL_PROTECTED` are preserved from
/// the child; this function does NOT honour protection itself — a
/// caller who wants to respect `SE_DACL_PROTECTED` should check it
/// before calling.
///
/// If the parent has no DACL, the child's inherited ACEs are stripped
/// and no new ones are added.
///
/// ACE order in the output DACL is: child's explicit (non-inherited)
/// ACEs in declaration order, then the new inherited ACEs in
/// declaration order — the canonical "explicit before inherited"
/// shape per MS-DTYP §2.5.2.1.
///
/// # Errors
/// [`Error::Parse`] if either input is malformed or not self-relative.
pub fn reinherit(parent_sd: &[u8], child_sd: &[u8], child_is_container: bool) -> Result<Vec<u8>> {
    let parent = SecurityDescriptor::parse(parent_sd)?;
    let child = SecurityDescriptor::parse(child_sd)?;
    if child.control & SE_SELF_RELATIVE == 0 {
        return Err(Error::Parse(ParseError::SdNotSelfRelative));
    }

    let new_inherited = match parent.dacl() {
        Some(Ok(d)) => compute_inherited_aces(&d, child_is_container),
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => Vec::new(),
    };

    let (had_dacl, mut dacl_builder) = match child.dacl() {
        Some(Ok(dacl)) => {
            let mut b = AclBuilder::new();
            for ace_r in dacl.aces_iter() {
                let ace = ace_r?;
                if ace.flags & ACE_FLAG_INHERITED == 0 {
                    b = b.ace(AceBuilder::from_ace_ref(&ace));
                }
            }
            (true, b)
        }
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => (false, AclBuilder::new()),
    };
    for ace in new_inherited {
        dacl_builder = dacl_builder.ace(ace);
    }

    let mut out = SdBuilder::new();
    if let Some(owner) = child.owner() {
        out = out.owner(owner);
    }
    if let Some(group) = child.group() {
        out = out.group(group);
    }
    match child.sacl() {
        Some(Ok(sacl)) => {
            let mut sb = AclBuilder::new();
            for ace_r in sacl.aces_iter() {
                sb = sb.ace(AceBuilder::from_ace_ref(&ace_r?));
            }
            out = out.sacl(sb);
        }
        Some(Err(e)) => return Err(Error::Parse(e)),
        None => {}
    }
    if had_dacl || !dacl_builder.is_empty() {
        out = out.dacl(dacl_builder);
    }
    let extra = child.control
        & (SE_DACL_AUTO_INHERITED | SE_DACL_PROTECTED | SE_SACL_AUTO_INHERITED | SE_SACL_PROTECTED);
    if extra != 0 {
        out = out.control(extra);
    }
    out.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wellknown::WellKnownSid;
    use alloc::vec;
    use crate::codec::{ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ};

    fn build_parent_dacl(aces: Vec<AceBuilder>) -> Vec<u8> {
        let mut b = AclBuilder::new();
        for a in aces {
            b = b.ace(a);
        }
        b.build().unwrap()
    }

    fn parse_dacl(bytes: &[u8]) -> Acl<'_> {
        Acl::parse(bytes).unwrap()
    }

    // ---- compute_inherited_aces ----

    #[test]
    fn no_inherit_flags_emits_nothing() {
        let bytes = build_parent_dacl(vec![AceBuilder::allow(
            WellKnownSid::Everyone,
            ACCESS_GENERIC_READ,
        )]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, true).is_empty());
        assert!(compute_inherited_aces(&acl, false).is_empty());
    }

    #[test]
    fn oi_only_to_file_clears_all_inherit_flags() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        assert_eq!(out.len(), 1);
        let built = out[0].build();
        let f = built[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn oi_only_to_container_keeps_oi_sets_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_OBJECT_INHERIT != 0);
        assert!(f & ACE_FLAG_INHERIT_ONLY != 0);
        assert_eq!(f & ACE_FLAG_CONTAINER_INHERIT, 0);
        assert_eq!(f & ACE_FLAG_NO_PROPAGATE_INHERIT, 0);
    }

    #[test]
    fn ci_only_to_file_emits_nothing() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, false).is_empty());
    }

    #[test]
    fn ci_only_to_container_keeps_ci_clears_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_INHERIT_ONLY),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert_eq!(f & ACE_FLAG_INHERIT_ONLY, 0);
        assert_eq!(f & ACE_FLAG_OBJECT_INHERIT, 0);
    }

    #[test]
    fn ci_oi_to_container_keeps_both_clears_io() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_CONTAINER_INHERIT | ACE_FLAG_OBJECT_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert!(f & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert!(f & ACE_FLAG_OBJECT_INHERIT != 0);
        assert_eq!(f & ACE_FLAG_INHERIT_ONLY, 0);
    }

    #[test]
    fn np_collapses_to_one_level_on_container() {
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ).flags(
                ACE_FLAG_CONTAINER_INHERIT
                    | ACE_FLAG_OBJECT_INHERIT
                    | ACE_FLAG_NO_PROPAGATE_INHERIT,
            ),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, true);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn np_with_oi_only_to_container_emits_nothing() {
        // OI alone says "applies to files only"; NP says "don't propagate
        // beyond the immediate child." A container child with this combo
        // sees nothing — the ACE doesn't apply (no CI) and won't propagate.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_NO_PROPAGATE_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        assert!(compute_inherited_aces(&acl, true).is_empty());
    }

    #[test]
    fn np_with_oi_to_file_emits_one_terminal_ace() {
        // File child of an OI+NP ACE: still inherits, no further propagation.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_NO_PROPAGATE_INHERIT),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        assert_eq!(out.len(), 1);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
        assert_eq!(f & ALL_INHERIT_FLAGS, 0);
    }

    #[test]
    fn parent_inherited_flag_preserved_on_child() {
        // Parent ACE has INHERITED set (from grandparent). Child copy
        // also has INHERITED set — same bit, just confirms we OR rather
        // than overwrite.
        let bytes = build_parent_dacl(vec![
            AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERITED),
        ]);
        let acl = parse_dacl(&bytes);
        let out = compute_inherited_aces(&acl, false);
        let f = out[0].build()[1];
        assert!(f & ACE_FLAG_INHERITED != 0);
    }

    // ---- reinherit ----

    #[test]
    fn reinherit_drops_old_inherited_and_appends_new() {
        let parent = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT),
                ),
            )
            .build()
            .unwrap();
        // Child file with stale inherited ACE and one explicit ACE.
        let child = SdBuilder::new()
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Anonymous,
                        ACCESS_GENERIC_ALL,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::AuthenticatedUsers, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();

        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 2, "explicit + freshly inherited");
        let aces: Vec<_> = dacl.aces_iter().collect();
        let a0 = aces[0].as_ref().unwrap();
        let a1 = aces[1].as_ref().unwrap();
        // First ACE is the explicit one (Anonymous, no INHERITED flag).
        assert_eq!(a0.flags & ACE_FLAG_INHERITED, 0);
        let (_, sid0) = a0.as_mask_sid().unwrap();
        assert_eq!(sid0.to_owned(), WellKnownSid::Anonymous.to_sid());
        // Second ACE is the freshly inherited one — Everyone from parent.
        assert!(a1.flags & ACE_FLAG_INHERITED != 0);
        let (_, sid1) = a1.as_mask_sid().unwrap();
        assert_eq!(sid1.to_owned(), WellKnownSid::Everyone.to_sid());
    }

    #[test]
    fn reinherit_preserves_owner_group_sacl() {
        let parent = SdBuilder::new().build().unwrap();
        let child = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .group(WellKnownSid::BuiltinAdministrators)
            .sacl(AclBuilder::new().ace(AceBuilder::audit(
                WellKnownSid::Everyone,
                ACCESS_GENERIC_READ,
            )))
            .dacl(AclBuilder::new().ace(AceBuilder::allow(
                WellKnownSid::Anonymous,
                ACCESS_GENERIC_ALL,
            )))
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, true).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        assert_eq!(parsed.owner().unwrap(), WellKnownSid::LocalSystem.to_sid());
        assert_eq!(
            parsed.group().unwrap(),
            WellKnownSid::BuiltinAdministrators.to_sid()
        );
        assert_eq!(parsed.sacl().unwrap().unwrap().ace_count, 1);
        assert_eq!(parsed.dacl().unwrap().unwrap().ace_count, 1);
    }

    #[test]
    fn reinherit_preserves_protection_bit() {
        let parent = SdBuilder::new()
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT),
                ),
            )
            .build()
            .unwrap();
        let child = SdBuilder::new()
            .dacl(AclBuilder::new().ace(AceBuilder::allow(
                WellKnownSid::Anonymous,
                ACCESS_GENERIC_ALL,
            )))
            .control(SE_DACL_PROTECTED)
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        assert!(parsed.control & SE_DACL_PROTECTED != 0);
    }

    #[test]
    fn reinherit_with_parent_no_dacl_just_strips() {
        let parent = SdBuilder::new().build().unwrap();
        let child = SdBuilder::new()
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Anonymous,
                        ACCESS_GENERIC_ALL,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();
        let out = reinherit(&parent, &child, false).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 1, "only the explicit ACE remains");
    }

    #[test]
    fn reinherit_rejects_non_self_relative_child() {
        let parent = SdBuilder::new().build().unwrap();
        let mut child = [0u8; 20];
        child[0] = 1; // revision; no SE_SELF_RELATIVE bit
        assert!(matches!(
            reinherit(&parent, &child, false),
            Err(Error::Parse(ParseError::SdNotSelfRelative))
        ));
    }

    #[test]
    fn reinherit_container_chain_keeps_propagating_flags() {
        // Parent has CI+OI ACE. Reinherit into a container child: the
        // resulting inherited ACE should still carry CI+OI so a further
        // reinherit picks it up for grandchildren.
        let parent = SdBuilder::new()
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT),
                ),
            )
            .build()
            .unwrap();
        let child = SdBuilder::new().build().unwrap();
        let out = reinherit(&parent, &child, true).unwrap();
        let parsed = SecurityDescriptor::parse(&out).unwrap();
        let dacl = parsed.dacl().unwrap().unwrap();
        let aces: Vec<_> = dacl.aces_iter().collect();
        let ace = aces[0].as_ref().unwrap();
        assert!(ace.flags & ACE_FLAG_CONTAINER_INHERIT != 0);
        assert!(ace.flags & ACE_FLAG_OBJECT_INHERIT != 0);
        assert!(ace.flags & ACE_FLAG_INHERITED != 0);
    }
}
