// Safe get_sd / set_sd wrappers.

use crate::Result;
use crate::error::Error;
use crate::raw;
use alloc::ffi::CString;
use alloc::vec;
use alloc::vec::Vec;
use crate::codec::{
    ACE_FLAG_INHERITED, Acl, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION,
    SD_HEADER_BYTES, SE_SELF_RELATIVE, SecurityDescriptor,
};
use libp_errno::Errno;
use libp_sys::eintr_retry;
use libp_wire::ParseError;
use libp_wire::SidRef;

/// Which parts of a security descriptor a get/set call should touch.
///
/// A bitset over the `*_SECURITY_INFORMATION` flags. Build with the
/// constructors / `with_*` methods:
///
/// ```ignore
/// SecurityInfo::owner().with_dacl()   // owner + DACL
/// SecurityInfo::all()                 // everything
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityInfo(u32);

impl SecurityInfo {
    /// No components selected.
    pub const fn none() -> Self {
        SecurityInfo(0)
    }
    /// Owner only.
    pub const fn owner() -> Self {
        SecurityInfo(OWNER_SECURITY_INFORMATION)
    }
    /// Primary group only.
    pub const fn group() -> Self {
        SecurityInfo(GROUP_SECURITY_INFORMATION)
    }
    /// DACL only.
    pub const fn dacl() -> Self {
        SecurityInfo(DACL_SECURITY_INFORMATION)
    }
    /// SACL only.
    pub const fn sacl() -> Self {
        SecurityInfo(SACL_SECURITY_INFORMATION)
    }
    /// Mandatory label only.
    pub const fn label() -> Self {
        SecurityInfo(LABEL_SECURITY_INFORMATION)
    }
    /// Owner + group + DACL + SACL.
    ///
    /// Deliberately excludes `LABEL`: the kernel rejects a
    /// `security_info` that sets both `SACL` and `LABEL` with `-EINVAL`
    /// (the mandatory label is a specialized view of the SACL slot, not
    /// an independent component). To read the mandatory label instead
    /// of the full SACL, use `SecurityInfo::label()` or build a set
    /// with `with_label()` and without `with_sacl()`.
    pub const fn all() -> Self {
        SecurityInfo(
            OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | SACL_SECURITY_INFORMATION,
        )
    }

    /// Add the owner component.
    pub const fn with_owner(self) -> Self {
        SecurityInfo(self.0 | OWNER_SECURITY_INFORMATION)
    }
    /// Add the group component.
    pub const fn with_group(self) -> Self {
        SecurityInfo(self.0 | GROUP_SECURITY_INFORMATION)
    }
    /// Add the DACL component.
    pub const fn with_dacl(self) -> Self {
        SecurityInfo(self.0 | DACL_SECURITY_INFORMATION)
    }
    /// Add the SACL component.
    pub const fn with_sacl(self) -> Self {
        SecurityInfo(self.0 | SACL_SECURITY_INFORMATION)
    }
    /// Add the mandatory-label component.
    pub const fn with_label(self) -> Self {
        SecurityInfo(self.0 | LABEL_SECURITY_INFORMATION)
    }

    /// The raw `SECURITY_INFORMATION` bitmask.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

/// What a get_sd / set_sd call operates on.
pub enum SdTarget<'a> {
    /// A filesystem path. `dirfd` of [`raw::FDCWD`] makes `path`
    /// resolve relative to the current working directory.
    Path {
        dirfd: i32,
        path: &'a str,
        /// Act on a symlink itself rather than its target.
        no_follow_symlinks: bool,
    },
    /// An already-open file descriptor (a file fd or a KACS token fd).
    /// Resolved with an empty path + `AT_EMPTY_PATH`.
    Fd(i32),
}

impl<'a> SdTarget<'a> {
    /// A cwd-relative path target.
    pub fn path(path: &'a str) -> Self {
        SdTarget::Path {
            dirfd: raw::FDCWD,
            path,
            no_follow_symlinks: false,
        }
    }
}

/// Lower a `SdTarget` to the (dirfd, CString, flags) triple the
/// syscall takes. The returned `CString` must outlive the syscall.
fn lower(target: &SdTarget<'_>) -> Result<(i32, CString, u32)> {
    match target {
        SdTarget::Path {
            dirfd,
            path,
            no_follow_symlinks,
        } => {
            let c = CString::new(*path)
                .map_err(|_| Error::Encode("path contains an interior NUL byte"))?;
            let flags = if *no_follow_symlinks {
                raw::AT_SYMLINK_NOFOLLOW
            } else {
                0
            };
            Ok((*dirfd, c, flags))
        }
        SdTarget::Fd(fd) => {
            // Empty path + AT_EMPTY_PATH → operate on the fd itself.
            Ok((*fd, CString::default(), raw::AT_EMPTY_PATH))
        }
    }
}

/// Read the security descriptor of `target`.
///
/// Uses the kernel's probe protocol: a zero-length probe call learns
/// the descriptor size, then a sized call fetches it. Returns the raw
/// self-relative SD bytes — parse with [`crate::SecurityDescriptor`].
pub fn get_sd(target: &SdTarget<'_>, info: SecurityInfo) -> Result<Vec<u8>> {
    let (dirfd, path, flags) = lower(target)?;
    let path_ptr = path.as_ptr() as *const u8;

    // Probe: buf_len = 0. Kernel returns the required size.
    let needed = eintr_retry(|| unsafe {
        raw::get_sd(
            dirfd,
            path_ptr,
            info.bits(),
            core::ptr::null_mut(),
            0,
            flags,
        )
    });
    if needed < 0 {
        return Err(Error::Syscall(Errno::from_raw(needed)));
    }
    let needed = needed as usize;
    if needed == 0 {
        return Ok(Vec::new());
    }

    // Fetch into a sized buffer.
    let mut buf = vec![0u8; needed];
    let got = eintr_retry(|| unsafe {
        raw::get_sd(
            dirfd,
            path_ptr,
            info.bits(),
            buf.as_mut_ptr(),
            needed as u32,
            flags,
        )
    });
    if got < 0 {
        return Err(Error::Syscall(Errno::from_raw(got)));
    }
    let got = got as usize;
    if got > buf.len() {
        // The descriptor grew between probe and fetch — surface it
        // rather than handing back a truncated SD.
        return Err(Error::BufferTooSmall { needed: got });
    }
    buf.truncate(got);
    Ok(buf)
}

/// Write `sd_bytes` as the security descriptor of `target`. Only the
/// components selected by `info` are applied.
pub fn set_sd(target: &SdTarget<'_>, info: SecurityInfo, sd_bytes: &[u8]) -> Result<()> {
    let (dirfd, path, flags) = lower(target)?;
    let path_ptr = path.as_ptr() as *const u8;
    let rc = eintr_retry(|| unsafe {
        raw::set_sd(
            dirfd,
            path_ptr,
            info.bits(),
            sd_bytes.as_ptr(),
            sd_bytes.len() as u32,
            flags,
        )
    });
    if rc < 0 {
        Err(Error::Syscall(Errno::from_raw(rc)))
    } else {
        Ok(())
    }
}

/// Returns a copy of `sd_bytes` with inherited ACEs stripped from the
/// ACLs selected by `info`.
///
/// An ACE is "inherited" iff its `AceFlags` byte has `ACE_FLAG_INHERITED`
/// (`0x10`) set. Such ACEs are dropped; every other ACE passes through
/// verbatim — including ACE types [`crate::AceBuilder`] does not model.
///
/// - `DACL_SECURITY_INFORMATION` in `info` → strip inherited ACEs from
///   the DACL.
/// - `SACL_SECURITY_INFORMATION` in `info` → strip inherited ACEs from
///   the SACL.
/// - `OWNER` / `GROUP` / `LABEL` bits in `info` are ignored.
/// - `info` selecting neither DACL nor SACL → returns `sd_bytes`
///   byte-for-byte.
///
/// Owner SID, group SID, and the control word pass through verbatim —
/// including `SE_DACL_AUTO_INHERITED` / `SE_SACL_AUTO_INHERITED`: this
/// filters ACEs, it does not re-derive inheritance metadata. An ACL not
/// selected by `info` is reproduced byte-for-byte. A filtered ACL keeps
/// its revision and `Sbz1`; its `AceCount` / `AclSize` and the SD's
/// component offsets are recomputed. If filtering removes every ACE the
/// result is a present-but-empty ACL (8-byte header, `AceCount` 0) —
/// distinct from an absent ACL. The output is self-relative.
///
/// # Errors
/// [`Error::Parse`] if `sd_bytes` is not a well-formed self-relative
/// security descriptor.
pub fn strip_inherited_aces(sd_bytes: &[u8], info: SecurityInfo) -> Result<Vec<u8>> {
    let sd = SecurityDescriptor::parse(sd_bytes)?;
    if sd.control & SE_SELF_RELATIVE == 0 {
        return Err(Error::Parse(ParseError::SdNotSelfRelative));
    }

    let strip_dacl = info.bits() & DACL_SECURITY_INFORMATION != 0;
    let strip_sacl = info.bits() & SACL_SECURITY_INFORMATION != 0;
    if !strip_dacl && !strip_sacl {
        // Nothing selected — hand the input straight back.
        return Ok(sd_bytes.to_vec());
    }

    // Resolve the four referenced components into owned byte buffers.
    let owner = verbatim_sid(sd_bytes, sd.owner_off)?;
    let group = verbatim_sid(sd_bytes, sd.group_off)?;
    let sacl = resolve_acl(sd.sacl(), strip_sacl)?;
    let dacl = resolve_acl(sd.dacl(), strip_dacl)?;

    // Reassemble: 20-byte header, then owner, group, SACL, DACL.
    let mut out = vec![0u8; SD_HEADER_BYTES];
    let mut owner_off = 0u32;
    let mut group_off = 0u32;
    let mut sacl_off = 0u32;
    let mut dacl_off = 0u32;
    if let Some(b) = &owner {
        owner_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &group {
        group_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &sacl {
        sacl_off = out.len() as u32;
        out.extend_from_slice(b);
    }
    if let Some(b) = &dacl {
        dacl_off = out.len() as u32;
        out.extend_from_slice(b);
    }

    out[0] = sd.revision;
    out[1] = sd.sbz1;
    out[2..4].copy_from_slice(&sd.control.to_le_bytes());
    out[4..8].copy_from_slice(&owner_off.to_le_bytes());
    out[8..12].copy_from_slice(&group_off.to_le_bytes());
    out[12..16].copy_from_slice(&sacl_off.to_le_bytes());
    out[16..20].copy_from_slice(&dacl_off.to_le_bytes());
    Ok(out)
}

/// Copy the SID at byte offset `off` verbatim. `off == 0` → absent.
fn verbatim_sid(sd_bytes: &[u8], off: u32) -> Result<Option<Vec<u8>>> {
    if off == 0 {
        return Ok(None);
    }
    let start = off as usize;
    if start > sd_bytes.len() {
        return Err(Error::Parse(ParseError::SdOffsetOutOfBounds));
    }
    let (_, used) = SidRef::parse(&sd_bytes[start..])?;
    Ok(Some(sd_bytes[start..start + used].to_vec()))
}

/// Resolve one ACL into the bytes to emit. `None` → the ACL is absent and
/// stays absent. A selected ACL is filtered; an unselected one is copied
/// verbatim.
fn resolve_acl(
    acl: core::option::Option<core::result::Result<Acl<'_>, ParseError>>,
    strip: bool,
) -> Result<Option<Vec<u8>>> {
    match acl {
        None => Ok(None),
        Some(Err(e)) => Err(Error::Parse(e)),
        Some(Ok(acl)) => {
            // A well-formed ACL is at least its 8-byte header.
            if (acl.size as usize) < 8 {
                return Err(Error::Parse(ParseError::AclSizeOutOfBounds));
            }
            if strip {
                Ok(Some(filter_acl(&acl)?))
            } else {
                Ok(Some(acl.bytes.to_vec()))
            }
        }
    }
}

/// Rebuild an ACL keeping only the ACEs without `ACE_FLAG_INHERITED`.
fn filter_acl(acl: &Acl<'_>) -> Result<Vec<u8>> {
    let mut ace_bytes: Vec<u8> = Vec::new();
    let mut kept: u16 = 0;
    for ace in acl.aces_iter() {
        let ace = ace?;
        if ace.flags & ACE_FLAG_INHERITED != 0 {
            continue;
        }
        // Re-emit the ACE verbatim: [type][flags][size:u16le][body].
        ace_bytes.push(ace.ace_type);
        ace_bytes.push(ace.flags);
        ace_bytes.extend_from_slice(&ace.size.to_le_bytes());
        ace_bytes.extend_from_slice(ace.body);
        kept += 1; // bounded by the source AceCount, itself a u16
    }
    let total = 8 + ace_bytes.len();
    if total > u16::MAX as usize {
        return Err(Error::Encode("filtered ACL exceeds 65535 bytes"));
    }
    let mut out = Vec::with_capacity(total);
    out.push(acl.revision); // AclRevision — copied
    out.push(acl.bytes[1]); // Sbz1 — copied
    out.extend_from_slice(&(total as u16).to_le_bytes()); // AclSize — recomputed
    out.extend_from_slice(&kept.to_le_bytes()); // AceCount — recomputed
    out.extend_from_slice(&0u16.to_le_bytes()); // Sbz2 — zeroed
    out.extend_from_slice(&ace_bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AceBuilder, AclBuilder, SdBuilder, WellKnownSid};
    use crate::codec::{
        ACCESS_GENERIC_ALL, ACCESS_GENERIC_READ, ACCESS_GENERIC_WRITE, ACE_TYPE_ACCESS_ALLOWED,
        SE_DACL_PRESENT,
    };

    #[test]
    fn security_info_composition() {
        assert_eq!(
            SecurityInfo::owner().with_dacl().bits(),
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
        );
        let all = SecurityInfo::all().bits();
        assert!(all & OWNER_SECURITY_INFORMATION != 0);
        assert!(all & SACL_SECURITY_INFORMATION != 0);
        // `all()` deliberately omits LABEL — the kernel rejects
        // SACL+LABEL together.
        assert_eq!(all & LABEL_SECURITY_INFORMATION, 0);
    }

    #[test]
    fn lower_rejects_interior_nul() {
        let target = SdTarget::path("bad\0path");
        assert!(matches!(lower(&target), Err(Error::Encode(_))));
    }

    #[test]
    fn strip_dacl_drops_inherited_keeps_explicit() {
        let sd = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .group(WellKnownSid::BuiltinAdministrators)
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Everyone,
                        ACCESS_GENERIC_READ,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
                            .flags(ACE_FLAG_INHERITED),
                    )
                    .ace(
                        AceBuilder::deny(WellKnownSid::Everyone, ACCESS_GENERIC_WRITE)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();

        let stripped = strip_inherited_aces(&sd, SecurityInfo::dacl()).unwrap();
        let parsed = SecurityDescriptor::parse(&stripped).unwrap();

        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 1);
        assert_eq!(dacl.size as usize, dacl.bytes.len());

        let aces: Vec<_> = dacl.aces_iter().collect();
        assert_eq!(aces.len(), 1);
        let ace = aces[0].as_ref().unwrap();
        assert_eq!(ace.ace_type, ACE_TYPE_ACCESS_ALLOWED);
        let (mask, sid) = ace.as_mask_sid().unwrap();
        assert_eq!(mask, ACCESS_GENERIC_READ);
        assert_eq!(sid.to_owned(), WellKnownSid::Everyone.to_sid());

        // Owner and group pass through verbatim.
        assert_eq!(parsed.owner().unwrap(), WellKnownSid::LocalSystem.to_sid());
        assert_eq!(
            parsed.group().unwrap(),
            WellKnownSid::BuiltinAdministrators.to_sid()
        );
    }

    #[test]
    fn strip_none_returns_input_verbatim() {
        let sd = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_INHERITED),
                ),
            )
            .build()
            .unwrap();
        let out = strip_inherited_aces(&sd, SecurityInfo::none()).unwrap();
        assert_eq!(out, sd);
    }

    #[test]
    fn strip_all_inherited_yields_present_empty_dacl() {
        let sd = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .dacl(
                AclBuilder::new()
                    .ace(
                        AceBuilder::allow(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    )
                    .ace(
                        AceBuilder::allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();
        let stripped = strip_inherited_aces(&sd, SecurityInfo::dacl()).unwrap();
        let parsed = SecurityDescriptor::parse(&stripped).unwrap();

        // Present-but-empty: the DACL is still there, with zero ACEs —
        // distinct from an absent (NULL) DACL.
        assert!(parsed.control & SE_DACL_PRESENT != 0);
        let dacl = parsed.dacl().unwrap().unwrap();
        assert_eq!(dacl.ace_count, 0);
        assert_eq!(dacl.size, 8);
    }

    #[test]
    fn strip_absent_dacl_stays_absent() {
        let sd = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .build()
            .unwrap();
        let stripped = strip_inherited_aces(&sd, SecurityInfo::dacl()).unwrap();
        let parsed = SecurityDescriptor::parse(&stripped).unwrap();
        assert_eq!(parsed.control & SE_DACL_PRESENT, 0);
        assert!(parsed.dacl().is_none());
    }

    #[test]
    fn strip_dacl_and_sacl_together() {
        let sd = SdBuilder::new()
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Everyone,
                        ACCESS_GENERIC_READ,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .sacl(
                AclBuilder::new()
                    .ace(
                        AceBuilder::audit(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                            .flags(ACE_FLAG_INHERITED),
                    )
                    .ace(AceBuilder::audit(
                        WellKnownSid::LocalSystem,
                        ACCESS_GENERIC_ALL,
                    )),
            )
            .build()
            .unwrap();
        let stripped = strip_inherited_aces(&sd, SecurityInfo::dacl().with_sacl()).unwrap();
        let parsed = SecurityDescriptor::parse(&stripped).unwrap();
        assert_eq!(parsed.dacl().unwrap().unwrap().ace_count, 1);
        assert_eq!(parsed.sacl().unwrap().unwrap().ace_count, 1);
    }

    #[test]
    fn strip_leaves_unselected_acl_byte_identical() {
        let sd = SdBuilder::new()
            .dacl(
                AclBuilder::new().ace(
                    AceBuilder::allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
                        .flags(ACE_FLAG_INHERITED),
                ),
            )
            .sacl(
                AclBuilder::new().ace(
                    AceBuilder::audit(WellKnownSid::Everyone, ACCESS_GENERIC_READ)
                        .flags(ACE_FLAG_INHERITED),
                ),
            )
            .build()
            .unwrap();
        // Strip the DACL only — the SACL must come through untouched.
        let stripped = strip_inherited_aces(&sd, SecurityInfo::dacl()).unwrap();
        let src = SecurityDescriptor::parse(&sd).unwrap();
        let out = SecurityDescriptor::parse(&stripped).unwrap();
        assert_eq!(
            src.sacl().unwrap().unwrap().bytes,
            out.sacl().unwrap().unwrap().bytes,
        );
        assert_eq!(out.dacl().unwrap().unwrap().ace_count, 0);
    }

    #[test]
    fn strip_is_idempotent() {
        let sd = SdBuilder::new()
            .owner(WellKnownSid::LocalSystem)
            .dacl(
                AclBuilder::new()
                    .ace(AceBuilder::allow(
                        WellKnownSid::Everyone,
                        ACCESS_GENERIC_READ,
                    ))
                    .ace(
                        AceBuilder::allow(WellKnownSid::LocalSystem, ACCESS_GENERIC_ALL)
                            .flags(ACE_FLAG_INHERITED),
                    ),
            )
            .build()
            .unwrap();
        let once = strip_inherited_aces(&sd, SecurityInfo::dacl()).unwrap();
        let twice = strip_inherited_aces(&once, SecurityInfo::dacl()).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn strip_rejects_truncated_input() {
        let too_short = [0u8; 10];
        assert!(matches!(
            strip_inherited_aces(&too_short, SecurityInfo::dacl()),
            Err(Error::Parse(_))
        ));
    }

    #[test]
    fn strip_rejects_non_self_relative() {
        // A 20-byte SD header whose control word lacks SE_SELF_RELATIVE.
        let mut absolute = [0u8; SD_HEADER_BYTES];
        absolute[0] = 1; // revision
        assert!(matches!(
            strip_inherited_aces(&absolute, SecurityInfo::dacl()),
            Err(Error::Parse(ParseError::SdNotSelfRelative))
        ));
    }
}
