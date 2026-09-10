// libp-errno — the Errno newtype and the Linux errno constants.
//
// Kernel syscalls (Peios LSM and otherwise) return `-errno` on failure;
// libp captures the positive errno as `Errno(i32)`. Callers inspect it via
// the named constants below or via `raw()`.
//
// This is the libp-rs analogue of libp-go's `errno` package. The
// EINTR-retry helper that libp-go keeps in `internal/sys` lives in
// `libp-sys` here, not in this crate.
//
// `#[repr(transparent)]` so `Errno` crosses the C ABI as a bare `i32` —
// the canonical numeric-status type for the future libp.so C shim.

#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

/// A Linux errno value, captured as a positive integer.
///
/// Construct with `Errno::from_raw(rc)` where `rc` is the negative return
/// from a syscall (e.g. `-EACCES = -13`), or with `Errno::new(13)` for the
/// positive form.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Errno(pub i32);

impl Errno {
    /// Construct from a raw syscall return code. The argument is the
    /// signed value the kernel returned (negative on error). Positive or
    /// zero values map to `Errno(0)` which callers should treat as "no
    /// error" — this function is meant for the error branch.
    #[inline]
    pub const fn from_raw(rc: i64) -> Self {
        if rc >= 0 { Errno(0) } else { Errno(-rc as i32) }
    }

    /// Construct from a positive errno value (e.g. `Errno::new(13)` for
    /// EACCES). Negative arguments are treated as already-negated returns
    /// and normalized.
    #[inline]
    pub const fn new(value: i32) -> Self {
        if value < 0 {
            Errno(-value)
        } else {
            Errno(value)
        }
    }

    /// The raw positive errno value.
    #[inline]
    pub const fn raw(self) -> i32 {
        self.0
    }

    /// A short uppercase mnemonic (e.g. `"EACCES"`) for known values, or
    /// `"E<n>"` for unknown codes.
    pub fn name(self) -> &'static str {
        match self.0 {
            EPERM => "EPERM",
            ENOENT => "ENOENT",
            ESRCH => "ESRCH",
            EINTR => "EINTR",
            EIO => "EIO",
            ENXIO => "ENXIO",
            E2BIG => "E2BIG",
            ENOEXEC => "ENOEXEC",
            EBADF => "EBADF",
            ECHILD => "ECHILD",
            EAGAIN => "EAGAIN",
            ENOMEM => "ENOMEM",
            EACCES => "EACCES",
            EFAULT => "EFAULT",
            ENOTBLK => "ENOTBLK",
            EBUSY => "EBUSY",
            EEXIST => "EEXIST",
            EXDEV => "EXDEV",
            ENODEV => "ENODEV",
            ENOTDIR => "ENOTDIR",
            EISDIR => "EISDIR",
            EINVAL => "EINVAL",
            ENFILE => "ENFILE",
            EMFILE => "EMFILE",
            ENOTTY => "ENOTTY",
            ETXTBSY => "ETXTBSY",
            EFBIG => "EFBIG",
            ENOSPC => "ENOSPC",
            ESPIPE => "ESPIPE",
            EROFS => "EROFS",
            EMLINK => "EMLINK",
            EPIPE => "EPIPE",
            EDOM => "EDOM",
            ERANGE => "ERANGE",
            ENAMETOOLONG => "ENAMETOOLONG",
            ENOSYS => "ENOSYS",
            ENOTEMPTY => "ENOTEMPTY",
            ELOOP => "ELOOP",
            EOVERFLOW => "EOVERFLOW",
            EOPNOTSUPP => "EOPNOTSUPP",
            ETIMEDOUT => "ETIMEDOUT",
            _ => "E?",
        }
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name();
        if name == "E?" {
            write!(f, "E{}", self.0)
        } else {
            write!(f, "{} ({})", name, self.0)
        }
    }
}

impl core::error::Error for Errno {}

#[cfg(feature = "std")]
impl From<Errno> for std::io::Error {
    fn from(e: Errno) -> Self {
        std::io::Error::from_raw_os_error(e.0)
    }
}

// ---------------------------------------------------------------------------
// Linux errno constants. x86_64 / generic ABI values — same on every
// Linux architecture except a handful that diverge (mips/sparc/alpha)
// which Peios doesn't target.
// ---------------------------------------------------------------------------

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const ESRCH: i32 = 3;
pub const EINTR: i32 = 4;
pub const EIO: i32 = 5;
pub const ENXIO: i32 = 6;
pub const E2BIG: i32 = 7;
pub const ENOEXEC: i32 = 8;
pub const EBADF: i32 = 9;
pub const ECHILD: i32 = 10;
pub const EAGAIN: i32 = 11;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EFAULT: i32 = 14;
pub const ENOTBLK: i32 = 15;
pub const EBUSY: i32 = 16;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENODEV: i32 = 19;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENFILE: i32 = 23;
pub const EMFILE: i32 = 24;
pub const ENOTTY: i32 = 25;
pub const ETXTBSY: i32 = 26;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const ESPIPE: i32 = 29;
pub const EROFS: i32 = 30;
pub const EMLINK: i32 = 31;
pub const EPIPE: i32 = 32;
pub const EDOM: i32 = 33;
pub const ERANGE: i32 = 34;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ELOOP: i32 = 40;
pub const EOVERFLOW: i32 = 75;
pub const EOPNOTSUPP: i32 = 95;
pub const ENOTSUP: i32 = EOPNOTSUPP;
pub const ETIMEDOUT: i32 = 110;

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_negative() {
        assert_eq!(Errno::from_raw(-13).raw(), 13);
        assert_eq!(Errno::from_raw(-13).name(), "EACCES");
    }

    #[test]
    fn from_raw_zero_or_positive() {
        assert_eq!(Errno::from_raw(0).raw(), 0);
        assert_eq!(Errno::from_raw(5).raw(), 0);
    }

    #[test]
    fn unknown_errno_renders_numeric() {
        let e = Errno::new(255);
        assert_eq!(e.name(), "E?");
        let s = alloc::format!("{e}");
        assert_eq!(s, "E255");
    }

    #[test]
    fn known_errno_renders_with_name() {
        let e = Errno::new(EACCES);
        let s = alloc::format!("{e}");
        assert_eq!(s, "EACCES (13)");
    }

    #[test]
    fn enotsup_aliases_linux_eopnotsupp() {
        assert_eq!(ENOTSUP, EOPNOTSUPP);
        assert_eq!(ENOTSUP, 95);
    }
}
