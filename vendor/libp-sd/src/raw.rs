// Raw KACS SD syscall wrappers.
//
// `unsafe`, numeric-return, no EINTR retry — same contract as
// `libp_token::raw`. The safe `get_sd` / `set_sd` in this crate wrap
// these.

use libp_sys::syscall6;
use peios_uapi::{SYS_KACS_GET_SD, SYS_KACS_SET_SD};

/// `kacs_get_sd(dirfd, path, security_info, buf, buf_len, flags)`.
///
/// Returns the descriptor's total length on success (which may exceed
/// `buf_len` — that's the probe protocol), or `-errno`.
///
/// # Safety
/// `path` must point to a NUL-terminated string valid for the call.
/// If `buf_len != 0`, `buf` must point to `buf_len` writable bytes.
#[inline]
pub unsafe fn get_sd(
    dirfd: i32,
    path: *const u8,
    security_info: u32,
    buf: *mut u8,
    buf_len: u32,
    flags: u32,
) -> i64 {
    unsafe {
        syscall6(
            SYS_KACS_GET_SD as i64,
            dirfd as u64,
            path as u64,
            security_info as u64,
            buf as u64,
            buf_len as u64,
            flags as u64,
        )
    }
}

/// `kacs_set_sd(dirfd, path, security_info, sd_buf, sd_len, flags)`.
///
/// Returns 0 on success or `-errno`.
///
/// # Safety
/// `path` must point to a NUL-terminated string valid for the call.
/// `sd_buf` must point to `sd_len` readable bytes encoding a
/// self-relative SECURITY_DESCRIPTOR.
#[inline]
pub unsafe fn set_sd(
    dirfd: i32,
    path: *const u8,
    security_info: u32,
    sd_buf: *const u8,
    sd_len: u32,
    flags: u32,
) -> i64 {
    unsafe {
        syscall6(
            SYS_KACS_SET_SD as i64,
            dirfd as u64,
            path as u64,
            security_info as u64,
            sd_buf as u64,
            sd_len as u64,
            flags as u64,
        )
    }
}

/// `AT_FDCWD` — dirfd value meaning "current working directory". Defined
/// by Linux UAPI as -100; it is a generic at-family constant, not part of
/// the KACS ABI headers, so it is spelled out here.
pub const FDCWD: i32 = -100;

/// `AT_EMPTY_PATH` — operate on the fd in `dirfd` itself, with an empty
/// path. Used for fd-targeted get_sd/set_sd.
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// `AT_SYMLINK_NOFOLLOW` — act on the symlink itself, not its target.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
