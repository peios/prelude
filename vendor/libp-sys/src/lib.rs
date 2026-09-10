// libp-sys — direct kernel syscall invocation. no_std, no libc.
//
// Per the peios-rs design doc, syscalls are invoked via direct inline
// asm rather than through the C library. This keeps the entire libp
// stack libc-free, removes a layer that doesn't help us (libc's
// `syscall(3)` is just an asm wrapper), and pre-aligns the path to
// Tier 3 (replacing musl entirely).
//
// This is the libp-rs analogue of libp-go's `internal/sys` package: the
// raw syscall mechanism plus the EINTR-retry helper that safe-API
// wrappers loop their invocations through.
//
// Architecture support: x86_64 only for v1. aarch64 stubs come when
// Peios runs on that arch.
//
// Each `syscall<N>` returns the raw signed kernel return code:
//   - On success, a non-negative value (fd, byte count, etc.).
//   - On failure, `-errno` (negative).
//
// Callers in `libp-*::raw` wrap these in typed signatures; the safe layer
// above invokes them through `eintr_retry`.

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]

use libp_errno::EINTR;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    use core::arch::asm;

    // Safety contract shared by all syscall<N> functions in this module:
    //
    //   - The kernel may interpret any of the argument registers as a
    //     pointer. The caller must ensure that any pointer-shaped
    //     argument points to a valid, properly-aligned memory region of
    //     the size the kernel expects for the given syscall.
    //   - Some syscalls modify caller memory (e.g. `read(2)` writes the
    //     buffer). The caller must hold exclusive access for the
    //     duration of the call.
    //   - The syscall instruction does not preserve `rcx` or `r11`; this
    //     is encoded in the `out("rcx")` / `out("r11")` clobbers below.
    //   - The call is `nostack` and `preserves_flags`. It must not be
    //     used for syscalls that the kernel documents as clobbering
    //     either property (Linux x86_64 has none in current use).

    /// 0-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract: the caller must ensure the syscall
    /// number is valid and the kernel side has no side-effects on memory
    /// the caller is currently accessing.
    #[inline]
    pub unsafe fn syscall0(n: i64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 1-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall1(n: i64, a1: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 2-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall2(n: i64, a1: u64, a2: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 3-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall3(n: i64, a1: u64, a2: u64, a3: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 4-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall4(n: i64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 5-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall5(n: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                in("r8") a5,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    /// 6-argument syscall.
    ///
    /// # Safety
    /// See the module-level contract.
    #[inline]
    pub unsafe fn syscall6(n: i64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
        let ret: i64;
        unsafe {
            asm!(
                "syscall",
                inlateout("rax") n => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                in("r8") a5,
                in("r9") a6,
                out("rcx") _,
                out("r11") _,
                options(nostack, preserves_flags),
            );
        }
        ret
    }

    // ----- well-known generic Linux syscall numbers used by helpers below -----

    /// Linux x86_64 `__NR_ioctl`.
    pub const SYS_IOCTL: i64 = 16;

    /// Linux x86_64 `__NR_close`.
    pub const SYS_CLOSE: i64 = 3;

    /// Linux x86_64 `__NR_mmap`.
    pub const SYS_MMAP: i64 = 9;

    /// Linux x86_64 `__NR_munmap`.
    pub const SYS_MUNMAP: i64 = 11;

    /// Linux x86_64 `__NR_futex`.
    pub const SYS_FUTEX: i64 = 202;
}

#[cfg(not(target_arch = "x86_64"))]
compile_error!(
    "libp-sys currently supports only x86_64. \
     Add per-arch asm stubs to crates/libp-sys/src/lib.rs when porting."
);

// ---------------------------------------------------------------------------
// Common helpers built on the raw syscalls above. These are still
// `unsafe` since the kernel can read memory the caller passes through
// pointer-shaped arguments.
// ---------------------------------------------------------------------------

/// Invoke `ioctl(fd, req, arg)`. `arg` is treated as opaque — pass the
/// pointer's bit pattern as `u64`.
///
/// # Safety
/// If `arg` is a pointer, the caller must ensure it points to a valid,
/// properly-aligned memory region of the size the kernel expects for
/// the given `req`. `fd` must be a valid open file descriptor of a
/// driver/object the kernel knows how to dispatch.
#[inline]
pub unsafe fn ioctl(fd: i32, req: u64, arg: u64) -> i64 {
    unsafe { syscall3(SYS_IOCTL, fd as u64, req, arg) }
}

/// Invoke `close(fd)`. Returns 0 on success or `-errno` on failure.
///
/// # Safety
/// The caller must ensure no other code in the process is concurrently
/// using `fd`; closing a file descriptor that another thread is using
/// is a classic use-after-free.
#[inline]
pub unsafe fn close(fd: i32) -> i64 {
    unsafe { syscall1(SYS_CLOSE, fd as u64) }
}

// ---------------------------------------------------------------------------
// mmap / futex constants and helpers. Generic across Linux architectures;
// the numeric values are stable ABI.
// ---------------------------------------------------------------------------

/// `mmap` protection bit: pages may be read.
pub const PROT_READ: i32 = 0x1;

/// `mmap` protection bit: pages may be written.
pub const PROT_WRITE: i32 = 0x2;

/// `mmap` flag: the mapping is shared — writes carry through to the
/// backing object and are visible to other mappers.
pub const MAP_SHARED: i32 = 0x1;

/// `futex` operation: wait until the futex word at `uaddr` changes.
pub const FUTEX_WAIT: i32 = 0;

/// POSIX `struct timespec`. Used for syscall timeouts (e.g. `futex`).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timespec {
    /// Whole seconds.
    pub tv_sec: i64,
    /// Nanoseconds (`0..1_000_000_000`).
    pub tv_nsec: i64,
}

/// Invoke `mmap(addr, len, prot, flags, fd, offset)`.
///
/// Returns the mapped address as a non-negative value, or `-errno` on
/// failure. Valid userspace addresses sit well within the positive `i64`
/// range, so callers may treat any negative return as the error case.
///
/// # Safety
/// `fd` must be a valid file descriptor that supports mapping. The caller
/// is responsible for eventually `munmap`-ing the returned region and for
/// not aliasing it unsafely.
#[inline]
pub unsafe fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, offset: i64) -> i64 {
    unsafe {
        syscall6(
            SYS_MMAP,
            addr as u64,
            len as u64,
            prot as u64,
            flags as u64,
            fd as u64,
            offset as u64,
        )
    }
}

/// Invoke `munmap(addr, len)`. Returns 0 on success or `-errno`.
///
/// # Safety
/// `addr` and `len` must describe a region previously returned by `mmap`.
/// No live references into the region may exist when it is unmapped.
#[inline]
pub unsafe fn munmap(addr: *mut u8, len: usize) -> i64 {
    unsafe { syscall2(SYS_MUNMAP, addr as u64, len as u64) }
}

/// Invoke `futex(uaddr, FUTEX_WAIT, val, timeout, NULL, 0)` — a *shared*
/// (non-private) wait.
///
/// Returns 0 when woken, or `-errno`: `-EAGAIN` if `*uaddr != val` (the
/// wait was never entered — treat as a spurious wake), `-ETIMEDOUT` if
/// `timeout` elapsed, `-EINTR` if a signal arrived.
///
/// The wait is deliberately shared (no `FUTEX_PRIVATE_FLAG`): KMES wakes
/// ring-buffer consumers using the shared futex key derived from the
/// producer page's backing inode, so a private wait would never match.
///
/// # Safety
/// `uaddr` must point to a valid, aligned `u32` in mapped memory. If
/// `timeout` is non-null it must point to a valid `Timespec` that
/// outlives the call.
#[inline]
pub unsafe fn futex_wait(uaddr: *const u32, val: u32, timeout: *const Timespec) -> i64 {
    unsafe {
        syscall6(
            SYS_FUTEX,
            uaddr as u64,
            FUTEX_WAIT as u64,
            val as u64,
            timeout as u64,
            0,
            0,
        )
    }
}

// ---------------------------------------------------------------------------
// Retry helper. Most safe-API wrappers in libp-* should loop their syscall
// invocation through this so callers don't see EINTR. Event-wait APIs
// explicitly bypass it. (libp-go's `internal/sys.Retry`.)
// ---------------------------------------------------------------------------

/// Call `op` until it returns something other than `-EINTR`.
///
/// `op` must return the raw signed syscall return code (negative on
/// error). This helper exists so that libp-* safe-API wrappers can hide
/// signal-interrupt noise from callers without writing the retry loop
/// at every call site.
#[inline]
pub fn eintr_retry<F>(mut op: F) -> i64
where
    F: FnMut() -> i64,
{
    loop {
        let rc = op();
        if rc != -(EINTR as i64) {
            return rc;
        }
    }
}
