// Errors produced by libp-sd's safe-API surface.

use crate::sddl::SddlError;
use libp_errno::Errno;
use libp_wire::ParseError;
use thiserror::Error;

/// Errors from libp-sd.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum Error {
    /// A `kacs_get_sd` / `kacs_set_sd` syscall returned `-errno`.
    #[error("kacs SD syscall failed: {0}")]
    Syscall(Errno),

    /// An SD / ACL / ACE blob couldn't be parsed.
    #[error("security descriptor did not parse: {0}")]
    Parse(#[from] ParseError),

    /// `get_sd` reported a descriptor larger than the buffer the caller
    /// provided. Carries the size the kernel says it needs.
    #[error("get_sd buffer too small: need {needed} bytes")]
    BufferTooSmall { needed: usize },

    /// A builder was handed an input that can't be encoded — e.g. an
    /// ACL with more ACEs than the 16-bit count field allows.
    #[error("security descriptor would not encode: {0}")]
    Encode(&'static str),

    /// SDDL text input couldn't be parsed, or a binary SD couldn't be
    /// formatted as SDDL.
    #[error("SDDL: {0}")]
    Sddl(#[from] SddlError),
}

impl From<Errno> for Error {
    fn from(e: Errno) -> Self {
        Error::Syscall(e)
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Syscall(errno) => std::io::Error::from(errno),
            other => std::io::Error::other(other.to_string()),
        }
    }
}
