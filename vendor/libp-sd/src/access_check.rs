// AccessCheck — `kacs_access_check` (scalar) and
// `kacs_access_check_list` (object-tree).
//
// "Given this token, would this desired-access mask be granted against
// this security descriptor?" — without actually opening anything.
//
// `AccessCheckRequest` is a builder; it owns the side buffers (SD,
// self-SID, object tree, claims, audit context) and assembles the
// 136-byte `kacs_access_check_args` for the syscall.

use crate::Result;
use crate::claims::{ClaimAttribute, encode_claims_array};
use crate::error::Error;
use crate::object_tree::{ObjectTypeNode, encode_object_tree};
use alloc::vec::Vec;
use crate::abi::{KACS_ACCESS_CHECK_ARGS_SIZE, KacsAccessCheckArgs, KacsNodeResult};
use crate::codec::GenericMapping;
use libp_errno::{EACCES, Errno};
use libp_sys::{eintr_retry, syscall1, syscall3};
use libp_wire::Sid;
use peios_uapi::{SYS_KACS_ACCESS_CHECK, SYS_KACS_ACCESS_CHECK_LIST};

/// The outcome of a scalar access check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessDecision {
    /// True if the check granted access (kernel did not return
    /// `-EACCES`).
    pub granted: bool,
    /// The access mask the kernel reported as granted. Zero on denial.
    pub granted_mask: u32,
}

/// The per-node outcome of an `access_check_list` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeDecision {
    /// Granted access mask for this object-tree node.
    pub granted_mask: u32,
    /// NTSTATUS-style status (0 = granted).
    pub status: i32,
}

/// Builder for an AccessCheck request.
pub struct AccessCheckRequest<'a> {
    token_fd: i32,
    sd: &'a [u8],
    desired_access: u32,
    mapping: GenericMapping,
    self_sid: Option<Sid>,
    privilege_intent: u32,
    object_tree: Vec<ObjectTypeNode>,
    local_claims: Vec<ClaimAttribute>,
    pip_type: u32,
    pip_trust: u32,
    audit_context: Option<Vec<u8>>,
}

impl<'a> AccessCheckRequest<'a> {
    /// A minimal request: check `desired_access` for `token_fd` against
    /// the self-relative descriptor `sd`.
    pub fn new(token_fd: i32, sd: &'a [u8], desired_access: u32) -> Self {
        AccessCheckRequest {
            token_fd,
            sd,
            desired_access,
            mapping: GenericMapping::default(),
            self_sid: None,
            privilege_intent: 0,
            object_tree: Vec::new(),
            local_claims: Vec::new(),
            pip_type: 0,
            pip_trust: 0,
            audit_context: None,
        }
    }

    /// Set the generic-access mapping.
    pub fn mapping(mut self, mapping: GenericMapping) -> Self {
        self.mapping = mapping;
        self
    }

    /// Provide the `PRINCIPAL_SELF` substitution SID.
    pub fn self_sid(mut self, sid: Sid) -> Self {
        self.self_sid = Some(sid);
        self
    }

    /// Set the privilege-intent flags.
    pub fn privilege_intent(mut self, flags: u32) -> Self {
        self.privilege_intent = flags;
        self
    }

    /// Append an object-type tree node. Needed for `check_list`; the
    /// scalar `check` ignores the tree.
    pub fn object_node(mut self, node: ObjectTypeNode) -> Self {
        self.object_tree.push(node);
        self
    }

    /// Append a `@Local` claim attribute for conditional-ACE evaluation.
    pub fn claim(mut self, claim: ClaimAttribute) -> Self {
        self.local_claims.push(claim);
        self
    }

    /// Set the PSB-derived PIP axes.
    pub fn pip(mut self, pip_type: u32, pip_trust: u32) -> Self {
        self.pip_type = pip_type;
        self.pip_trust = pip_trust;
        self
    }

    /// Attach an object-audit context blob.
    pub fn audit_context(mut self, ctx: Vec<u8>) -> Self {
        self.audit_context = Some(ctx);
        self
    }

    /// Build the side buffers + the `kacs_access_check_args` struct.
    /// Returns the struct plus the buffers it points into — the
    /// buffers MUST outlive any syscall using the struct.
    fn assemble(&self, granted_out: &mut u32) -> Result<Assembled> {
        let self_sid_bytes = self.self_sid.as_ref().map(|s| s.encode());
        let object_tree_bytes = encode_object_tree(&self.object_tree);
        let claims_bytes = encode_claims_array(&self.local_claims)?;

        if self.sd.is_empty() {
            return Err(Error::Encode("access check requires a security descriptor"));
        }

        let args = KacsAccessCheckArgs {
            caller_size: KACS_ACCESS_CHECK_ARGS_SIZE,
            token_fd: self.token_fd,
            sd_ptr: self.sd.as_ptr() as u64,
            sd_len: self.sd.len() as u32,
            desired_access: self.desired_access,
            mapping_read: self.mapping.read,
            mapping_write: self.mapping.write,
            mapping_execute: self.mapping.execute,
            mapping_all: self.mapping.all,
            self_sid_ptr: ptr_or_zero(self_sid_bytes.as_deref()),
            self_sid_len: len_or_zero(self_sid_bytes.as_deref()),
            privilege_intent: self.privilege_intent,
            object_tree_ptr: if self.object_tree.is_empty() {
                0
            } else {
                object_tree_bytes.as_ptr() as u64
            },
            object_tree_count: self.object_tree.len() as u32,
            _pad0: 0,
            local_claims_ptr: if claims_bytes.is_empty() {
                0
            } else {
                claims_bytes.as_ptr() as u64
            },
            local_claims_len: claims_bytes.len() as u32,
            _pad1: 0,
            granted_out_ptr: granted_out as *mut u32 as u64,
            pip_type: self.pip_type,
            pip_trust: self.pip_trust,
            audit_context_ptr: ptr_or_zero(self.audit_context.as_deref()),
            audit_context_len: len_or_zero(self.audit_context.as_deref()),
            _pad2: 0,
            continuous_audit_out_ptr: 0,
            staging_mismatch_out_ptr: 0,
        };

        Ok(Assembled {
            args,
            _self_sid: self_sid_bytes,
            _object_tree: object_tree_bytes,
            _claims: claims_bytes,
        })
    }

    /// Run a scalar access check.
    ///
    /// Returns `Ok(AccessDecision { granted: false, .. })` when the
    /// kernel denies access (`-EACCES`) — denial is a valid answer, not
    /// an error. Any other `-errno` is an `Err`.
    pub fn check(&self) -> Result<AccessDecision> {
        let mut granted: u32 = 0;
        let assembled = self.assemble(&mut granted)?;
        let args_ptr = &assembled.args as *const KacsAccessCheckArgs as u64;
        let rc = eintr_retry(|| unsafe { syscall1(SYS_KACS_ACCESS_CHECK as i64, args_ptr) });
        // Keep the side buffers alive until the syscall has returned.
        drop(assembled);
        if rc == -(EACCES as i64) {
            return Ok(AccessDecision {
                granted: false,
                granted_mask: granted,
            });
        }
        if rc < 0 {
            return Err(Error::Syscall(Errno::from_raw(rc)));
        }
        Ok(AccessDecision {
            granted: true,
            granted_mask: granted,
        })
    }

    /// Run a result-list access check over the object-type tree.
    /// Returns one [`NodeDecision`] per object-tree node, in tree order.
    ///
    /// Requires at least one object-tree node (`object_node`).
    pub fn check_list(&self) -> Result<Vec<NodeDecision>> {
        if self.object_tree.is_empty() {
            return Err(Error::Encode(
                "access_check_list requires at least one object-tree node",
            ));
        }
        let count = self.object_tree.len();
        let mut granted: u32 = 0;
        let assembled = self.assemble(&mut granted)?;
        let mut results: Vec<KacsNodeResult> =
            (0..count).map(|_| KacsNodeResult::default()).collect();

        let args_ptr = &assembled.args as *const KacsAccessCheckArgs as u64;
        let rc = eintr_retry(|| unsafe {
            syscall3(
                SYS_KACS_ACCESS_CHECK_LIST as i64,
                args_ptr,
                results.as_mut_ptr() as u64,
                count as u64,
            )
        });
        drop(assembled);
        if rc < 0 {
            return Err(Error::Syscall(Errno::from_raw(rc)));
        }
        Ok(results
            .iter()
            .map(|r| NodeDecision {
                granted_mask: r.granted,
                status: r.status,
            })
            .collect())
    }
}

/// The assembled args struct plus the buffers its pointers reference.
/// Fields are kept (not dead code) precisely so they outlive the
/// syscall — the struct's pointers alias into them.
struct Assembled {
    args: KacsAccessCheckArgs,
    _self_sid: Option<Vec<u8>>,
    _object_tree: Vec<u8>,
    _claims: Vec<u8>,
}

fn ptr_or_zero(b: Option<&[u8]>) -> u64 {
    match b {
        Some(s) if !s.is_empty() => s.as_ptr() as u64,
        _ => 0,
    }
}

fn len_or_zero(b: Option<&[u8]>) -> u32 {
    match b {
        Some(s) => s.len() as u32,
        None => 0,
    }
}
