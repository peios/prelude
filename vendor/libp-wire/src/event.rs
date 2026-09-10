// KMES event header — the on-wire primitive a consumer parses out of a
// ring-buffer slot. The KMES *domain* (ring mmap layout, emit/attach,
// batch descriptors) lives in libp-event; this is just the header parser,
// mirroring libp-go's `wire.ParseEvent`.
//
// Event header (29 bytes, little-endian):
//   u32 event_size      — total bytes including header
//   u32 header_size     — bytes before the payload (header_base + type)
//   u64 timestamp       — ktime_get_real_ns() at emit time
//   u64 sequence        — monotonic per ring
//   u16 cpu_id
//   u8  origin_class    — a KMES_ORIGIN_* value
//   u16 event_type_len
//   then event_type bytes
//   then payload bytes  — kernel validator requires this to parse as msgpack

use crate::error::ParseError;

// Header field offsets, sourced from the generated uapi so they cannot
// drift from the kernel ABI.
const H_EVENT_SIZE: usize = peios_uapi::KMES_EVENT_SIZE_OFFSET as usize;
const H_HEADER_SIZE: usize = peios_uapi::KMES_EVENT_HEADER_SIZE_OFFSET as usize;
const H_TIMESTAMP: usize = peios_uapi::KMES_EVENT_TIMESTAMP_NS_OFFSET as usize;
const H_SEQUENCE: usize = peios_uapi::KMES_EVENT_SEQUENCE_OFFSET as usize;
const H_CPU_ID: usize = peios_uapi::KMES_EVENT_CPU_ID_OFFSET as usize;
const H_ORIGIN: usize = peios_uapi::KMES_EVENT_ORIGIN_CLASS_OFFSET as usize;
const H_EFFECTIVE_TOKEN_GUID: usize =
    peios_uapi::KMES_EVENT_EFFECTIVE_TOKEN_GUID_OFFSET as usize;
const H_TRUE_TOKEN_GUID: usize = peios_uapi::KMES_EVENT_TRUE_TOKEN_GUID_OFFSET as usize;
const H_PROCESS_GUID: usize = peios_uapi::KMES_EVENT_PROCESS_GUID_OFFSET as usize;
const GUID_SIZE: usize = peios_uapi::KMES_EVENT_GUID_SIZE as usize;
const H_EVENT_TYPE_LEN: usize = peios_uapi::KMES_EVENT_TYPE_LEN_OFFSET as usize;
const HDR_BASE: usize = peios_uapi::KMES_EVENT_HEADER_BASE_SIZE as usize;

/// The origin class of a KMES event — which subsystem emitted it.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Origin(pub u8);

impl Origin {
    /// Emitted by userspace via the KMES emit syscall.
    pub const USERSPACE: Self = Self(peios_uapi::KMES_ORIGIN_USERSPACE as u8);
    /// Emitted by the KMES subsystem itself.
    pub const KMES: Self = Self(peios_uapi::KMES_ORIGIN_KMES as u8);
    /// Emitted by KACS (access control).
    pub const KACS: Self = Self(peios_uapi::KMES_ORIGIN_KACS as u8);
    /// Emitted by LCS (the registry).
    pub const LCS: Self = Self(peios_uapi::KMES_ORIGIN_LCS as u8);

    /// The raw origin-class byte.
    #[inline]
    pub const fn raw(self) -> u8 {
        self.0
    }

    /// A short mnemonic for known origins, or `"????"` for unknown.
    pub fn name(self) -> &'static str {
        match self {
            Origin::USERSPACE => "USER",
            Origin::KMES => "KMES",
            Origin::KACS => "KACS",
            Origin::LCS => "LCS",
            _ => "????",
        }
    }
}

/// A short mnemonic for a raw origin-class byte. Convenience for callers
/// holding the raw [`EventHeader::origin`] byte (e.g. validation display).
pub fn origin_name(o: u8) -> &'static str {
    Origin(o).name()
}

/// Parsed KMES event header.
pub struct EventHeader<'a> {
    pub event_size: u32,
    pub header_size: u32,
    pub timestamp_ns: u64,
    pub sequence: u64,
    pub cpu_id: u16,
    /// The raw origin-class byte; interpret via [`Origin`].
    pub origin: u8,
    /// GUID (16 bytes) of the effective token at emission time. The null
    /// GUID (all zero) means identity was unavailable (KACS not initialised
    /// or no process context).
    pub effective_token_guid: &'a [u8],
    /// GUID (16 bytes) of the process's primary token at emission time.
    pub true_token_guid: &'a [u8],
    /// GUID (16 bytes) of the emitting process, assigned at fork.
    pub process_guid: &'a [u8],
    pub event_type: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> EventHeader<'a> {
    /// Parse one event laid out at the start of `bytes`. The slice must be at
    /// least `event_size` bytes long.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() < HDR_BASE {
            return Err(ParseError::EventHeaderTruncated);
        }
        let event_size =
            u32::from_le_bytes(bytes[H_EVENT_SIZE..H_EVENT_SIZE + 4].try_into().unwrap());
        let header_size =
            u32::from_le_bytes(bytes[H_HEADER_SIZE..H_HEADER_SIZE + 4].try_into().unwrap());
        let timestamp_ns =
            u64::from_le_bytes(bytes[H_TIMESTAMP..H_TIMESTAMP + 8].try_into().unwrap());
        let sequence = u64::from_le_bytes(bytes[H_SEQUENCE..H_SEQUENCE + 8].try_into().unwrap());
        let cpu_id = u16::from_le_bytes(bytes[H_CPU_ID..H_CPU_ID + 2].try_into().unwrap());
        let origin = bytes[H_ORIGIN];
        // GUID ranges sit within HDR_BASE, already bounds-checked above.
        let effective_token_guid =
            &bytes[H_EFFECTIVE_TOKEN_GUID..H_EFFECTIVE_TOKEN_GUID + GUID_SIZE];
        let true_token_guid = &bytes[H_TRUE_TOKEN_GUID..H_TRUE_TOKEN_GUID + GUID_SIZE];
        let process_guid = &bytes[H_PROCESS_GUID..H_PROCESS_GUID + GUID_SIZE];
        let etlen = u16::from_le_bytes(
            bytes[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
                .try_into()
                .unwrap(),
        ) as usize;

        let type_start = HDR_BASE;
        let type_end = type_start + etlen;
        let total = event_size as usize;
        let hdr = header_size as usize;
        // Structural validation. The payload is located via `header_size`,
        // not the end of the event type string: PSD-003 §2.2 mandates this
        // so consumers stay correct if a future header revision inserts
        // reserved fields between the type string and the payload.
        if total < HDR_BASE
            || total > bytes.len()
            || hdr < HDR_BASE
            || hdr > total
            || type_end > hdr
        {
            return Err(ParseError::EventSizeInvalid);
        }
        Ok(Self {
            event_size,
            header_size,
            timestamp_ns,
            sequence,
            cpu_id,
            origin,
            effective_token_guid,
            true_token_guid,
            process_guid,
            event_type: &bytes[type_start..type_end],
            payload: &bytes[hdr..total],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_constants_match_kmes_header() {
        assert_eq!(Origin::USERSPACE.raw(), 0);
        assert_eq!(Origin::KMES.raw(), 1);
        assert_eq!(Origin::KACS.raw(), 2);
        assert_eq!(Origin::LCS.raw(), 3);
        assert_eq!(origin_name(2), "KACS");
        assert_eq!(origin_name(9), "????");
    }

    /// Build a synthetic event with `header_size == HDR_BASE + type_len`
    /// (the v0.20 minimum) and round-trip it through `EventHeader::parse`.
    #[test]
    fn parse_minimal_event() {
        let type_str = b"test.event";
        let payload = b"\x81\xa1k\x01";
        let header_size = HDR_BASE + type_str.len();
        let event_size = header_size + payload.len();

        let mut buf = alloc::vec![0u8; event_size];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(event_size as u32).to_le_bytes());
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4].copy_from_slice(&(header_size as u32).to_le_bytes());
        buf[H_TIMESTAMP..H_TIMESTAMP + 8].copy_from_slice(&123u64.to_le_bytes());
        buf[H_SEQUENCE..H_SEQUENCE + 8].copy_from_slice(&7u64.to_le_bytes());
        buf[H_CPU_ID..H_CPU_ID + 2].copy_from_slice(&2u16.to_le_bytes());
        buf[H_ORIGIN] = Origin::KACS.raw();
        buf[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
            .copy_from_slice(&(type_str.len() as u16).to_le_bytes());
        buf[HDR_BASE..HDR_BASE + type_str.len()].copy_from_slice(type_str);
        buf[header_size..].copy_from_slice(payload);

        let ev = EventHeader::parse(&buf).unwrap();
        assert_eq!(ev.event_size, event_size as u32);
        assert_eq!(ev.timestamp_ns, 123);
        assert_eq!(ev.sequence, 7);
        assert_eq!(ev.cpu_id, 2);
        assert_eq!(ev.origin, Origin::KACS.raw());
        assert_eq!(ev.event_type, type_str);
        assert_eq!(ev.payload, payload);
    }

    /// `header_size` larger than `HDR_BASE + type_len` — a reserved gap.
    /// The payload MUST still be located via `header_size`.
    #[test]
    fn parse_uses_header_size_for_payload() {
        let type_str = b"x";
        let gap = 8usize;
        let header_size = HDR_BASE + type_str.len() + gap;
        let payload = b"\xc3";
        let event_size = header_size + payload.len();

        let mut buf = alloc::vec![0u8; event_size];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(event_size as u32).to_le_bytes());
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4].copy_from_slice(&(header_size as u32).to_le_bytes());
        buf[H_EVENT_TYPE_LEN..H_EVENT_TYPE_LEN + 2]
            .copy_from_slice(&(type_str.len() as u16).to_le_bytes());
        buf[HDR_BASE..HDR_BASE + type_str.len()].copy_from_slice(type_str);
        buf[header_size..].copy_from_slice(payload);

        let ev = EventHeader::parse(&buf).unwrap();
        assert_eq!(ev.event_type, type_str);
        assert_eq!(ev.payload, payload);
    }

    #[test]
    fn parse_rejects_header_size_past_event() {
        let mut buf = alloc::vec![0u8; HDR_BASE];
        buf[H_EVENT_SIZE..H_EVENT_SIZE + 4].copy_from_slice(&(HDR_BASE as u32).to_le_bytes());
        // header_size declares more bytes than the event has.
        buf[H_HEADER_SIZE..H_HEADER_SIZE + 4]
            .copy_from_slice(&(HDR_BASE as u32 + 16).to_le_bytes());
        assert!(matches!(
            EventHeader::parse(&buf),
            Err(ParseError::EventSizeInvalid)
        ));
    }
}
