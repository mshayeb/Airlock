//! Airlock `AF_VSOCK` multiplexed framing protocol (`spec.md` §7.4–§7.5).
//!
//! Every frame carries a fixed 16-byte little-endian header followed by optional
//! Context TLVs (reserved for Phase 2 MCP principal IDs and Phase 3 IFC taint
//! labels) and a variable-length payload.

use std::fmt;

/// Protocol magic bytes (`0x414C`, ASCII "AL").
pub const MAGIC: u16 = 0x414C;

/// Wire protocol version for Phase 1.
pub const VERSION: u8 = 1;

/// Fixed frame header length in bytes.
pub const HEADER_LEN: usize = 16;

/// Default principal identity used throughout Phase 1.
pub const DEFAULT_PRINCIPAL_ID: &str = "agent:main";

/// Maximum payload size per frame (16 MiB) to guard against allocation DoS.
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

/// Multiplexed stream channel types over `AF_VSOCK`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamType {
    ExecCtrl = 0x01,
    ExecIo = 0x02,
    HttpConnect = 0x03,
    L4TunTcp = 0x04,
    DnsQuery = 0x05,
    DiffExport = 0x06,
    Heartbeat = 0x07,
}

impl StreamType {
    /// Parses a byte into a [`StreamType`].
    pub fn from_u8(val: u8) -> Result<Self, ProtoError> {
        match val {
            0x01 => Ok(Self::ExecCtrl),
            0x02 => Ok(Self::ExecIo),
            0x03 => Ok(Self::HttpConnect),
            0x04 => Ok(Self::L4TunTcp),
            0x05 => Ok(Self::DnsQuery),
            0x06 => Ok(Self::DiffExport),
            0x07 => Ok(Self::Heartbeat),
            other => Err(ProtoError::UnknownStreamType(other)),
        }
    }
}

/// Bitmask flags carried in byte 8 of the frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameFlags(pub u8);

impl FrameFlags {
    pub const NONE: Self = Self(0x00);
    pub const FIN: u8 = 0x01;
    pub const RST: u8 = 0x02;
    pub const ACK: u8 = 0x04;
    pub const WINDOW_UPDATE: u8 = 0x08;

    pub fn has(self, flag: u8) -> bool {
        (self.0 & flag) != 0
    }
}

/// TLV type tags carried in the Context TLV section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContextTlvTag {
    /// Phase 2 seam: `"agent:main"` in Phase 1; `"mcp:<server>"` in Phase 2.
    PrincipalId = 0x01,
    /// Phase 3 seam: 2-byte `(confidentiality, integrity)` taint label pair.
    TaintLabels = 0x02,
}

/// Forward-compatible per-frame metadata carried in the Context TLV block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextMetadata {
    pub principal_id: Option<String>,
    pub taint_labels: Option<(u8, u8)>,
}

impl Default for ContextMetadata {
    fn default() -> Self {
        Self {
            principal_id: None,
            taint_labels: None,
        }
    }
}

impl ContextMetadata {
    /// Returns true if no TLV entries need serialization (Phase 1 fast-path).
    pub fn is_empty(&self) -> bool {
        self.principal_id.is_none() && self.taint_labels.is_none()
    }

    /// Serializes populated TLV items into wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        let mut out = Vec::new();
        if let Some(ref principal) = self.principal_id {
            let bytes = principal.as_bytes();
            let len = u16::try_from(bytes.len()).map_err(|_| ProtoError::ContextTooLarge)?;
            out.push(ContextTlvTag::PrincipalId as u8);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
        }
        if let Some((conf, integ)) = self.taint_labels {
            out.push(ContextTlvTag::TaintLabels as u8);
            out.extend_from_slice(&2u16.to_le_bytes());
            out.push(conf);
            out.push(integ);
        }
        if out.len() > u16::MAX as usize {
            return Err(ProtoError::ContextTooLarge);
        }
        Ok(out)
    }

    /// Parses TLVs from a slice; unknown tags are skipped safely for forward compatibility.
    pub fn decode(mut buf: &[u8]) -> Result<Self, ProtoError> {
        let mut meta = Self::default();
        while !buf.is_empty() {
            if buf.len() < 3 {
                return Err(ProtoError::MalformedTlv("truncated TLV header"));
            }
            let tag = buf[0];
            let len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
            buf = &buf[3..];
            if buf.len() < len {
                return Err(ProtoError::MalformedTlv("truncated TLV value"));
            }
            let val = &buf[..len];
            buf = &buf[len..];

            if tag == ContextTlvTag::PrincipalId as u8 {
                let s = std::str::from_utf8(val)
                    .map_err(|_| ProtoError::MalformedTlv("invalid UTF-8 principal_id"))?;
                meta.principal_id = Some(s.to_owned());
            } else if tag == ContextTlvTag::TaintLabels as u8 {
                if val.len() != 2 {
                    return Err(ProtoError::MalformedTlv("taint_labels must be 2 bytes"));
                }
                meta.taint_labels = Some((val[0], val[1]));
            }
        }
        Ok(meta)
    }
}

/// A single multiplexed `AF_VSOCK` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockFrame {
    pub stream_type: StreamType,
    pub stream_id: u32,
    pub flags: FrameFlags,
    pub context: ContextMetadata,
    pub payload: Vec<u8>,
}

impl VsockFrame {
    /// Creates a new Phase 1 frame with an empty Context TLV section.
    pub fn new(stream_type: StreamType, stream_id: u32, flags: FrameFlags, payload: Vec<u8>) -> Self {
        Self {
            stream_type,
            stream_id,
            flags,
            context: ContextMetadata::default(),
            payload,
        }
    }

    /// Encodes the frame into wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProtoError::PayloadTooLarge(self.payload.len()));
        }
        let tlv_bytes = self.context.encode()?;
        let tlv_len = tlv_bytes.len() as u16;
        let payload_len = self.payload.len() as u32;

        let mut buf = Vec::with_capacity(HEADER_LEN + tlv_bytes.len() + self.payload.len());
        buf.extend_from_slice(&MAGIC.to_le_bytes());
        buf.push(VERSION);
        buf.push(self.stream_type as u8);
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.push(self.flags.0);
        buf.push(0); // Reserved
        buf.extend_from_slice(&tlv_len.to_le_bytes());
        buf.extend_from_slice(&payload_len.to_le_bytes());
        buf.extend_from_slice(&tlv_bytes);
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Encodes into a caller-provided buffer to avoid per-frame allocations on hot paths.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), ProtoError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(ProtoError::PayloadTooLarge(self.payload.len()));
        }
        let tlv_bytes = self.context.encode()?;
        let tlv_len = tlv_bytes.len() as u16;
        let payload_len = self.payload.len() as u32;

        out.clear();
        out.reserve(HEADER_LEN + tlv_bytes.len() + self.payload.len());
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.push(VERSION);
        out.push(self.stream_type as u8);
        out.extend_from_slice(&self.stream_id.to_le_bytes());
        out.push(self.flags.0);
        out.push(0);
        out.extend_from_slice(&tlv_len.to_le_bytes());
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&tlv_bytes);
        out.extend_from_slice(&self.payload);
        Ok(())
    }

    /// Decodes a single frame from `buf`, returning `(frame, bytes_consumed)`.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize), ProtoError> {
        if buf.len() < HEADER_LEN {
            return Err(ProtoError::Incomplete(HEADER_LEN - buf.len()));
        }
        let magic = u16::from_le_bytes([buf[0], buf[1]]);
        if magic != MAGIC {
            return Err(ProtoError::InvalidMagic(magic));
        }
        let version = buf[2];
        if version != VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }
        let stream_type = StreamType::from_u8(buf[3])?;
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let flags = FrameFlags(buf[8]);
        // buf[9] is reserved; ignored by Phase 1 decoders
        let context_len = u16::from_le_bytes([buf[10], buf[11]]) as usize;
        let payload_len = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;

        if payload_len > MAX_PAYLOAD_LEN {
            return Err(ProtoError::PayloadTooLarge(payload_len));
        }
        let total = HEADER_LEN + context_len + payload_len;
        if buf.len() < total {
            return Err(ProtoError::Incomplete(total - buf.len()));
        }

        let context = if context_len == 0 {
            ContextMetadata::default()
        } else {
            ContextMetadata::decode(&buf[HEADER_LEN..HEADER_LEN + context_len])?
        };
        let payload = buf[HEADER_LEN + context_len..total].to_vec();

        Ok((
            Self {
                stream_type,
                stream_id,
                flags,
                context,
                payload,
            },
            total,
        ))
    }
}

/// Errors returned during frame serialization or parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    Incomplete(usize),
    InvalidMagic(u16),
    UnsupportedVersion(u8),
    UnknownStreamType(u8),
    ContextTooLarge,
    PayloadTooLarge(usize),
    MalformedTlv(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Incomplete(missing) => write!(f, "incomplete frame: need {missing} more bytes"),
            Self::InvalidMagic(m) => write!(f, "invalid frame magic: 0x{m:04x}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported protocol version: {v}"),
            Self::UnknownStreamType(s) => write!(f, "unknown stream type: 0x{s:02x}"),
            Self::ContextTooLarge => write!(f, "context TLV exceeds u16::MAX bytes"),
            Self::PayloadTooLarge(len) => write!(f, "payload length {len} exceeds limit"),
            Self::MalformedTlv(msg) => write!(f, "malformed context TLV: {msg}"),
        }
    }
}

impl std::error::Error for ProtoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_path_header_is_16_bytes_and_roundtrips() {
        let frame = VsockFrame::new(
            StreamType::HttpConnect,
            42,
            FrameFlags(FrameFlags::ACK),
            b"CONNECT github.com:443".to_vec(),
        );
        let bytes = frame.encode().expect("encode");
        assert_eq!(bytes.len(), HEADER_LEN + frame.payload.len());
        assert_eq!(&bytes[0..2], &MAGIC.to_le_bytes());
        assert_eq!(bytes[2], VERSION);
        assert_eq!(bytes[3], StreamType::HttpConnect as u8);
        assert_eq!(&bytes[10..12], &0u16.to_le_bytes());

        let (decoded, consumed) = VsockFrame::decode(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, frame);
    }

    #[test]
    fn phase2_and_phase3_tlv_seam_roundtrips() {
        let mut frame = VsockFrame::new(
            StreamType::ExecCtrl,
            7,
            FrameFlags(FrameFlags::FIN),
            b"{}".to_vec(),
        );
        frame.context = ContextMetadata {
            principal_id: Some("mcp:github-server".to_owned()),
            taint_labels: Some((2, 1)),
        };

        let bytes = frame.encode().expect("encode");
        let (decoded, consumed) = VsockFrame::decode(&bytes).expect("decode");
        assert_eq!(consumed, bytes.len());
        assert_eq!(decoded, frame);
    }

    #[test]
    fn rejects_bad_magic_and_partial_buffers() {
        let frame = VsockFrame::new(StreamType::Heartbeat, 1, FrameFlags::NONE, vec![1, 2, 3]);
        let mut bytes = frame.encode().expect("encode");

        assert_eq!(
            VsockFrame::decode(&bytes[..8]),
            Err(ProtoError::Incomplete(8))
        );
        assert_eq!(
            VsockFrame::decode(&bytes[..bytes.len() - 1]),
            Err(ProtoError::Incomplete(1))
        );

        bytes[0] = 0x00;
        assert!(matches!(
            VsockFrame::decode(&bytes),
            Err(ProtoError::InvalidMagic(_))
        ));
    }
}
