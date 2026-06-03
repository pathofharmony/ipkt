use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::uuid::Uuid;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PduType {
    Request = 0,
    Ping = 1,
    Response = 2,
    Fault = 3,
    Working = 4,
    Nocall = 5,
    Reject = 6,
    Ack = 7,
    ClCancel = 8,
    Fack = 9,
    CancelAck = 10,
    Bind = 11,
    BindAck = 12,
    BindNak = 13,
    AlterContext = 14,
    AlterContextResp = 15,
    Shutdown = 17,
    CoCancel = 18,
    Orphaned = 19,
}

impl PduType {
    #[must_use]
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Request,
            2 => Self::Response,
            3 => Self::Fault,
            11 => Self::Bind,
            12 => Self::BindAck,
            13 => Self::BindNak,
            14 => Self::AlterContext,
            15 => Self::AlterContextResp,
            _ => return None,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcHeader {
    pub version_major: u8,
    pub version_minor: u8,
    pub pdu_type: PduType,
    pub flags: u8,
    pub data_representation: u32,
    pub frag_length: u16,
    pub auth_length: u16,
    pub call_id: u32,
}

impl RpcHeader {
    
    #[must_use]
    pub fn new(pdu_type: PduType, call_id: u32) -> Self {
        Self {
            version_major: 5,
            version_minor: 0,
            pdu_type,
            flags: 0x03,                      
            data_representation: 0x0000_0010, 
            frag_length: 0,
            auth_length: 0,
            call_id,
        }
    }
}

impl Pack for RpcHeader {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u8(self.version_major)
            .write_u8(self.version_minor)
            .write_u8(self.pdu_type as u8)
            .write_u8(self.flags)
            .write_u32_le(self.data_representation)
            .write_u16_le(self.frag_length)
            .write_u16_le(self.auth_length)
            .write_u32_le(self.call_id);
    }
}

impl Unpack for RpcHeader {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let version_major = reader.read_u8()?;
        let version_minor = reader.read_u8()?;
        let pdu_type = reader.read_u8()?;
        let pdu_type = PduType::from_u8(pdu_type).ok_or_else(|| {
            ipkt_core::Error::invalid_data("RPC header", format!("pdu type {pdu_type}"))
        })?;
        let flags = reader.read_u8()?;
        let data_representation = reader.read_u32_le()?;
        let frag_length = reader.read_u16_le()?;
        let auth_length = reader.read_u16_le()?;
        let call_id = reader.read_u32_le()?;
        Ok(Self {
            version_major,
            version_minor,
            pdu_type,
            flags,
            data_representation,
            frag_length,
            auth_length,
            call_id,
        })
    }
}

/// BIND PDU body (simplified — one presentation context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindPdu {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
    pub context_id: u16,
    pub abstract_syntax: Uuid,
    pub transfer_syntax: Uuid,
}

impl Pack for BindPdu {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(4280) // max_xmit
            .write_u16_le(4280) // max_recv
            .write_u32_le(self.assoc_group)
            .write_u32_le(1) // context count
            .write_u16_le(0) // reserved
            .write_u16_le(1) // max transmit size for context?
            .write_u16_le(self.context_id)
            .write_u8(1) // num trans items
            .write_u8(0) // reserved
            .write_u16_le(68) // abstract syntax version
            .write_u16_le(0); // transfer syntax count placeholder
        self.abstract_syntax.pack_into(writer);
        writer.write_u16_le(2); // num transfer syntaxes
        writer.write_u16_le(68);
        self.transfer_syntax.pack_into(writer);
    }
}

/// REQUEST PDU stub data wrapper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPdu {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub opnum: u16,
    pub stub: Vec<u8>,
}

impl Pack for RequestPdu {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u32_le(self.alloc_hint)
            .write_u16_le(self.context_id)
            .write_u16_le(self.opnum)
            .write_bytes(&self.stub);
    }
}

impl Unpack for RequestPdu {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let alloc_hint = reader.read_u32_le()?;
        let context_id = reader.read_u16_le()?;
        let opnum = reader.read_u16_le()?;
        let stub = reader.read_bytes(reader.remaining())?.to_vec();
        Ok(Self {
            alloc_hint,
            context_id,
            opnum,
            stub,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcMessage<B> {
    pub header: RpcHeader,
    pub body: B,
}

impl<B: Pack> RpcMessage<B> {
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut w = ByteWriter::new();
        let mut body_buf = ByteWriter::new();
        self.body.pack_into(&mut body_buf);
        let body = body_buf.into_vec();
        let mut header = self.header.clone();
        header.frag_length = (16 + body.len()) as u16;
        header.pack_into(&mut w);
        w.write_bytes(&body);
        w.into_vec()
    }
}

impl<B: Unpack> RpcMessage<B> {
    pub fn unpack(bytes: &[u8]) -> CoreResult<Self> {
        let mut reader = ByteReader::new(bytes);
        let header = RpcHeader::unpack_from(&mut reader)?;
        let body = B::unpack_from(&mut reader)?;
        Ok(Self { header, body })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindAckPdu {
    pub max_xmit_frag: u16,
    pub max_recv_frag: u16,
    pub assoc_group: u32,
}

impl Unpack for BindAckPdu {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let max_xmit_frag = reader.read_u16_le()?;
        let max_recv_frag = reader.read_u16_le()?;
        let assoc_group = reader.read_u32_le()?;
        Ok(Self {
            max_xmit_frag,
            max_recv_frag,
            assoc_group,
        })
    }
}

/// RESPONSE PDU body (stub + auth trailer skipped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponsePdu {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub cancel_count: u8,
    pub stub: Vec<u8>,
}

impl Unpack for ResponsePdu {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let alloc_hint = reader.read_u32_le()?;
        let context_id = reader.read_u16_le()?;
        let cancel_count = reader.read_u8()?;
        let _ = reader.read_u8()?;
        let stub = reader.read_bytes(reader.remaining())?.to_vec();
        Ok(Self {
            alloc_hint,
            context_id,
            cancel_count,
            stub,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPdu {
    pub alloc_hint: u32,
    pub context_id: u16,
    pub status: u32,
}

impl Unpack for FaultPdu {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let alloc_hint = reader.read_u32_le()?;
        let context_id = reader.read_u16_le()?;
        let _ = reader.read_u8()?;
        let _ = reader.read_u8()?;
        let status = reader.read_u32_le()?;
        Ok(Self {
            alloc_hint,
            context_id,
            status,
        })
    }
}

/// Parsed RPC PDU with typed body when recognized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedRpcPdu {
    BindAck(BindAckPdu),
    Response(ResponsePdu),
    Fault(FaultPdu),
    Other {
        pdu_type: PduType,
        body: Vec<u8>,
    },
}

/// Parses header and dispatches to a known body type.
pub fn parse_rpc_pdu(bytes: &[u8]) -> CoreResult<(RpcHeader, ParsedRpcPdu)> {
    let mut reader = ByteReader::new(bytes);
    let header = RpcHeader::unpack_from(&mut reader)?;
    let body_bytes = reader.read_bytes(reader.remaining())?.to_vec();
    let parsed = match header.pdu_type {
        PduType::BindAck => {
            let mut br = ByteReader::new(&body_bytes);
            ParsedRpcPdu::BindAck(BindAckPdu::unpack_from(&mut br)?)
        }
        PduType::Response => {
            let mut br = ByteReader::new(&body_bytes);
            ParsedRpcPdu::Response(ResponsePdu::unpack_from(&mut br)?)
        }
        PduType::Fault => {
            let mut br = ByteReader::new(&body_bytes);
            ParsedRpcPdu::Fault(FaultPdu::unpack_from(&mut br)?)
        }
        other => ParsedRpcPdu::Other {
            pdu_type: other,
            body: body_bytes,
        },
    };
    Ok((header, parsed))
}
