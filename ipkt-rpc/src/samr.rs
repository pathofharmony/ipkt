use ipkt_dcerpc::{PduType, RequestPdu, RpcHeader, RpcMessage, Uuid};

use crate::ndr::NdrWriter;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrConnectResponse {
    pub status: u32,

    pub server_handle: [u8; 20],
}

pub fn parse_samr_connect_response(stub: &[u8]) -> Option<SamrConnectResponse> {
    if stub.len() < 20 {
        return None;
    }
    let mut server_handle = [0u8; 20];
    server_handle.copy_from_slice(&stub[..20]);
    let status = if stub.len() >= 24 {
        u32::from_le_bytes(stub[20..24].try_into().ok()?)
    } else {
        0
    };
    Some(SamrConnectResponse {
        status,
        server_handle,
    })
}

pub const SAMR_INTERFACE: &str = "12345778-1234-abcd-ef00-0123456789ac";

pub const NDR_TRANSFER_SYNTAX: &str = "8a885d04-1ceb-11c9-9fe8-08002b104860";

pub fn samr_connect_request(server_name: Option<&str>, access_mask: u32) -> RpcMessage<RequestPdu> {
    let mut ndr = NdrWriter::new();
    ndr.write_u32(access_mask);
    if let Some(name) = server_name {
        ndr.write_unicode_string(name);
    } else {
        ndr.write_u32(0);
    }
    let stub = ndr.finish();
    RpcMessage {
        header: RpcHeader::new(PduType::Request, 1),
        body: RequestPdu {
            alloc_hint: stub.len() as u32,
            context_id: 0,
            opnum: 0,
            stub,
        },
    }
}

pub fn samr_lookup_domain_request(
    server_handle: &[u8; 20],
    domain: &str,
) -> RpcMessage<RequestPdu> {
    let mut ndr = NdrWriter::new();
    ndr.write_sampr_handle(server_handle);
    ndr.write_unicode_string(domain);
    let stub = ndr.finish();
    RpcMessage {
        header: RpcHeader::new(PduType::Request, 2),
        body: RequestPdu {
            alloc_hint: stub.len() as u32,
            context_id: 0,
            opnum: 5,
            stub,
        },
    }
}

pub fn samr_enumerate_users_request(
    domain_handle: &[u8; 20],
    resume_handle: u32,
    max_size: u32,
) -> RpcMessage<RequestPdu> {
    let mut ndr = NdrWriter::new();
    ndr.write_sampr_handle(domain_handle);
    ndr.write_u32(resume_handle);
    ndr.write_u32(1);
    ndr.write_u32(max_size);
    let stub = ndr.finish();
    RpcMessage {
        header: RpcHeader::new(PduType::Request, 3),
        body: RequestPdu {
            alloc_hint: stub.len() as u32,
            context_id: 0,
            opnum: 0x0D,
            stub,
        },
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamrUserEntry {
    pub rid: u32,
    pub name: String,
}

pub fn parse_samr_enumerate_users(stub: &[u8]) -> Vec<SamrUserEntry> {
    let mut out = Vec::new();
    let mut r = crate::ndr::NdrReader::new(stub);
    let count = r.read_u32().unwrap_or(0);
    for _ in 0..count.min(64) {
        let rid = r.read_u32().unwrap_or(0);
        if rid == 0 {
            break;
        }
        out.push(SamrUserEntry {
            rid,
            name: format!("RID-{rid}"),
        });
    }
    out
}

pub fn samr_bind_uuids() -> Result<(Uuid, Uuid), ipkt_dcerpc::Error> {
    Ok((
        Uuid::parse(SAMR_INTERFACE)?,
        Uuid::parse(NDR_TRANSFER_SYNTAX)?,
    ))
}
