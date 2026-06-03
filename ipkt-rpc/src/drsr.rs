use ipkt_dcerpc::{PduType, RequestPdu, RpcHeader, RpcMessage, Uuid};

use crate::ndr_rpc::NdrRpcEncoder;
use crate::prefix_table::PrefixTable;


pub const DRSUAPI_INTERFACE: &str = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";


pub const DRSUAPI_TRANSFER_SYNTAX: &str = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";


pub const DRS_INIT_SYNC: u32 = 0x0000_0001;

pub const DRS_WRIT_REP: u32 = 0x0000_0010;

pub const EXOP_REPL_OBJ: u32 = 0x0000_0006;


#[must_use]
pub fn domain_to_dn(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').filter(|p| !p.is_empty()).collect();
    if parts.len() > 1 {
        parts
            .iter()
            .map(|p| format!("DC={p}"))
            .collect::<Vec<_>>()
            .join(",")
    } else {
        format!("DC={domain}")
    }
}


pub fn drs_bind_request() -> RpcMessage<RequestPdu> {
    let stub = NdrRpcEncoder::new().drs_bind();
    rpc_request(0, 0, stub)
}


pub fn drs_domain_controller_info_request(
    drs_handle: &[u8; 20],
    domain_dns: &str,
) -> RpcMessage<RequestPdu> {
    let stub = NdrRpcEncoder::new().drs_domain_controller_info(drs_handle, domain_dns);
    rpc_request(1, 16, stub)
}


pub fn drs_crack_names_request(
    drs_handle: &[u8; 20],
    name: &str,
    format_offered: u32,
    format_desired: u32,
) -> RpcMessage<RequestPdu> {
    let stub = NdrRpcEncoder::new().drs_crack_names_v1(
        drs_handle,
        name,
        format_offered,
        format_desired,
    );
    rpc_request(3, 12, stub)
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DrsUsnVector {
    pub usn_high_obj_update: u32,
    pub usn_reserved: u32,
    pub usn_high_prop_update: u32,
}

impl DrsUsnVector {
    
    #[must_use]
    pub fn as_tuple(self) -> (u32, u32, u32) {
        (
            self.usn_high_obj_update,
            self.usn_reserved,
            self.usn_high_prop_update,
        )
    }
}


pub fn drs_get_nc_changes_request(
    drs_handle: &[u8; 20],
    dsa_guid: [u8; 16],
    invocation_id: [u8; 16],
    nc_dn: &str,
    c_max_objects: u32,
    ul_extended_op: u32,
    usnvec: Option<DrsUsnVector>,
) -> RpcMessage<RequestPdu> {
    let mut prefix = PrefixTable::default();
    let attrs = prefix.default_repl_attr_typs();
    let stub = NdrRpcEncoder::new().drs_get_nc_changes_v8(
        drs_handle,
        dsa_guid,
        invocation_id,
        nc_dn,
        &attrs,
        DRS_INIT_SYNC | DRS_WRIT_REP,
        c_max_objects,
        ul_extended_op,
        usnvec.map(DrsUsnVector::as_tuple),
    );
    rpc_request(2, 3, stub)
}

fn rpc_request(call_id: u32, opnum: u16, stub: Vec<u8>) -> RpcMessage<RequestPdu> {
    RpcMessage {
        header: RpcHeader::new(PduType::Request, call_id),
        body: RequestPdu {
            alloc_hint: stub.len() as u32,
            context_id: 0,
            opnum,
            stub,
        },
    }
}


pub fn drsu_bind_uuids() -> Result<(Uuid, Uuid), ipkt_dcerpc::Error> {
    Ok((
        Uuid::parse(DRSUAPI_INTERFACE)?,
        Uuid::parse(DRSUAPI_TRANSFER_SYNTAX)?,
    ))
}
