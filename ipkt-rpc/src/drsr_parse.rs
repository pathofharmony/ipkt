use crate::drsr::DrsUsnVector;
use crate::replentinf::decode_get_nc_changes_reply as decode_v6_reply;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrsBindResult {
    pub handle: [u8; 20],
    pub status: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrsUserSecret {
    pub username: String,
    pub rid: u32,
    pub lm_hash: Option<[u8; 16]>,
    pub nt_hash: Option<[u8; 16]>,
}

#[derive(Debug, Clone)]
pub struct DrsNcChangesReply {
    pub out_version: u32,
    pub num_objects: u32,
    pub more_data: bool,
    pub prefix_table: crate::prefix_table::PrefixTable,
    pub pek_list: Vec<[u8; 16]>,
    pub usnvec: Option<DrsUsnVector>,
    pub invocation_id: Option<[u8; 16]>,
    pub secrets: Vec<DrsUserSecret>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrsCrackNamesResult {
    pub status: u32,
    pub name: String,
}

pub fn parse_drs_bind_response(stub: &[u8]) -> Option<DrsBindResult> {
    if stub.len() < 24 {
        return None;
    }
    let status = u32::from_le_bytes(stub[stub.len() - 4..].try_into().ok()?);
    let mut handle = [0u8; 20];
    handle.copy_from_slice(&stub[stub.len() - 24..stub.len() - 4]);
    Some(DrsBindResult { handle, status })
}

pub fn parse_drs_dc_info_ntds_guid(stub: &[u8]) -> Option<[u8; 16]> {
    for window in stub.windows(16) {
        let guid: [u8; 16] = window.try_into().ok()?;
        if guid != [0u8; 16] && guid[6] & 0xF0 == 0x40 {
            return Some(guid);
        }
    }
    None
}

pub fn parse_drs_crack_names(stub: &[u8]) -> Option<DrsCrackNamesResult> {
    use crate::ndr_decode::NdrDecoder;
    let mut dec = NdrDecoder::new(stub);
    let _out_ver = dec.read_u32()?;
    let _tag = dec.read_u32()?;
    let _ptr = dec.read_ptr()?;
    let c_items = dec.read_u32()?;
    let items_ptr = dec.read_ptr()?;
    let items_off = items_ptr as usize;
    let mut item_dec = dec.at(items_off)?;
    for _ in 0..c_items {
        let status = item_dec.read_u32()?;
        let _domain_ptr = item_dec.read_ptr()?;
        let name_ptr = item_dec.read_ptr();
        if status == 0 {
            if let Some(name_off) = name_ptr {
                let mut name_dec = dec.at(name_off as usize)?;
                let name = name_dec.read_conformant_utf16()?;
                return Some(DrsCrackNamesResult { status, name });
            }
        }
    }
    None
}

pub fn parse_get_nc_changes_reply(stub: &[u8], session_key: &[u8]) -> DrsNcChangesReply {
    let out_version = u32::from_le_bytes(
        stub.get(0..4)
            .unwrap_or(&[0; 4])
            .try_into()
            .unwrap_or([0; 4]),
    );
    if let Some(v6) = decode_v6_reply(stub, session_key) {
        let _dsa = v6.uuid_dsa_obj_src;
        let _ext = v6.ul_extended_ret;
        return DrsNcChangesReply {
            out_version,
            num_objects: v6.c_num_objects,
            more_data: v6.f_more_data,
            prefix_table: v6.prefix_table_src,
            pek_list: v6.pek_list,
            usnvec: Some(v6.usnvec_to),
            invocation_id: Some(v6.uuid_invoc_id_src),
            secrets: v6.secrets,
        };
    }
    DrsNcChangesReply {
        out_version,
        num_objects: 0,
        more_data: false,
        prefix_table: crate::prefix_table::PrefixTable::default(),
        pek_list: Vec::new(),
        usnvec: None,
        invocation_id: None,
        secrets: Vec::new(),
    }
}

pub fn parse_get_nc_changes_secrets(stub: &[u8], session_key: &[u8]) -> Vec<DrsUserSecret> {
    parse_get_nc_changes_reply(stub, session_key).secrets
}
