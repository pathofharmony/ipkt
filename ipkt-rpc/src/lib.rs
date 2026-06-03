#![allow(missing_docs)]

mod drsr;
mod drsr_crypto;
mod drsr_parse;
mod ndr;
mod ndr_decode;
mod ndr_rpc;
mod prefix_table;
mod replentinf;
pub mod samr;

pub use drsr::{
    domain_to_dn, drs_bind_request, drs_crack_names_request, drs_domain_controller_info_request,
    drs_get_nc_changes_request, drsu_bind_uuids, DrsUsnVector, DRSUAPI_INTERFACE, DRS_INIT_SYNC,
    DRS_WRIT_REP, EXOP_REPL_OBJ,
};
pub use drsr_crypto::{
    decrypt_drs_attribute, decrypt_nt_hash_from_replication, decrypt_pek_entry, remove_des_layer,
    remove_rc4_pek_layer,
};
pub use drsr_parse::{
    parse_drs_bind_response, parse_drs_crack_names, parse_drs_dc_info_ntds_guid,
    parse_get_nc_changes_reply, parse_get_nc_changes_secrets, DrsBindResult, DrsCrackNamesResult,
    DrsNcChangesReply, DrsUserSecret,
};
pub use ndr::{NdrReader, NdrWriter};
pub use ndr_rpc::NdrRpcEncoder;
pub use prefix_table::{
    make_attid, oid_from_attid, PrefixTable, ATTID_UNICODE_PWD, DEFAULT_REPL_ATTIDS,
    OID_UNICODE_PWD,
};
pub use samr::{
    parse_samr_connect_response, parse_samr_enumerate_users, samr_bind_uuids, samr_connect_request,
    samr_enumerate_users_request, samr_lookup_domain_request, SamrConnectResponse, SamrUserEntry,
    SAMR_INTERFACE,
};
