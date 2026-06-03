#![allow(missing_docs)]
use ipkt_rpc::{
    domain_to_dn, drs_bind_request, drs_get_nc_changes_request, drsu_bind_uuids,
    parse_drs_bind_response,
};

#[test]
fn drsu_bind_uuids_parse() {
    drsu_bind_uuids().unwrap();
}

#[test]
fn drs_bind_request_packs() {
    let msg = drs_bind_request();
    assert!(!msg.pack().is_empty());
}

#[test]
fn domain_to_dn_splits_labels() {
    assert_eq!(domain_to_dn("CORP.LOCAL"), "DC=CORP,DC=LOCAL");
}

#[test]
fn get_nc_changes_request_packs() {
    let handle = [0xAB; 20];
    let msg = drs_get_nc_changes_request(
        &handle,
        [1u8; 16],
        [2u8; 16],
        "DC=CORP,DC=LOCAL",
        100,
        0,
        None,
    );
    assert!(msg.pack().len() > 64);
}

#[test]
fn parse_bind_tail() {
    let mut stub = vec![0u8; 40];
    let tail_start = stub.len() - 24;
    let status_start = stub.len() - 4;
    stub[tail_start..status_start].fill(0xCC);
    stub[status_start..].copy_from_slice(&0u32.to_le_bytes());
    let bind = parse_drs_bind_response(&stub).unwrap();
    assert_eq!(bind.status, 0);
    assert_eq!(bind.handle, [0xCC; 20]);
}
