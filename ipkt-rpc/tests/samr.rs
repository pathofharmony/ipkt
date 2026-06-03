#![allow(missing_docs)]
use ipkt_dcerpc::{RequestPdu, RpcMessage};
use ipkt_rpc::{samr_bind_uuids, samr_connect_request};

#[test]
fn samr_connect_request_has_opnum_zero() {
    let msg = samr_connect_request(Some("dc01.example.com"), 0x0000_0200);
    let bytes = msg.pack();
    let parsed = RpcMessage::<RequestPdu>::unpack(&bytes).unwrap();
    assert_eq!(parsed.body.opnum, 0);
    assert!(!parsed.body.stub.is_empty());
}

#[test]
fn samr_uuids_parse() {
    let (a, b) = samr_bind_uuids().unwrap();
    assert_ne!(a, b);
}
