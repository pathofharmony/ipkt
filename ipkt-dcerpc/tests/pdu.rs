#![allow(missing_docs)]

use ipkt_core::{Pack, Unpack};
use ipkt_dcerpc::{BindPdu, PduType, RequestPdu, RpcHeader, RpcMessage, Uuid};

#[test]
fn uuid_round_trips() {
    let id = Uuid::parse("12345678-1234-1234-1234-123456789abc").unwrap();
    let bytes = id.pack();
    assert_eq!(Uuid::unpack(&bytes).unwrap(), id);
}

#[test]
fn rpc_request_round_trips() {
    let msg = RpcMessage {
        header: RpcHeader::new(PduType::Request, 1),
        body: RequestPdu {
            alloc_hint: 4,
            context_id: 0,
            opnum: 2,
            stub: vec![0xDE, 0xAD, 0xBE, 0xEF],
        },
    };
    let bytes = msg.pack();
    let parsed = RpcMessage::<RequestPdu>::unpack(&bytes).unwrap();
    assert_eq!(parsed.body.opnum, 2);
    assert_eq!(parsed.body.stub, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn bind_pdu_packs() {
    let bind = BindPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group: 0,
        context_id: 0,
        abstract_syntax: Uuid::NIL,
        transfer_syntax: Uuid::NIL,
    };
    let msg = RpcMessage {
        header: RpcHeader::new(PduType::Bind, 0),
        body: bind,
    };
    assert!(msg.pack().len() > 16);
}
