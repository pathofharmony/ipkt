#![allow(missing_docs)]
use ipkt_core::Pack;
use ipkt_dcerpc::{parse_rpc_pdu, BindPdu, PduType, RpcHeader, RpcMessage};

#[test]
fn parse_bind_ack_from_bytes() {
    let bind = BindPdu {
        max_xmit_frag: 4280,
        max_recv_frag: 4280,
        assoc_group: 0,
        context_id: 0,
        abstract_syntax: ipkt_dcerpc::Uuid::parse("12345778-1234-abcd-ef00-0123456789ac").unwrap(),
        transfer_syntax: ipkt_dcerpc::Uuid::parse("8a885d04-1ceb-11c9-9fe8-08002b104860")
            .unwrap(),
    };
    let _ = RpcMessage {
        header: RpcHeader::new(PduType::Bind, 0),
        body: bind,
    };
    let mut ack_body = Vec::new();
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&4280u16.to_le_bytes());
    ack_body.extend_from_slice(&42u32.to_le_bytes());
    let header = RpcHeader::new(PduType::BindAck, 1);
    let mut w = ipkt_core::ByteWriter::new();
    let mut h = header.clone();
    h.frag_length = (16 + ack_body.len()) as u16;
    h.pack_into(&mut w);
    w.write_bytes(&ack_body);
    let raw = w.into_vec();
    let (hdr, pdu) = parse_rpc_pdu(&raw).unwrap();
    assert_eq!(hdr.pdu_type, PduType::BindAck);
    match pdu {
        ipkt_dcerpc::ParsedRpcPdu::BindAck(b) => assert_eq!(b.assoc_group, 42),
        _ => panic!("expected BindAck"),
    }
}
