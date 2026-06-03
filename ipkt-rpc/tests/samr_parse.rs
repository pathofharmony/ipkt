#![allow(missing_docs)]
use ipkt_rpc::parse_samr_connect_response;

#[test]
fn samr_connect_parses_20_byte_handle() {
    let mut stub = vec![0x01, 0x00, 0x00, 0x00];
    stub.extend_from_slice(&[0xAB; 16]);
    let resp = parse_samr_connect_response(&stub).unwrap();
    assert_eq!(resp.status, 0);
    assert_eq!(resp.server_handle[4], 0xAB);
}
