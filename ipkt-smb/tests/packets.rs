use ipkt_core::{Pack, Unpack};
use ipkt_ntlm::Credentials;
use ipkt_smb::{
    CloseRequest, CreateRequest, Dialect, NegotiateRequest, NegotiateResponse,
    NetbiosSessionMessage, NtlmSessionSetup, ReadRequest, Smb2Command, Smb2Header, Smb2Packet,
    TreeConnectRequest, WriteRequest,
};

#[test]
fn smb2_header_round_trips() {
    let header = Smb2Header::request(Smb2Command::Negotiate, 1, 0, 0);
    let bytes = header.pack();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..4], &[0xFE, b'S', b'M', b'B']);
    let parsed = Smb2Header::unpack(&bytes).unwrap();
    assert_eq!(parsed.command, Smb2Command::Negotiate);
    assert_eq!(parsed.message_id, 1);
}

#[test]
fn negotiate_request_contains_dialects() {
    let body = NegotiateRequest::default();
    let packet = Smb2Packet {
        header: Smb2Header::request(Smb2Command::Negotiate, 0, 0, 0),
        body,
        payload: Vec::new(),
    };
    let bytes = packet.pack();
    assert!(bytes
        .windows(2)
        .any(|w| w == Dialect::Smb311.as_u16().to_le_bytes()));
    
    assert!(bytes.windows(2).any(|w| w == [0x01, 0x00]));
}

#[test]
fn tree_connect_round_trips() {
    let body = TreeConnectRequest::new("\\\\srv\\share");
    let packet = Smb2Packet {
        header: Smb2Header::request(Smb2Command::TreeConnect, 2, 0x1234, 0),
        body,
        payload: Vec::new(),
    };
    let bytes = packet.pack();
    let parsed = Smb2Packet::<TreeConnectRequest>::unpack(&bytes).unwrap();
    assert_eq!(parsed.body.path, "\\\\srv\\share");
}

#[test]
fn netbios_framing_round_trips() {
    let inner = vec![0xFE, b'S', b'M', b'B', 0xFF];
    let framed = NetbiosSessionMessage::wrap(inner.clone());
    let (msg, consumed) = NetbiosSessionMessage::unwrap(&framed).unwrap();
    assert_eq!(consumed, framed.len());
    assert_eq!(msg.payload, inner);
}

#[test]
fn ntlm_session_setup_first_packet_contains_ntlmssp() {
    let setup = NtlmSessionSetup::new(Credentials::new("DOM", "user", "pw"));
    let packet = setup.first_request(1);
    let bytes = packet.pack();
    assert!(bytes.windows(8).any(|w| w == b"NTLMSSP\0"));
}

#[test]
fn create_read_write_close_structures_pack() {
    let create = CreateRequest::open("test.txt");
    let _ = create.pack();
    let read = ReadRequest {
        file_id: [1; 16],
        offset: 0,
        length: 4096,
    };
    let _ = read.pack();
    let write = WriteRequest {
        file_id: [1; 16],
        offset: 0,
        data: b"hello".to_vec(),
    };
    let _ = write.pack();
    let close = CloseRequest { file_id: [1; 16] };
    let _ = close.pack();
}

#[test]
fn negotiate_response_round_trips() {
    let body = NegotiateResponse {
        security_mode: 1,
        dialect: Dialect::Smb302,
        server_guid: [0xAB; 16],
        max_transact_size: 1048576,
    };
    let bytes = {
        let p = Smb2Packet {
            header: Smb2Header::request(Smb2Command::Negotiate, 0, 0, 0),
            body,
            payload: Vec::new(),
        };
        p.pack()
    };
    let parsed = Smb2Packet::<NegotiateResponse>::unpack(&bytes).unwrap();
    assert_eq!(parsed.body.dialect, Dialect::Smb302);
}
