#![allow(missing_docs)]
use ipkt_kerberos::{
    decode_as_rep, encode_as_rep, AsRep, PrincipalName, Realm,
};

#[test]
fn as_rep_encode_decode_subset() {
    let rep = AsRep {
        pvno: 5,
        msg_type: 11,
        crealm: Realm::new("EXAMPLE.COM"),
        cname: PrincipalName::new(1, vec!["alice".into()]),
        ticket: vec![0x30, 0x03, 0x01, 0x02, 0x03],
        enc_part: vec![0x04, 0x02, 0xAA, 0xBB],
    };
    let bytes = encode_as_rep(&rep).unwrap();
    let decoded = decode_as_rep(&bytes).unwrap();
    assert_eq!(decoded.crealm.as_str(), "EXAMPLE.COM");
    assert_eq!(decoded.ticket, rep.ticket);
}
