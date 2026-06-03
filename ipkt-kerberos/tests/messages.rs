use ipkt_kerberos::n_fold;
use ipkt_kerberos::{
    decode_as_req, encode_as_req, encode_tgs_req, AsReq, KdcReqBody, PrincipalName, Realm, TgsReq,
    ETYPE_AES256_CTS_HMAC_SHA1_96,
};

#[test]
fn n_fold_matches_rfc3961_reference() {
    let data = b"password";
    let folded = n_fold(16, data);
    assert_eq!(folded.len(), 16);
    assert_eq!(folded, n_fold(16, data));
}

#[test]
fn as_req_encodes_and_decodes() {
    let realm = Realm::new("EXAMPLE.COM");
    let cname = PrincipalName::new(1, vec!["user".into()]);
    let body = KdcReqBody {
        kdc_options: 0x4081_0000,
        cname,
        realm: realm.clone(),
        sname: None,
        nonce: 0x1234_5678,
        etype: vec![ETYPE_AES256_CTS_HMAC_SHA1_96, 17, 16],
    };
    let req = AsReq {
        pvno: 5,
        msg_type: 10,
        req_body: body,
    };
    let der = encode_as_req(&req).unwrap();
    assert!(!der.is_empty());
    let parsed = decode_as_req(&der).unwrap();
    assert_eq!(parsed.pvno, 5);
    assert_eq!(parsed.msg_type, 10);
    assert_eq!(parsed.req_body.nonce, 0x1234_5678);
    assert_eq!(parsed.req_body.realm.as_str(), "EXAMPLE.COM");
}

#[test]
fn tgs_req_encodes() {
    let realm = Realm::new("EXAMPLE.COM");
    let cname = PrincipalName::new(1, vec!["user".into()]);
    let sname = PrincipalName::new(2, vec!["host".into(), "server.example.com".into()]);
    let body = KdcReqBody {
        kdc_options: 0x4081_0000,
        cname,
        realm,
        sname: Some(sname),
        nonce: 42,
        etype: vec![ETYPE_AES256_CTS_HMAC_SHA1_96],
    };
    let req = TgsReq {
        pvno: 5,
        msg_type: 12,
        req_body: body,
    };
    let der = encode_tgs_req(&req).unwrap();
    assert!(der.len() > 10);
}
