#![allow(missing_docs)]
use ipkt_kerberos::{
    ap_rep_for_ldap_bind, encode_ap_rep, encode_ap_rep_from_challenge, encode_ap_req,
    ldap_service_principal, parse_ap_req, KerberosSessionKey, PrincipalName,
};

#[test]
fn ap_req_and_ap_rep_encode() {
    let key = KerberosSessionKey::aes256([0x11u8; 32]);
    let ticket = vec![0x6eu8, 0x82, 0x01, 0x00];
    let cname = PrincipalName::new(1, vec!["alice".into()]);
    let sname = ldap_service_principal("dc01.corp.local", "CORP.LOCAL");
    let ap_req = encode_ap_req(&ticket, &key, "CORP.LOCAL", &cname, &sname).unwrap();
    assert_eq!(ap_req[0], 0x6e);
    let ap_rep = encode_ap_rep(&key).unwrap();
    assert_eq!(ap_rep[0], 0x6f);
}

#[test]
fn ap_rep_from_mutual_challenge() {
    let key = KerberosSessionKey::aes256([0x22u8; 32]);
    let cname = PrincipalName::new(1, vec!["alice".into()]);
    let sname = ldap_service_principal("dc01.corp.local", "CORP.LOCAL");
    let ticket = vec![0x6eu8, 0x04, 0x01, 0x02, 0x03];
    let client_ap = encode_ap_req(&ticket, &key, "CORP.LOCAL", &cname, &sname).unwrap();
    let server_ap = encode_ap_req(&ticket, &key, "CORP.LOCAL", &cname, &sname).unwrap();
    let _ = parse_ap_req(&client_ap).unwrap();
    let ap_rep = encode_ap_rep_from_challenge(&key, &server_ap).unwrap();
    assert_eq!(ap_rep[0], 0x6f);
    let _ = ap_rep_for_ldap_bind(&key, Some(&server_ap)).unwrap();
}
