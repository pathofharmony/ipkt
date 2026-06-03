#![allow(missing_docs)]
use ipkt_ldap::{neg_token_init_kerberos, parse_neg_token_targ};

#[test]
fn parse_neg_token_targ_finds_response_token() {
    let ap_stub = vec![0x6eu8, 0x04, 0xde, 0xad, 0xbe, 0xef];
    let init = neg_token_init_kerberos(&ap_stub);
    let targ = parse_neg_token_targ(&init);
    assert!(targ.is_some());
}
