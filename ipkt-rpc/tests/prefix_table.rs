#![allow(missing_docs)]
use ipkt_rpc::{make_attid, oid_from_attid, PrefixTable, ATTID_UNICODE_PWD, OID_UNICODE_PWD};

#[test]
fn make_attid_oid_round_trip() {
    let mut t = PrefixTable::default();
    let wire = make_attid(&mut t, OID_UNICODE_PWD);
    assert_eq!(oid_from_attid(&t, wire), Some(ATTID_UNICODE_PWD));
}
