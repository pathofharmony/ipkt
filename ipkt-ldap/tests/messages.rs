#![allow(missing_docs)]
use ipkt_ldap::{BindRequest, SearchRequest};

#[test]
fn bind_request_encodes_non_empty() {
    let msg = BindRequest::simple(3, "cn=admin,dc=example,dc=com", b"secret");
    let bytes = msg.encode(1);
    assert!(!bytes.is_empty());
    assert_eq!(bytes[0], 0x30);
    let id = ipkt_ldap::decode_message_id(&bytes).unwrap();
    assert_eq!(id, 1);
}

#[test]
fn search_request_encodes_filter() {
    let msg = SearchRequest {
        base_object: "dc=example,dc=com".into(),
        filter: "(objectClass=user)".into(),
        scope: 2,
    };
    let bytes = msg.encode(2);
    assert!(bytes.windows(6).any(|w| w == b"object"));
}
