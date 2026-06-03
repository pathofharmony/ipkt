#![allow(missing_docs)]
use ipkt_ldap::{BindAuth, BindRequest};

#[test]
fn sasl_bind_encodes_mechanism() {
    let msg = BindRequest::sasl(3, "", "GSSAPI", vec![0x01, 0x02]);
    let bytes = msg.encode(1);
    assert!(bytes.windows(6).any(|w| w == b"GSSAPI"));
    assert!(matches!(msg.auth, BindAuth::Sasl { .. }));
}
