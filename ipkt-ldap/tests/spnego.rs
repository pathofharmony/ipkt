#![allow(missing_docs)]
use ipkt_ldap::{gssapi_sasl_credentials, BindRequest};

#[test]
fn gssapi_sasl_bind_includes_spnego_oid() {
    let msg = BindRequest::sasl_gssapi_init(3, "");
    let bytes = msg.encode(1);
    assert!(bytes.windows(6).any(|w| w == b"GSSAPI"));
    assert!(!gssapi_sasl_credentials().is_empty());
}
