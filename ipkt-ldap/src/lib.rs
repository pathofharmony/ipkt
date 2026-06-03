#![allow(missing_docs)]



mod ber;
mod error;
mod messages;
mod spnego;

#[cfg(feature = "client")]
mod client;

pub use error::{Error, Result};
pub use messages::{decode_message_id, BindAuth, BindRequest, LdapOp, SearchRequest};
pub use spnego::{
    extract_krb5_token_from_neg_token, gssapi_kerberos_credentials, gssapi_kerberos_response,
    gssapi_sasl_credentials, neg_token_init_kerberos, neg_token_init_spnego,
    neg_token_resp_kerberos, parse_neg_token_targ, NegTokenTarg,
};

#[cfg(feature = "client")]
pub use client::{BindResult, LdapClient, LDAP_SASL_BIND_IN_PROGRESS};
