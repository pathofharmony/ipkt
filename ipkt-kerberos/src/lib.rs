#![allow(missing_docs)]

mod aes_cts;
mod ap_req;
mod asn1;
mod crypto;
mod des_crypto;
mod enc_kdc;
mod error;
mod krb_error;
mod messages;
mod pa_data;
mod pac;
mod rc4_hmac;
mod session_key;
mod types;

#[cfg(feature = "kdc")]
mod kdc;

pub use aes_cts::{
    decrypt_aes256, encrypt_aes256, string2key_aes256 as aes_string2key, KEY_USAGE_AS_REP_ENC_PART,
    KEY_USAGE_PA_ENC_TIMESTAMP,
};
pub use ap_req::{
    ap_rep_for_ldap_bind, encode_ap_rep, encode_ap_rep_from_challenge, encode_ap_req,
    encode_pa_tgs_req, ldap_service_principal, parse_ap_req,
};
pub use crypto::{n_fold, string2key_aes256, ETYPE_AES256_CTS_HMAC_SHA1_96};
pub use des_crypto::{
    crc32_kerberos, decrypt_des3_cbc_sha1, decrypt_des_cbc_crc, decrypt_des_cbc_md5,
    encrypt_des3_cbc_sha1, encrypt_des_cbc_crc, encrypt_des_cbc_md5, string2key_des,
    string2key_des3, ETYPE_DES3_CBC_SHA1, ETYPE_DES_CBC_CRC, ETYPE_DES_CBC_MD5,
};
pub use enc_kdc::{
    decrypt_tgs_rep_enc_part, extract_and_verify_pac_from_tgs_rep, extract_pac_from_tgs_rep,
    parse_encrypted_data, session_key_from_as_rep, session_key_from_tgs_rep,
};
pub use error::{Error, Result};
pub use krb_error::{
    decode_krb_error, try_decode_krb_error, KrbError, KDC_ERR_C_PRINCIPAL_UNKNOWN,
    KDC_ERR_ETYPE_NOSUPP, KDC_ERR_PREAUTH_REQUIRED, KDC_ERR_SUMTYPE_NOSUPP,
};
pub use messages::{
    decode_as_rep, decode_as_req, decode_tgs_rep, encode_as_rep, encode_as_req,
    encode_as_req_with_padata, encode_tgs_req, encode_tgs_req_with_padata, AsRep, AsReq,
    KdcReqBody, TgsRep, TgsReq,
};
pub use pa_data::{
    build_pa_enc_timestamp, encode_pa_enc_timestamp, encode_pa_pac_request, PA_ENC_TIMESTAMP,
    PA_PAC_REQUEST,
};
pub use pac::{
    extract_pac_from_enc_kdc_rep, pac_signing_key, parse_logon_info, parse_pac,
    verify_pac_checksums, Pac, PacBuffer, PacCredentialInfo, PacLogonInfo, PacSignature,
    PAC_BUFFER_CREDENTIAL_INFO, PAC_BUFFER_KDC_CHECKSUM, PAC_BUFFER_LOGON_INFO,
    PAC_BUFFER_SERVER_CHECKSUM, PAC_SIGNATURE_HMAC_MD5,
};
pub use rc4_hmac::{string2key_rc4, ETYPE_RC4_HMAC};
pub use session_key::{default_enctype_list, KerberosSessionKey};
pub use types::{EncryptedData, PrincipalName, Realm, Ticket};

#[cfg(feature = "kdc")]
pub use kdc::{AsExchange, KdcClient, LdapKerberosTokens, TgsExchange};
