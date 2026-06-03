use ipkt_core::ByteReader;

use crate::types::{PrincipalName, Realm};
use crate::Result;


pub const KDC_ERR_PREAUTH_REQUIRED: i32 = 24;
pub const KDC_ERR_ETYPE_NOSUPP: i32 = 14;
pub const KDC_ERR_SUMTYPE_NOSUPP: i32 = 15;
pub const KDC_ERR_C_PRINCIPAL_UNKNOWN: i32 = 6;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KrbError {
    pub pvno: u32,
    pub msg_type: u32,
    pub error_code: i32,
    pub crealm: Option<Realm>,
    pub cname: Option<PrincipalName>,
    pub realm: Option<Realm>,
    pub sname: Option<PrincipalName>,
    pub etext: Option<String>,
    pub e_data: Option<Vec<u8>>,
}

impl std::fmt::Display for KrbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

impl KrbError {
    /// Human-readable summary for logging.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!("KRB-ERROR code={}", self.error_code);
        if let Some(t) = &self.etext {
            s.push_str(&format!(" ({t})"));
        }
        s
    }
}

/// Decodes KRB-ERROR (tag `0x7e`).
pub fn decode_krb_error(bytes: &[u8]) -> Result<KrbError> {
    let mut reader = ByteReader::new(bytes);
    let app_tag = reader.read_u8()?;
    if app_tag != 0x7e {
        return Err(crate::Error::Der(format!(
            "expected APPLICATION 30, got {app_tag:#x}"
        )));
    }
    let app_len = crate::asn1::read_length(&mut reader)?;
    let app_body = reader.read_bytes(app_len)?;
    parse_krb_error_body(app_body)
}

fn parse_krb_error_body(body: &[u8]) -> Result<KrbError> {
    let mut r = ByteReader::new(body);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected SEQUENCE".into()));
    }
    let slen = crate::asn1::read_length(&mut r)?;
    let seq = r.read_bytes(slen)?;
    let mut sr = ByteReader::new(seq);
    let mut pvno = 5u32;
    let mut msg_type = 30u32;
    let mut error_code = 0i32;
    let mut crealm = None;
    let mut cname = None;
    let mut realm = None;
    let mut sname = None;
    let mut etext = None;
    let mut e_data = None;
    while !sr.is_empty() {
        let tag = sr.read_u8()?;
        let len = crate::asn1::read_length(&mut sr)?;
        let chunk = sr.read_bytes(len)?;
        match tag {
            0xA1 => {
                let mut inner = ByteReader::new(chunk);
                pvno = crate::asn1::decode_integer(&mut inner)?;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                msg_type = crate::asn1::decode_integer(&mut inner)?;
            }
            0xA3 => {
                let mut inner = ByteReader::new(chunk);
                error_code = crate::asn1::decode_integer(&mut inner)? as i32;
            }
            0xA4 => {
                let mut inner = ByteReader::new(chunk);
                crealm = Some(Realm::new(crate::asn1::decode_general_string(&mut inner)?));
            }
            0xA5 => cname = Some(decode_principal(chunk)?),
            0xA6 => {
                let mut inner = ByteReader::new(chunk);
                realm = Some(Realm::new(crate::asn1::decode_general_string(&mut inner)?));
            }
            0xA7 => sname = Some(decode_principal(chunk)?),
            0xA9 => {
                let mut inner = ByteReader::new(chunk);
                etext = Some(crate::asn1::decode_general_string(&mut inner)?);
            }
            0xAA => e_data = Some(chunk.to_vec()),
            _ => {}
        }
    }
    Ok(KrbError {
        pvno,
        msg_type,
        error_code,
        crealm,
        cname,
        realm,
        sname,
        etext,
        e_data,
    })
}

fn decode_principal(bytes: &[u8]) -> Result<PrincipalName> {
    let mut reader = ByteReader::new(bytes);
    let _ = reader.read_u8()?;
    let _ = crate::asn1::read_length(&mut reader)?;
    let mut name_type = 1u32;
    let mut components = Vec::new();
    while !reader.is_empty() {
        let ctx = reader.read_u8()?;
        let len = crate::asn1::read_length(&mut reader)?;
        let mut inner = ByteReader::new(reader.read_bytes(len)?);
        if ctx == 0xA0 {
            name_type = crate::asn1::decode_integer(&mut inner)?;
        } else if ctx == 0xA1 {
            let _ = inner.read_u8()?;
            let slen = crate::asn1::read_length(&mut inner)?;
            let mut sr = ByteReader::new(inner.read_bytes(slen)?);
            while !sr.is_empty() {
                let _ = sr.read_u8()?;
                let plen = crate::asn1::read_length(&mut sr)?;
                let mut pr = ByteReader::new(sr.read_bytes(plen)?);
                components.push(crate::asn1::decode_general_string(&mut pr)?);
            }
        }
    }
    Ok(PrincipalName::new(name_type, components))
}

/// Detects KRB-ERROR and decodes it; returns `None` for success PDUs.
pub fn try_decode_krb_error(bytes: &[u8]) -> Option<KrbError> {
    if bytes.first() == Some(&0x7e) {
        decode_krb_error(bytes).ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1::{encode_application, encode_context, encode_general_string, encode_integer, encode_sequence};

    #[test]
    fn krb_error_roundtrip_fields() {
        let mut body = Vec::new();
        body.extend(encode_context(1, &encode_integer(5)));
        body.extend(encode_context(2, &encode_integer(30)));
        body.extend(encode_context(3, &encode_integer(KDC_ERR_PREAUTH_REQUIRED as u32)));
        body.extend(encode_context(
            9,
            &encode_general_string("Pre-authentication required"),
        ));
        let der = encode_application(30, &encode_sequence(&body));
        let err = decode_krb_error(&der).unwrap();
        assert_eq!(err.error_code, KDC_ERR_PREAUTH_REQUIRED);
        assert_eq!(err.etext.as_deref(), Some("Pre-authentication required"));
    }
}
