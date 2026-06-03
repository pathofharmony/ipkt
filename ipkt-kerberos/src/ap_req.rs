use ipkt_core::ByteReader;

use crate::asn1::{
    encode_application, encode_context, encode_general_string, encode_integer, encode_octet_string,
    encode_sequence,
};
use crate::session_key::KerberosSessionKey;
use crate::types::PrincipalName;
use crate::Result;

pub const KEY_USAGE_AP_REQ_AUTH: u32 = 11;

pub const KEY_USAGE_AP_REP_ENC_PART: u32 = 12;

#[derive(Debug, Clone)]
pub struct ApReqParts {
    pub ticket: Vec<u8>,
    pub enc_authenticator: Vec<u8>,
}

pub fn encode_ap_req(
    ticket_der: &[u8],
    session_key: &KerberosSessionKey,
    realm: &str,
    cname: &PrincipalName,
    _sname: &PrincipalName,
) -> Result<Vec<u8>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let auth_plain = encode_authenticator_plain(realm, cname, now);
    let enc_auth = encrypt_encrypted_data(session_key, KEY_USAGE_AP_REQ_AUTH, &auth_plain)?;
    let mut ap = Vec::new();
    ap.extend(encode_context(0, &encode_integer(5)));
    ap.extend(encode_context(1, &encode_integer(14)));
    ap.extend(encode_context(2, ticket_der));
    ap.extend(encode_context(3, &enc_auth));
    Ok(encode_application(14, &encode_sequence(&ap)))
}

pub fn encode_ap_rep_from_challenge(
    service_key: &KerberosSessionKey,
    server_ap_req: &[u8],
) -> Result<Vec<u8>> {
    let parts = parse_ap_req(server_ap_req)?;
    let enc = crate::enc_kdc::parse_encrypted_data(&parts.enc_authenticator)?;
    let _auth_plain = service_key.decrypt(KEY_USAGE_AP_REQ_AUTH, &enc.cipher)?;
    let enc_ap_rep_part = encode_enc_ap_rep_part(service_key)?;
    let enc_blob =
        encrypt_encrypted_data(service_key, KEY_USAGE_AP_REP_ENC_PART, &enc_ap_rep_part)?;
    let mut inner = Vec::new();
    inner.extend(encode_context(0, &encode_integer(5)));
    inner.extend(encode_context(1, &encode_integer(15)));
    inner.extend(encode_context(2, &enc_blob));
    Ok(encode_application(15, &encode_sequence(&inner)))
}

pub fn encode_ap_rep(session_key: &KerberosSessionKey) -> Result<Vec<u8>> {
    let enc_ap_rep_part = encode_enc_ap_rep_part(session_key)?;
    let enc_blob =
        encrypt_encrypted_data(session_key, KEY_USAGE_AP_REP_ENC_PART, &enc_ap_rep_part)?;
    let mut inner = Vec::new();
    inner.extend(encode_context(0, &encode_integer(5)));
    inner.extend(encode_context(1, &encode_integer(15)));
    inner.extend(encode_context(2, &enc_blob));
    Ok(encode_application(15, &encode_sequence(&inner)))
}

pub fn parse_ap_req(bytes: &[u8]) -> Result<ApReqParts> {
    let mut reader = ByteReader::new(bytes);
    let tag = reader.read_u8()?;
    if tag != 0x6e {
        return Err(crate::Error::Der(format!(
            "expected AP-REQ 0x6e, got {tag:#x}"
        )));
    }
    let len = crate::asn1::read_length(&mut reader)?;
    let body = reader.read_bytes(len)?;
    let mut r = ByteReader::new(body);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("AP-REQ SEQUENCE expected".into()));
    }
    let slen = crate::asn1::read_length(&mut r)?;
    let seq = r.read_bytes(slen)?;
    let mut sr = ByteReader::new(seq);
    let mut ticket = Vec::new();
    let mut enc_authenticator = Vec::new();
    while !sr.is_empty() {
        let ctx = sr.read_u8()?;
        let clen = crate::asn1::read_length(&mut sr)?;
        let chunk = sr.read_bytes(clen)?;
        match ctx {
            0xA2 => ticket = chunk.to_vec(),
            0xA3 => enc_authenticator = chunk.to_vec(),
            _ => {}
        }
    }
    if ticket.is_empty() || enc_authenticator.is_empty() {
        return Err(crate::Error::InvalidMessage("incomplete AP-REQ".into()));
    }
    Ok(ApReqParts {
        ticket,
        enc_authenticator,
    })
}

fn encode_enc_ap_rep_part(session_key: &KerberosSessionKey) -> Result<Vec<u8>> {
    let mut inner = Vec::new();
    inner.extend(encode_context(0, &encode_integer(session_key.etype as u32)));
    inner.extend(encode_context(2, &encode_octet_string(&session_key.key)));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    inner.extend(encode_context(5, &encode_integer(now as u32)));
    inner.extend(encode_context(6, &encode_integer(0)));
    Ok(encode_sequence(&inner))
}

fn encrypt_encrypted_data(
    session_key: &KerberosSessionKey,
    key_usage: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let confounder = [0x01u8; 16];
    let cipher = session_key.encrypt(key_usage, plaintext, &confounder)?;
    let mut enc = Vec::new();
    enc.extend(encode_context(0, &encode_integer(session_key.etype as u32)));
    enc.extend(encode_context(2, &encode_octet_string(&cipher)));
    Ok(encode_sequence(&enc))
}

fn encode_authenticator_plain(realm: &str, cname: &PrincipalName, ctime: u64) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(encode_context(0, &encode_integer(5)));
    inner.extend(encode_context(1, &encode_integer(2)));
    inner.extend(encode_context(2, &encode_principal(cname)));
    inner.extend(encode_context(3, &encode_general_string(realm)));
    inner.extend(encode_context(5, &encode_integer(ctime as u32)));
    inner.extend(encode_context(6, &encode_integer(0u32)));
    encode_sequence(&inner)
}

fn encode_principal(name: &PrincipalName) -> Vec<u8> {
    let mut parts = Vec::new();
    parts.extend(encode_context(0, &encode_integer(name.name_type)));
    let mut strings = Vec::new();
    for c in &name.components {
        strings.extend(encode_sequence(&encode_general_string(c)));
    }
    parts.extend(encode_context(1, &encode_sequence(&strings)));
    encode_sequence(&parts)
}

pub fn encode_pa_tgs_req(ap_req: &[u8]) -> Vec<u8> {
    let mut pa = Vec::new();
    pa.extend(encode_context(1, &encode_integer(1)));
    pa.extend(encode_context(2, &encode_octet_string(ap_req)));
    encode_sequence(&pa)
}

pub fn ap_rep_for_ldap_bind(
    service_key: &KerberosSessionKey,
    server_sasl_creds: Option<&[u8]>,
) -> Result<Vec<u8>> {
    if let Some(creds) = server_sasl_creds {
        if let Some(ap_req) = extract_ap_req_from_spnego(creds) {
            return encode_ap_rep_from_challenge(service_key, &ap_req);
        }
    }
    encode_ap_rep(service_key)
}

fn extract_ap_req_from_spnego(spnego: &[u8]) -> Option<Vec<u8>> {
    find_kerberos_ap_req(spnego)
}

fn find_kerberos_ap_req(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() == Some(&0x6e) {
        return Some(data.to_vec());
    }
    let mut i = 0usize;
    while i < data.len() {
        let tag = *data.get(i)?;
        i += 1;
        let len = read_der_len_simple(data, i)?;
        let (hdr, l) = len;
        i += hdr;
        if i + l > data.len() {
            break;
        }
        let body = &data[i..i + l];
        if tag == 0x6e {
            let mut out = vec![0x6e];
            out.extend(encode_length_bytes(l));
            out.extend_from_slice(body);
            return Some(out);
        }
        if let Some(inner) = find_kerberos_ap_req(body) {
            return Some(inner);
        }
        i += l;
    }
    None
}

fn read_der_len_simple(data: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *data.get(off)?;
    if first < 0x80 {
        return Some((1, first as usize));
    }
    let n = (first & 0x7F) as usize;
    if n == 1 {
        return Some((2, usize::from(*data.get(off + 1)?)));
    }
    if n == 2 {
        let hi = usize::from(*data.get(off + 1)?);
        let lo = usize::from(*data.get(off + 2)?);
        return Some((3, (hi << 8) | lo));
    }
    None
}

fn encode_length_bytes(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xFF) as u8]
    }
}

#[must_use]
pub fn ldap_service_principal(host: &str, realm: &str) -> PrincipalName {
    let short = host.split('.').next().unwrap_or(host).to_uppercase();
    PrincipalName::new(2, vec!["ldap".into(), short, realm.into()])
}
