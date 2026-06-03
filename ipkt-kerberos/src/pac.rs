use hmac::{Hmac, Mac};
use md5::Md5;

use ipkt_core::ByteReader;

use crate::Result;

pub const PAC_BUFFER_LOGON_INFO: u32 = 1;
pub const PAC_BUFFER_CREDENTIAL_INFO: u32 = 2;
pub const PAC_BUFFER_SERVER_CHECKSUM: u32 = 6;
pub const PAC_BUFFER_KDC_CHECKSUM: u32 = 7;

pub const PAC_SIGNATURE_HMAC_MD5: u32 = 0;

pub const AD_IF_RELEVANT: i32 = 1;
pub const AD_WIN2K_PAC: i32 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PacInfoBuffer {
    buffer_type: u32,
    cb_size: u32,
    offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacSignature {
    pub signature_type: u32,
    pub signature: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacCredentialInfo {
    pub encryption_type: u32,
    pub kvno: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacBuffer {
    pub buffer_type: u32,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pac {
    pub raw: Vec<u8>,
    pub version: u32,
    pub buffers: Vec<PacBuffer>,
    pub logon: Option<PacLogonInfo>,
    pub kdc_checksum: Option<PacSignature>,
    pub server_checksum: Option<PacSignature>,
    pub credential_info: Option<PacCredentialInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacLogonInfo {
    pub effective_name: String,
    pub full_name: String,
    pub domain_name: String,
    pub logon_server: String,
    pub user_id: u32,
    pub primary_group_id: u32,
    pub logon_domain_id: Option<Vec<u8>>,
}

pub fn parse_pac(data: &[u8]) -> Result<Pac> {
    if data.len() < 8 {
        return Err(crate::Error::InvalidMessage("PAC too short".into()));
    }
    let c_buffers = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
    let headers = parse_pac_headers(data, c_buffers)?;
    let mut buffers = Vec::new();
    for hdr in &headers {
        if hdr.cb_size == 0 || hdr.offset + hdr.cb_size as usize > data.len() {
            continue;
        }
        let slice = data[hdr.offset..hdr.offset + hdr.cb_size as usize].to_vec();
        buffers.push(PacBuffer {
            buffer_type: hdr.buffer_type,
            data: slice,
        });
    }
    let kdc_checksum = buffers
        .iter()
        .find(|b| b.buffer_type == PAC_BUFFER_KDC_CHECKSUM)
        .and_then(|b| parse_pac_signature(&b.data));
    let server_checksum = buffers
        .iter()
        .find(|b| b.buffer_type == PAC_BUFFER_SERVER_CHECKSUM)
        .and_then(|b| parse_pac_signature(&b.data));
    let credential_info = buffers
        .iter()
        .find(|b| b.buffer_type == PAC_BUFFER_CREDENTIAL_INFO)
        .and_then(|b| parse_credential_info(&b.data));
    let logon = buffers
        .iter()
        .find(|b| b.buffer_type == PAC_BUFFER_LOGON_INFO)
        .and_then(|b| parse_logon_info(&b.data));
    Ok(Pac {
        raw: data.to_vec(),
        version,
        buffers,
        logon,
        kdc_checksum,
        server_checksum,
        credential_info,
    })
}

impl Pac {
    pub fn verify_checksums(
        &self,
        kdc_session_key: &[u8],
        service_session_key: &[u8],
    ) -> Result<()> {
        if self.kdc_checksum.is_some() {
            verify_pac_signature(
                &self.raw,
                PAC_BUFFER_KDC_CHECKSUM,
                &pac_signing_key(kdc_session_key),
                true,
            )?;
        }
        if self.server_checksum.is_some() {
            verify_pac_signature(
                &self.raw,
                PAC_BUFFER_SERVER_CHECKSUM,
                &pac_signing_key(service_session_key),
                false,
            )?;
        }
        Ok(())
    }
}

pub fn verify_pac_checksums(
    raw: &[u8],
    kdc_session_key: &[u8],
    service_session_key: &[u8],
) -> Result<()> {
    parse_pac(raw)?.verify_checksums(kdc_session_key, service_session_key)
}

fn parse_pac_headers(data: &[u8], c_buffers: u32) -> Result<Vec<PacInfoBuffer>> {
    let mut headers = Vec::new();
    let mut off = 8usize;
    for _ in 0..c_buffers {
        if off + 12 > data.len() {
            break;
        }
        headers.push(PacInfoBuffer {
            buffer_type: u32::from_le_bytes(data[off..off + 4].try_into().unwrap()),
            cb_size: u32::from_le_bytes(data[off + 4..off + 8].try_into().unwrap()),
            offset: u32::from_le_bytes(data[off + 8..off + 12].try_into().unwrap()) as usize,
        });
        off += 12;
    }
    Ok(headers)
}

fn parse_pac_signature(data: &[u8]) -> Option<PacSignature> {
    if data.len() < 20 {
        return None;
    }
    let signature_type = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let mut signature = [0u8; 16];
    signature.copy_from_slice(&data[4..20]);
    Some(PacSignature {
        signature_type,
        signature,
    })
}

fn parse_credential_info(data: &[u8]) -> Option<PacCredentialInfo> {
    if data.len() < 12 {
        return None;
    }
    let _version = u32::from_le_bytes(data[0..4].try_into().ok()?);
    let encryption_type = u32::from_le_bytes(data[4..8].try_into().ok()?);
    let kvno = u32::from_le_bytes(data[8..12].try_into().ok()?);
    Some(PacCredentialInfo {
        encryption_type,
        kvno,
    })
}

#[must_use]
pub fn pac_signing_key(session_key: &[u8]) -> [u8; 16] {
    let mut key = [0u8; 16];
    let n = session_key.len().min(16);
    key[..n].copy_from_slice(&session_key[..n]);
    key
}

fn verify_pac_signature(
    raw: &[u8],
    buffer_type: u32,
    key: &[u8; 16],
    zero_both_checksums: bool,
) -> Result<()> {
    let headers = parse_pac_headers(raw, u32::from_le_bytes(raw[0..4].try_into().unwrap()))?;
    let expected = headers
        .iter()
        .find(|h| h.buffer_type == buffer_type)
        .and_then(|h| {
            if h.offset + 20 > raw.len() {
                return None;
            }
            let mut sig = [0u8; 16];
            sig.copy_from_slice(&raw[h.offset + 4..h.offset + 20]);
            let sig_type = u32::from_le_bytes(raw[h.offset..h.offset + 4].try_into().ok()?);
            if sig_type != PAC_SIGNATURE_HMAC_MD5 {
                return None;
            }
            Some(sig)
        })
        .ok_or_else(|| {
            crate::Error::InvalidMessage(format!("PAC buffer type {buffer_type} missing"))
        })?;
    let computed = compute_pac_hmac(raw, &headers, key, zero_both_checksums)?;
    if computed != expected {
        return Err(crate::Error::Crypto(format!(
            "PAC signature mismatch for buffer type {buffer_type}"
        )));
    }
    Ok(())
}

fn compute_pac_hmac(
    raw: &[u8],
    headers: &[PacInfoBuffer],
    key: &[u8; 16],
    zero_both_checksums: bool,
) -> Result<[u8; 16]> {
    let mut copy = raw.to_vec();
    for hdr in headers {
        match hdr.buffer_type {
            PAC_BUFFER_KDC_CHECKSUM if zero_both_checksums => zero_signature(&mut copy, hdr),
            PAC_BUFFER_SERVER_CHECKSUM => zero_signature(&mut copy, hdr),
            _ => {}
        }
    }
    Ok(pac_hmac_md5(key, &copy))
}

fn zero_signature(pac: &mut [u8], hdr: &PacInfoBuffer) {
    let start = hdr.offset + 4;
    let end = start + 16;
    if end <= pac.len() {
        pac[start..end].fill(0);
    }
}

fn pac_hmac_md5(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut mac =
        <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC-MD5 accepts up to 64-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

pub fn parse_logon_info(data: &[u8]) -> Option<PacLogonInfo> {
    const OFF_EFFECTIVE: usize = 48;
    const OFF_FULL: usize = 60;
    const OFF_USER_ID: usize = 124;
    const OFF_PRIMARY_GID: usize = 128;
    const OFF_LOGON_SERVER: usize = 160;
    const OFF_LOGON_DOMAIN: usize = 172;

    if data.len() < OFF_LOGON_DOMAIN + 12 {
        return None;
    }
    let user_id = read_u32_at(data, OFF_USER_ID)?;
    let primary_group_id = read_u32_at(data, OFF_PRIMARY_GID)?;
    let effective_name = read_ndr_unicode_at(data, OFF_EFFECTIVE).unwrap_or_default();
    let full_name = read_ndr_unicode_at(data, OFF_FULL).unwrap_or_default();
    let domain_name = read_ndr_unicode_at(data, OFF_LOGON_DOMAIN).unwrap_or_default();
    let logon_server = read_ndr_unicode_at(data, OFF_LOGON_SERVER).unwrap_or_default();
    let logon_domain_id = find_sid_in_blob(data);
    Some(PacLogonInfo {
        effective_name,
        full_name,
        domain_name,
        logon_server,
        user_id,
        primary_group_id,
        logon_domain_id,
    })
}

pub fn extract_pac_from_enc_kdc_rep(plain: &[u8]) -> Option<Pac> {
    let blobs = extract_authorization_data_blobs(plain)?;
    for blob in blobs {
        if let Ok(pac) = parse_pac(&blob) {
            return Some(pac);
        }
        if let Some(nested) = extract_nested_pac(&blob) {
            return Some(nested);
        }
    }
    None
}

fn extract_nested_pac(ad_if_relevant: &[u8]) -> Option<Pac> {
    let blobs = extract_authorization_data_der(ad_if_relevant)?;
    for blob in blobs {
        if let Ok(pac) = parse_pac(&blob) {
            return Some(pac);
        }
    }
    None
}

fn extract_authorization_data_blobs(plain: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = ByteReader::new(plain);
    if r.read_u8().ok()? != 0x30 {
        return None;
    }
    let _ = crate::asn1::read_length(&mut r).ok()?;
    let mut out = Vec::new();
    while !r.is_empty() {
        let tag = r.read_u8().ok()?;
        let len = crate::asn1::read_length(&mut r).ok()?;
        let chunk = r.read_bytes(len).ok()?;
        if tag == 0xAB || tag == 0xA3 {
            out.extend(extract_authorization_data_der(chunk)?);
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn extract_authorization_data_der(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut r = ByteReader::new(bytes);
    let seq = r.read_u8().ok()?;
    if seq != 0x30 {
        return None;
    }
    let slen = crate::asn1::read_length(&mut r).ok()?;
    let body = r.read_bytes(slen).ok()?;
    let mut entries = Vec::new();
    let mut sr = ByteReader::new(body);
    while !sr.is_empty() {
        if sr.read_u8().ok()? != 0x30 {
            break;
        }
        let elen = crate::asn1::read_length(&mut sr).ok()?;
        let entry = sr.read_bytes(elen).ok()?;
        let ad_type = parse_ad_type(entry)?;
        if ad_type == AD_WIN2K_PAC {
            if let Some(data) = parse_ad_data(entry) {
                entries.push(data);
            }
        } else if ad_type == AD_IF_RELEVANT {
            if let Some(data) = parse_ad_data(entry) {
                entries.extend(extract_authorization_data_der(&data)?);
            }
        }
    }
    if entries.is_empty() {
        None
    } else {
        Some(entries)
    }
}

fn parse_ad_type(entry: &[u8]) -> Option<i32> {
    let mut r = ByteReader::new(entry);
    while !r.is_empty() {
        let tag = r.read_u8().ok()?;
        let len = crate::asn1::read_length(&mut r).ok()?;
        let chunk = r.read_bytes(len).ok()?;
        if tag == 0xA0 || tag == 0x02 {
            let mut inner = ByteReader::new(chunk);
            if inner.read_u8().ok()? == 0x02 {
                return Some(crate::asn1::decode_integer(&mut inner).ok()? as i32);
            }
            return Some(crate::asn1::decode_integer(&mut inner).ok()? as i32);
        }
    }
    None
}

fn parse_ad_data(entry: &[u8]) -> Option<Vec<u8>> {
    let mut r = ByteReader::new(entry);
    while !r.is_empty() {
        let tag = r.read_u8().ok()?;
        let len = crate::asn1::read_length(&mut r).ok()?;
        let chunk = r.read_bytes(len).ok()?;
        if tag == 0xA1 || tag == 0x04 {
            if chunk.first() == Some(&0x04) {
                let mut inner = ByteReader::new(chunk);
                let olen = crate::asn1::read_length(&mut inner).ok()?;
                return inner.read_bytes(olen).ok().map(|b| b.to_vec());
            }
            return Some(chunk.to_vec());
        }
    }
    None
}

fn read_ndr_unicode_at(data: &[u8], off: usize) -> Option<String> {
    if off + 12 > data.len() {
        return None;
    }
    let str_off = u32::from_le_bytes(data[off..off + 4].try_into().ok()?) as usize;
    let max = u16::from_le_bytes(data[off + 4..off + 6].try_into().ok()?);
    let actual = u16::from_le_bytes(data[off + 8..off + 10].try_into().ok()?);
    if actual == 0 || str_off + actual as usize * 2 > data.len() {
        return None;
    }
    let _ = max;
    decode_utf16(&data[str_off..str_off + actual as usize * 2])
}

fn read_u32_at(data: &[u8], off: usize) -> Option<u32> {
    if off + 4 > data.len() {
        return None;
    }
    Some(u32::from_le_bytes(data[off..off + 4].try_into().ok()?))
}

fn find_sid_in_blob(data: &[u8]) -> Option<Vec<u8>> {
    for off in 0..data.len().saturating_sub(12) {
        if data[off] == 0x01 && data[off + 1] >= 1 && data[off + 1] <= 8 {
            let subauth = data[off + 1] as usize;
            let len = 8 + subauth * 4;
            if off + len <= data.len() {
                return Some(data[off..off + len].to_vec());
            }
        }
    }
    None
}

fn decode_utf16(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    for chunk in bytes.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_logon_buffer() -> Vec<u8> {
        let mut logon = vec![0u8; 256];
        let name_utf = "alice"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        let domain_utf = "EXAMPLE"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect::<Vec<_>>();
        let name_off = 200usize;
        let domain_off = 220usize;
        logon[name_off..name_off + name_utf.len()].copy_from_slice(&name_utf);
        logon[domain_off..domain_off + domain_utf.len()].copy_from_slice(&domain_utf);
        logon[48..52].copy_from_slice(&(name_off as u32).to_le_bytes());
        logon[52..56].copy_from_slice(&(name_utf.len() as u32).to_le_bytes());
        logon[56..60].copy_from_slice(&(name_utf.len() as u32 / 2).to_le_bytes());
        logon[172..176].copy_from_slice(&(domain_off as u32).to_le_bytes());
        logon[176..180].copy_from_slice(&(domain_utf.len() as u32).to_le_bytes());
        logon[180..184].copy_from_slice(&(domain_utf.len() as u32 / 2).to_le_bytes());
        logon[124..128].copy_from_slice(&1000u32.to_le_bytes());
        logon[128..132].copy_from_slice(&513u32.to_le_bytes());
        logon
    }

    fn build_pac(buffers: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
        let header_size = 8 + buffers.len() * 12;
        let mut pac = vec![0u8; header_size];
        pac[0..4].copy_from_slice(&(buffers.len() as u32).to_le_bytes());
        let mut offset = header_size as u32;
        for (i, (ty, data)) in buffers.iter().enumerate() {
            let hoff = 8 + i * 12;
            pac[hoff..hoff + 4].copy_from_slice(&ty.to_le_bytes());
            pac[hoff + 4..hoff + 8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            pac[hoff + 8..hoff + 12].copy_from_slice(&offset.to_le_bytes());
            pac.extend_from_slice(data);
            offset += data.len() as u32;
        }
        pac
    }

    fn checksum_buffer(sig: &[u8; 16]) -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(&PAC_SIGNATURE_HMAC_MD5.to_le_bytes());
        buf[4..20].copy_from_slice(sig);
        buf
    }

    fn sign_pac(pac: &mut [u8], kdc_key: &[u8], srv_key: &[u8]) {
        let headers =
            parse_pac_headers(pac, u32::from_le_bytes(pac[0..4].try_into().unwrap())).unwrap();
        let kdc_hmac_key = pac_signing_key(kdc_key);
        let kdc_sig = compute_pac_hmac(pac, &headers, &kdc_hmac_key, true).unwrap();
        write_signature(pac, PAC_BUFFER_KDC_CHECKSUM, &kdc_sig);
        let headers =
            parse_pac_headers(pac, u32::from_le_bytes(pac[0..4].try_into().unwrap())).unwrap();
        let srv_hmac_key = pac_signing_key(srv_key);
        let srv_sig = compute_pac_hmac(pac, &headers, &srv_hmac_key, false).unwrap();
        write_signature(pac, PAC_BUFFER_SERVER_CHECKSUM, &srv_sig);
    }

    fn write_signature(pac: &mut [u8], buffer_type: u32, sig: &[u8; 16]) {
        let headers =
            parse_pac_headers(pac, u32::from_le_bytes(pac[0..4].try_into().unwrap())).unwrap();
        for hdr in headers {
            if hdr.buffer_type == buffer_type {
                pac[hdr.offset + 4..hdr.offset + 20].copy_from_slice(sig);
                break;
            }
        }
    }

    fn build_signed_test_pac(kdc_key: &[u8], srv_key: &[u8]) -> Vec<u8> {
        let mut pac = build_pac(vec![
            (PAC_BUFFER_LOGON_INFO, build_logon_buffer()),
            (PAC_BUFFER_KDC_CHECKSUM, checksum_buffer(&[0u8; 16])),
            (PAC_BUFFER_SERVER_CHECKSUM, checksum_buffer(&[0u8; 16])),
        ]);
        sign_pac(&mut pac, kdc_key, srv_key);
        pac
    }

    #[test]
    fn parse_pac_logon_buffer() {
        let pac = parse_pac(&build_signed_test_pac(&[0x11; 16], &[0x22; 16])).unwrap();
        let logon = pac.logon.as_ref().unwrap();
        assert_eq!(logon.user_id, 1000);
        assert_eq!(logon.primary_group_id, 513);
        assert!(logon.effective_name.contains("alice"));
        assert!(logon.domain_name.contains("EXAMPLE"));
    }

    #[test]
    fn pac_checksum_roundtrip() {
        let kdc_key = [0xAA; 32];
        let srv_key = [0xBB; 16];
        let raw = build_signed_test_pac(&kdc_key, &srv_key);
        verify_pac_checksums(&raw, &kdc_key, &srv_key).unwrap();
    }

    #[test]
    fn pac_checksum_rejects_tamper() {
        let kdc_key = [0xAA; 32];
        let srv_key = [0xBB; 16];
        let mut raw = build_signed_test_pac(&kdc_key, &srv_key);
        if let Some(b) = raw.last_mut() {
            *b ^= 0xFF;
        }
        assert!(verify_pac_checksums(&raw, &kdc_key, &srv_key).is_err());
    }
}
