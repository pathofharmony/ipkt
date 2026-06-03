use ipkt_core::ByteWriter;

use crate::asn1::{encode_context, encode_integer, encode_sequence};
use crate::aes_cts::{encrypt_aes256, string2key_aes256, KEY_USAGE_PA_ENC_TIMESTAMP};
use crate::crypto::ETYPE_AES256_CTS_HMAC_SHA1_96;
use crate::types::EncryptedData;
use crate::Result;


pub const PA_ENC_TIMESTAMP: i32 = 2;

pub const PA_PAC_REQUEST: i32 = 128;


#[must_use]
pub fn encode_pa_pac_request() -> Vec<u8> {
    let include_pac = encode_context(0, &[0x01, 0x01, 0xff]);
    let body = encode_sequence(&include_pac);
    let mut pa = Vec::new();
    pa.extend(encode_context(1, &encode_integer(PA_PAC_REQUEST as u32)));
    pa.extend(encode_context(2, &encode_sequence(&body)));
    encode_sequence(&pa)
}


pub fn build_pa_enc_timestamp(
    password: &str,
    realm: &str,
    principal: &str,
    timestamp: u64,
    usec: u32,
) -> Result<EncryptedData> {
    let mut inner = Vec::new();
    inner.extend(encode_kerberos_timestamp(timestamp));
    inner.extend(encode_kerberos_usec(usec));
    let seq = encode_sequence(&inner);
    let salt = format!("{realm}{principal}");
    let key = string2key_aes256(password, salt.as_bytes(), 4096)?;
    let confounder = fixed_confounder(timestamp, usec);
    let cipher = encrypt_aes256(&key, KEY_USAGE_PA_ENC_TIMESTAMP, &seq, &confounder)?;
    Ok(EncryptedData {
        etype: ETYPE_AES256_CTS_HMAC_SHA1_96,
        kvno: None,
        cipher,
    })
}

fn encode_kerberos_timestamp(ts: u64) -> Vec<u8> {
    let s = format!("{ts}");
    let mut w = ByteWriter::new();
    w.write_u8(0x18);
    crate::asn1::encode_length_public(&mut w, s.len());
    w.write_bytes(s.as_bytes());
    w.into_vec()
}

fn encode_kerberos_usec(usec: u32) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(0x02);
    crate::asn1::encode_length_public(&mut w, 4);
    w.write_bytes(&usec.to_be_bytes());
    w.into_vec()
}

fn fixed_confounder(timestamp: u64, usec: u32) -> [u8; 16] {
    let mut c = [0u8; 16];
    c[..8].copy_from_slice(&timestamp.to_le_bytes());
    c[8..12].copy_from_slice(&usec.to_le_bytes());
    c
}


pub fn encode_pa_enc_timestamp(enc: &EncryptedData) -> Vec<u8> {
    let mut ed = Vec::new();
    ed.extend(encode_context(0, &encode_integer(enc.etype as u32)));
    if let Some(kvno) = enc.kvno {
        ed.extend(encode_context(1, &encode_integer(kvno as u32)));
    }
    let mut w = ByteWriter::new();
    w.write_u8(0x04);
    crate::asn1::encode_length_public(&mut w, enc.cipher.len());
    w.write_bytes(&enc.cipher);
    ed.extend(encode_context(2, &w.into_vec()));
    let mut pa = Vec::new();
    pa.extend(encode_context(1, &encode_integer(PA_ENC_TIMESTAMP as u32)));
    pa.extend(encode_context(2, &encode_sequence(&ed)));
    encode_sequence(&pa)
}
