use ipkt_core::ByteReader;

use crate::aes_cts::{
    decrypt_aes256, string2key_aes256, KEY_USAGE_AS_REP_ENC_PART, KEY_USAGE_TGS_REP_ENC_PART,
};
use crate::crypto::ETYPE_AES256_CTS_HMAC_SHA1_96;
use crate::des_crypto::{
    decrypt_des3_cbc_sha1, decrypt_des_cbc_crc, decrypt_des_cbc_md5, string2key_des,
    string2key_des3, ETYPE_DES3_CBC_SHA1, ETYPE_DES_CBC_CRC, ETYPE_DES_CBC_MD5,
};
use crate::pac::{extract_pac_from_enc_kdc_rep, Pac};
use crate::rc4_hmac::{decrypt_rc4_hmac, string2key_rc4, ETYPE_RC4_HMAC};
use crate::session_key::KerberosSessionKey;
use crate::types::EncryptedData;
use crate::Result;

pub fn session_key_from_as_rep(
    password: &str,
    realm: &str,
    user: &str,
    enc_part: &[u8],
) -> Result<KerberosSessionKey> {
    let enc = parse_encrypted_data(enc_part)?;
    match enc.etype {
        ETYPE_AES256_CTS_HMAC_SHA1_96 => {
            let salt = format!("{realm}{user}");
            let base = string2key_aes256(password, salt.as_bytes(), 4096)?;
            let plain = decrypt_aes256(&base, KEY_USAGE_AS_REP_ENC_PART, &enc.cipher)?;
            parse_session_key_from_enc_kdc_rep(&plain, enc.etype)
        }
        ETYPE_RC4_HMAC => {
            let salt = format!("{realm}{user}");
            let base = string2key_rc4(password, salt.as_bytes());
            let plain = decrypt_rc4_hmac(&base, KEY_USAGE_AS_REP_ENC_PART, &enc.cipher)?;
            parse_session_key_from_enc_kdc_rep(&plain, enc.etype)
        }
        ETYPE_DES_CBC_CRC | ETYPE_DES_CBC_MD5 => {
            let salt = format!("{realm}{user}");
            let base = string2key_des(password, salt.as_bytes());
            let plain = if enc.etype == ETYPE_DES_CBC_CRC {
                decrypt_des_cbc_crc(&base, KEY_USAGE_AS_REP_ENC_PART, &enc.cipher)?
            } else {
                decrypt_des_cbc_md5(&base, KEY_USAGE_AS_REP_ENC_PART, &enc.cipher)?
            };
            parse_session_key_from_enc_kdc_rep(&plain, enc.etype)
        }
        ETYPE_DES3_CBC_SHA1 => {
            let salt = format!("{realm}{user}");
            let base = string2key_des3(password, salt.as_bytes());
            let plain = decrypt_des3_cbc_sha1(&base, KEY_USAGE_AS_REP_ENC_PART, &enc.cipher)?;
            parse_session_key_from_enc_kdc_rep(&plain, enc.etype)
        }
        et => Err(crate::Error::Crypto(format!(
            "unsupported AS-REP etype {et}"
        ))),
    }
}

pub fn session_key_from_tgs_rep(
    tgt_session_key: &KerberosSessionKey,
    enc_part: &[u8],
) -> Result<KerberosSessionKey> {
    let plain = decrypt_tgs_rep_enc_part(tgt_session_key, enc_part)?;
    let enc = parse_encrypted_data(enc_part)?;
    parse_session_key_from_enc_kdc_rep(&plain, enc.etype)
}

pub fn decrypt_tgs_rep_enc_part(
    tgt_session_key: &KerberosSessionKey,
    enc_part: &[u8],
) -> Result<Vec<u8>> {
    let enc = parse_encrypted_data(enc_part)?;
    tgt_session_key.decrypt(KEY_USAGE_TGS_REP_ENC_PART, &enc.cipher)
}

pub fn extract_pac_from_tgs_rep(
    tgt_session_key: &KerberosSessionKey,
    enc_part: &[u8],
) -> Result<Option<Pac>> {
    let plain = decrypt_tgs_rep_enc_part(tgt_session_key, enc_part)?;
    Ok(extract_pac_from_enc_kdc_rep(&plain))
}

pub fn extract_and_verify_pac_from_tgs_rep(
    tgt_session_key: &KerberosSessionKey,
    enc_part: &[u8],
    service_session_key: &KerberosSessionKey,
) -> Result<Option<Pac>> {
    let plain = decrypt_tgs_rep_enc_part(tgt_session_key, enc_part)?;
    if let Some(pac) = extract_pac_from_enc_kdc_rep(&plain) {
        pac.verify_checksums(&tgt_session_key.key, &service_session_key.key)?;
        return Ok(Some(pac));
    }
    Ok(None)
}

fn parse_session_key_from_enc_kdc_rep(plain: &[u8], etype: i32) -> Result<KerberosSessionKey> {
    let mut r = ByteReader::new(plain);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected EncKDCRepPart SEQUENCE".into()));
    }
    let _ = crate::asn1::read_length(&mut r)?;
    let mut key = Vec::new();
    let mut out_etype = etype;
    while !r.is_empty() {
        let tag = r.read_u8()?;
        let len = crate::asn1::read_length(&mut r)?;
        let chunk = r.read_bytes(len)?;
        match tag {
            0xA0 => {
                let mut inner = ByteReader::new(chunk);
                out_etype = crate::asn1::decode_integer(&mut inner)? as i32;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                if inner.read_u8()? == 0x04 {
                    let clen = crate::asn1::read_length(&mut inner)?;
                    key = inner.read_bytes(clen)?.to_vec();
                }
            }
            _ => {}
        }
    }
    if key.is_empty() {
        return Err(crate::Error::InvalidMessage(
            "missing key in EncKDCRepPart".into(),
        ));
    }
    Ok(KerberosSessionKey::from_parts(out_etype, key))
}

pub fn parse_encrypted_data(bytes: &[u8]) -> Result<EncryptedData> {
    let mut r = ByteReader::new(bytes);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected EncryptedData SEQUENCE".into()));
    }
    let _ = crate::asn1::read_length(&mut r)?;
    let mut etype = 0i32;
    let mut cipher = Vec::new();
    while !r.is_empty() {
        let tag = r.read_u8()?;
        let len = crate::asn1::read_length(&mut r)?;
        let chunk = r.read_bytes(len)?;
        match tag {
            0xA0 => {
                let mut inner = ByteReader::new(chunk);
                etype = crate::asn1::decode_integer(&mut inner)? as i32;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                if inner.read_u8()? == 0x04 {
                    let clen = crate::asn1::read_length(&mut inner)?;
                    cipher = inner.read_bytes(clen)?.to_vec();
                }
            }
            _ => {}
        }
    }
    Ok(EncryptedData {
        etype,
        kvno: None,
        cipher,
    })
}
