use aes::Aes256;
use cts::{Decrypt, Encrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::Sha1;

use crate::crypto::n_fold;
use crate::Result;

const HASH_SIZE: usize = 12;
const BLOCK: usize = 16;

pub const KEY_USAGE_PA_ENC_TIMESTAMP: u32 = 1;

pub const KEY_USAGE_AS_REP_ENC_PART: u32 = 3;

pub const KEY_USAGE_TGS_REP_ENC_PART: u32 = 8;

pub fn string2key_aes256(password: &str, salt: &[u8], iter_count: u32) -> Result<[u8; 32]> {
    let mut tkey = [0u8; 32];
    pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, iter_count, &mut tkey)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;
    dk_aes256(&tkey, b"kerberos")
}

pub fn encrypt_aes256(
    base_key: &[u8; 32],
    key_usage: u32,
    plaintext: &[u8],
    confounder: &[u8; 16],
) -> Result<Vec<u8>> {
    let ke = derive_key_aes256(base_key, key_usage, 0xAA);
    let ki = derive_key_aes256(base_key, key_usage, 0x55);
    let mut data = Vec::with_capacity(16 + plaintext.len() + BLOCK);
    data.extend_from_slice(confounder);
    data.extend_from_slice(plaintext);
    let pad_len = BLOCK - (data.len() % BLOCK);
    data.extend(std::iter::repeat_n(pad_len as u8, pad_len));
    let encrypted = aes256_cts(&ke, &data, true)?;
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&ki)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;
    mac.update(confounder);
    mac.update(&encrypted);
    let mut out = encrypted;
    out.extend_from_slice(&mac.finalize().into_bytes()[..HASH_SIZE]);
    Ok(out)
}

pub fn decrypt_aes256(base_key: &[u8; 32], key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < BLOCK + HASH_SIZE {
        return Err(crate::Error::Crypto("ciphertext too short".into()));
    }
    let (body, mac) = cipher.split_at(cipher.len() - HASH_SIZE);
    let ke = derive_key_aes256(base_key, key_usage, 0xAA);
    let plain = aes256_cts(&ke, body, false)?;
    let ki = derive_key_aes256(base_key, key_usage, 0x55);
    let confounder = &plain[..BLOCK];
    let mut mac_check = <Hmac<Sha1> as Mac>::new_from_slice(&ki)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;
    mac_check.update(confounder);
    mac_check.update(body);
    let expected = mac_check.finalize().into_bytes();
    if expected[..HASH_SIZE] != *mac {
        return Err(crate::Error::Crypto("HMAC verification failed".into()));
    }
    if plain.len() < BLOCK {
        return Err(crate::Error::Crypto("plaintext too short".into()));
    }
    let payload = &plain[BLOCK..];
    let pad = payload
        .last()
        .copied()
        .filter(|&p| p > 0 && (p as usize) <= payload.len())
        .unwrap_or(1);
    let end = payload.len().saturating_sub(pad as usize);
    Ok(payload[..end].to_vec())
}

fn dk_aes256(key: &[u8; 32], constant: &[u8]) -> Result<[u8; 32]> {
    let folded = n_fold(constant.len(), constant);
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;
    mac.update(&folded);
    let o1 = mac.finalize().into_bytes();
    let mut mac2 = <Hmac<Sha1> as Mac>::new_from_slice(key)
        .map_err(|e| crate::Error::Crypto(e.to_string()))?;
    mac2.update(&o1);
    let o2 = mac2.finalize().into_bytes();
    let mut out = [0u8; 32];
    out[..20].copy_from_slice(&o1);
    out[20..].copy_from_slice(&o2[..12]);
    Ok(out)
}

fn derive_key_aes256(base: &[u8; 32], usage: u32, suffix: u8) -> [u8; 32] {
    let constant = [
        ((usage >> 24) & 0xFF) as u8,
        ((usage >> 16) & 0xFF) as u8,
        ((usage >> 8) & 0xFF) as u8,
        (usage & 0xFF) as u8,
        suffix,
    ];
    dk_aes256(base, &constant).unwrap_or(*base)
}

fn aes256_cts(key: &[u8; 32], data: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    let iv = [0u8; 16];
    if encrypt {
        let mode = cts::CbcCs3::<Aes256>::new(key.into(), &iv.into());
        let mut buf = data.to_vec();
        mode.encrypt_b2b(data, &mut buf)
            .map_err(|_| crate::Error::Crypto("CTS encrypt failed".into()))?;
        Ok(buf)
    } else {
        let mode = cts::CbcCs3::<Aes256>::new(key.into(), &iv.into());
        let mut buf = data.to_vec();
        mode.decrypt(&mut buf)
            .map_err(|_| crate::Error::Crypto("CTS decrypt failed".into()))?;
        Ok(buf)
    }
}
