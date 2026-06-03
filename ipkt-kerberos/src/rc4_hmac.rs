use hmac::{Hmac, Mac};
use md4::{Digest as Md4Digest, Md4};
use md5::Md5;

use crate::crypto::n_fold;
use crate::Result;

pub const ETYPE_RC4_HMAC: i32 = 23;

pub fn string2key_rc4(password: &str, salt: &[u8]) -> [u8; 16] {
    let _ = salt;
    let mut hasher = Md4::new();
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    hasher.update(utf16);
    let k = hasher.finalize();
    let k1 = hmac_md5(&k, &[0, 0, 0, 1]);
    let k2 = hmac_md5(&k, &[0, 0, 0, 2]);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&k1[..8]);
    out[8..].copy_from_slice(&k2[..8]);
    let _ = salt;
    out
}

pub fn encrypt_rc4_hmac(key: &[u8], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ki = derive_key_rc4(key, key_usage, 0x55);
    let mut confounder = [0u8; 8];
    confounder.copy_from_slice(&plaintext.len().to_le_bytes());
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);
    let checksum = hmac_md5(&ki, &data);
    let ke = derive_key_rc4(key, key_usage, 0xAA);
    let mut cipher = rc4_crypt(&ke, &data);
    let mut out = checksum.to_vec();
    out.append(&mut cipher);
    Ok(out)
}

pub fn decrypt_rc4_hmac(key: &[u8], key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < 16 {
        return Err(crate::Error::Crypto("RC4 cipher too short".into()));
    }
    let (checksum, body) = cipher.split_at(16);
    let ke = derive_key_rc4(key, key_usage, 0xAA);
    let plain = rc4_crypt(&ke, body);
    let ki = derive_key_rc4(key, key_usage, 0x55);
    let expect = hmac_md5(&ki, &plain);
    if expect != checksum {
        return Err(crate::Error::Crypto("RC4-HMAC checksum mismatch".into()));
    }
    if plain.len() < 8 {
        return Err(crate::Error::Crypto("RC4 plaintext too short".into()));
    }
    Ok(plain[8..].to_vec())
}

fn derive_key_rc4(key: &[u8], usage: u32, constant: u8) -> [u8; 16] {
    let usage_bytes = usage.to_le_bytes();
    let mut buf = vec![constant];
    buf.extend_from_slice(&usage_bytes);
    let folded = n_fold(16, &buf);
    hmac_md5(key, &folded)
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC-MD5 accepts up to 64-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn rc4_crypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut s: Vec<u8> = (0u8..=255).collect();
    let mut j = 0usize;
    for i in 0..256 {
        j = (j + s[i] as usize + key[i % key.len()] as usize) % 256;
        s.swap(i, j);
    }
    let mut i = 0usize;
    j = 0;
    let mut out = Vec::with_capacity(data.len());
    for &b in data {
        i = (i + 1) % 256;
        j = (j + s[i] as usize) % 256;
        s.swap(i, j);
        let k = s[(s[i] as usize + s[j] as usize) % 256];
        out.push(b ^ k);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_roundtrip() {
        let key = string2key_rc4("password", b"DOMAINuser");
        let plain = b"kerberos";
        let enc = encrypt_rc4_hmac(&key, 3, plain).unwrap();
        let dec = decrypt_rc4_hmac(&key, 3, &enc).unwrap();
        assert_eq!(dec, plain);
    }
}
