include!("crc32_table.inc");

use des::cipher::{Block, BlockDecrypt, BlockEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md5::Md5;

use crate::crypto::n_fold;
use crate::Result;

pub const ETYPE_DES_CBC_MD5: i32 = 3;

pub const ETYPE_DES3_CBC_SHA1: i32 = 7;

pub const ETYPE_DES_CBC_CRC: i32 = 1;

pub fn string2key_des(password: &str, salt: &[u8]) -> [u8; 8] {
    let mut material = Vec::new();
    material.extend_from_slice(password.as_bytes());
    material.extend_from_slice(salt);
    let folded = n_fold(7, &material);
    let mut key7 = [0u8; 7];
    key7.copy_from_slice(&folded[..7]);
    des_key_from_7bytes(key7)
}

pub fn string2key_des3(password: &str, salt: &[u8]) -> [u8; 24] {
    let k1 = string2key_des(password, salt);
    let mut salt2 = salt.to_vec();
    salt2.push(0);
    let k2 = string2key_des(password, &salt2);
    let mut salt3 = salt.to_vec();
    salt3.push(1);
    let k3 = string2key_des(password, &salt3);
    let mut out = [0u8; 24];
    out[..8].copy_from_slice(&k1);
    out[8..16].copy_from_slice(&k2);
    out[16..].copy_from_slice(&k3);
    out
}

pub fn crc32_kerberos(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        let idx = usize::from(b ^ (crc as u8));
        crc >>= 8;
        crc ^= KRB5_CRC32_TABLE[idx];
    }
    crc
}

pub fn encrypt_des_cbc_crc(key: &[u8; 8], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ke = derive_des_key(key, key_usage, 0xAA);
    let mut confounder = [0u8; 8];
    confounder.copy_from_slice(&plaintext.len().to_le_bytes());
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);
    pad_des_block(&mut data);
    let checksum = crc32_kerberos(&data).to_le_bytes();
    let cipher = des_cbc(&ke, &data, true);
    let mut out = checksum.to_vec();
    out.extend(cipher);
    Ok(out)
}

pub fn decrypt_des_cbc_crc(key: &[u8; 8], key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < 12 {
        return Err(crate::Error::Crypto("DES-CRC cipher too short".into()));
    }
    let (checksum, body) = cipher.split_at(4);
    let ke = derive_des_key(key, key_usage, 0xAA);
    let plain = des_cbc(&ke, body, false);
    let expect = crc32_kerberos(&plain).to_le_bytes();
    if expect != checksum {
        return Err(crate::Error::Crypto("DES-CBC-CRC checksum mismatch".into()));
    }
    strip_des_plaintext(&plain)
}

pub fn encrypt_des_cbc_md5(key: &[u8; 8], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ke = derive_des_key(key, key_usage, 0xAA);
    let mut confounder = [0u8; 8];
    confounder.copy_from_slice(&plaintext.len().to_le_bytes());
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);
    pad_des_block(&mut data);
    let cipher = des_cbc(&ke, &data, true);
    let ki = derive_des_key(key, key_usage, 0x55);
    let checksum = hmac_md5(&ki, &data);
    let mut out = checksum.to_vec();
    out.extend(cipher);
    Ok(out)
}

pub fn decrypt_des_cbc_md5(key: &[u8; 8], key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    if cipher.len() < 24 {
        return Err(crate::Error::Crypto("DES cipher too short".into()));
    }
    let (checksum, body) = cipher.split_at(16);
    let ke = derive_des_key(key, key_usage, 0xAA);
    let plain = des_cbc(&ke, body, false);
    let ki = derive_des_key(key, key_usage, 0x55);
    let expect = hmac_md5(&ki, &plain);
    if expect != checksum {
        return Err(crate::Error::Crypto("DES-CBC-MD5 checksum mismatch".into()));
    }
    strip_des_plaintext(&plain)
}

pub fn encrypt_des3_cbc_sha1(key: &[u8; 24], key_usage: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
    use sha1::{Digest, Sha1};
    let ke = derive_des3_key(key, key_usage, 0xAA);
    let mut confounder = [0u8; 8];
    confounder.copy_from_slice(&plaintext.len().to_le_bytes());
    let mut data = Vec::with_capacity(8 + plaintext.len());
    data.extend_from_slice(&confounder);
    data.extend_from_slice(plaintext);
    pad_des_block(&mut data);
    let cipher = des3_cbc(&ke, &data, true);
    let ki = derive_des3_key(key, key_usage, 0x55);
    let mut hasher = Sha1::new();
    hasher.update(ki);
    hasher.update(&data);
    let checksum = hasher.finalize();
    let mut out = checksum.to_vec();
    out.extend(cipher);
    Ok(out)
}

pub fn decrypt_des3_cbc_sha1(key: &[u8; 24], key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
    use sha1::{Digest, Sha1};
    if cipher.len() < 28 {
        return Err(crate::Error::Crypto("3DES cipher too short".into()));
    }
    let (checksum, body) = cipher.split_at(20);
    let ke = derive_des3_key(key, key_usage, 0xAA);
    let plain = des3_cbc(&ke, body, false);
    let ki = derive_des3_key(key, key_usage, 0x55);
    let mut hasher = Sha1::new();
    hasher.update(ki);
    hasher.update(&plain);
    if hasher.finalize().as_slice() != checksum {
        return Err(crate::Error::Crypto("3DES-SHA1 checksum mismatch".into()));
    }
    strip_des_plaintext(&plain)
}

fn derive_des_key(key: &[u8; 8], usage: u32, constant: u8) -> [u8; 8] {
    let mut buf = vec![constant];
    buf.extend_from_slice(&usage.to_le_bytes());
    let mac = hmac_md5(key, &buf);
    let folded = n_fold(7, &mac);
    let mut key7 = [0u8; 7];
    key7.copy_from_slice(&folded[..7]);
    des_key_from_7bytes(key7)
}

fn derive_des3_key(key: &[u8; 24], usage: u32, constant: u8) -> [u8; 24] {
    use sha1::{Digest, Sha1};
    let mut buf = vec![constant];
    buf.extend_from_slice(&usage.to_le_bytes());
    let mut hasher = Sha1::new();
    hasher.update(key);
    hasher.update(&buf);
    let folded = n_fold(24, hasher.finalize().as_slice());
    let mut out = [0u8; 24];
    out.copy_from_slice(&folded[..24]);
    out
}

fn des_key_from_7bytes(key7: [u8; 7]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = key7[0] >> 1;
    out[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    out[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    out[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    out[4] = ((key7[3] & 0x0F) << 3) | (key7[4] >> 5);
    out[5] = ((key7[4] & 0x1F) << 2) | (key7[5] >> 6);
    out[6] = ((key7[5] & 0x3F) << 1) | (key7[6] >> 7);
    out[7] = key7[6] & 0x7F;
    for b in &mut out {
        *b = (*b << 1) & 0xFE;
    }
    out
}

fn strip_des_plaintext(plain: &[u8]) -> Result<Vec<u8>> {
    if plain.len() < 16 {
        return Err(crate::Error::Crypto("DES plaintext too short".into()));
    }
    let pad = plain[plain.len() - 1] as usize;
    if pad == 0 || pad > 8 || plain.len() < 8 + pad {
        return Err(crate::Error::Crypto("invalid DES padding".into()));
    }
    Ok(plain[8..plain.len() - pad].to_vec())
}

fn pad_des_block(data: &mut Vec<u8>) {
    let pad = (8 - (data.len() % 8)) % 8;
    if pad == 0 {
        data.extend([0x08; 8]);
    } else {
        data.extend(vec![pad as u8; pad]);
    }
}

fn block_to_iv(block: Block<Des>) -> [u8; 8] {
    let mut iv = [0u8; 8];
    iv.copy_from_slice(block.as_slice());
    iv
}

fn des_cbc(key: &[u8; 8], data: &[u8], encrypt: bool) -> Vec<u8> {
    let cipher = Des::new_from_slice(key).expect("DES key");
    let mut iv = [0u8; 8];
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks_exact(8) {
        let mut block = Block::<Des>::clone_from_slice(chunk);
        if encrypt {
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            cipher.encrypt_block(&mut block);
            iv = block_to_iv(block);
        } else {
            let prev = block_to_iv(block);
            cipher.decrypt_block(&mut block);
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            iv = prev;
        }
        out.extend_from_slice(block.as_slice());
    }
    out
}

fn des3_cbc(key: &[u8; 24], data: &[u8], encrypt: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut iv = [0u8; 8];
    for chunk in data.chunks_exact(8) {
        let mut block = Block::<Des>::clone_from_slice(chunk);
        if encrypt {
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            let c1 = Des::new_from_slice(&key[..8]).expect("3DES key");
            let c2 = Des::new_from_slice(&key[8..16]).expect("3DES key");
            let c3 = Des::new_from_slice(&key[16..]).expect("3DES key");
            c1.encrypt_block(&mut block);
            c2.decrypt_block(&mut block);
            c3.encrypt_block(&mut block);
            iv = block_to_iv(block);
        } else {
            let prev = block_to_iv(block);
            let c1 = Des::new_from_slice(&key[..8]).expect("3DES key");
            let c2 = Des::new_from_slice(&key[8..16]).expect("3DES key");
            let c3 = Des::new_from_slice(&key[16..]).expect("3DES key");
            c3.decrypt_block(&mut block);
            c2.encrypt_block(&mut block);
            c1.decrypt_block(&mut block);
            for i in 0..8 {
                block[i] ^= iv[i];
            }
            iv = prev;
        }
        out.extend_from_slice(block.as_slice());
    }
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac =
        <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC-MD5 accepts up to 64-byte key");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des3_roundtrip() {
        let key = string2key_des3("password", b"REALMuser");
        let plain = b"kerberos";
        let enc = encrypt_des3_cbc_sha1(&key, 8, plain).unwrap();
        let dec = decrypt_des3_cbc_sha1(&key, 8, &enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn des_cbc_inverts() {
        let key = [0x42u8; 8];
        let data = (0..16).collect::<Vec<_>>();
        let enc = des_cbc(&key, &data, true);
        let dec = des_cbc(&key, &enc, false);
        assert_eq!(data, dec);
    }

    #[test]
    fn crc32_rfc3961_vectors() {
        assert_eq!(crc32_kerberos(b"foo"), 0x7332_bc33);
        assert_eq!(crc32_kerberos(b"test0123456789"), 0xb83e_88d6);
    }

    #[test]
    fn des_crc_roundtrip() {
        let key = string2key_des("password", b"REALMuser");
        let plain = b"kerb";
        let enc = encrypt_des_cbc_crc(&key, 3, plain).unwrap();
        let dec = decrypt_des_cbc_crc(&key, 3, &enc).unwrap();
        assert_eq!(dec, plain);
    }

    #[test]
    fn des_md5_roundtrip() {
        let key = string2key_des("password", b"REALMuser");
        let plain = b"test";
        let enc = encrypt_des_cbc_md5(&key, 3, plain).unwrap();
        let dec = decrypt_des_cbc_md5(&key, 3, &enc).unwrap();
        assert_eq!(dec, plain);
    }
}
