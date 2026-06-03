use sha2::{Digest, Sha512};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};

use crate::error::{Error, Result};


pub const SMB2_TRANSFORM_PROTOCOL_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];

pub const SMB2_ENCRYPTION_AES128_GCM: u16 = 0x0001;

pub const SMB2_TRANSFORM_HEADER_SIZE: usize = 52;


#[must_use]
pub fn preauth_integrity_cap_sha512() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes()); 
    out.extend_from_slice(&[0u8; 32]); 
    out
}


#[must_use]
pub fn encryption_cap_aes128_gcm() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_le_bytes()); 
    out.extend_from_slice(&SMB2_ENCRYPTION_AES128_GCM.to_le_bytes());
    out.extend_from_slice(&[0u8; 14]); 
    out
}


#[must_use]
pub fn derive_encryption_key(exported_session_key: &[u8; 16]) -> [u8; 16] {
    let mut key = [0u8; 16];
    key.copy_from_slice(exported_session_key);
    key
}


#[must_use]
pub fn preauth_hash_sha512(prev: &[u8; 64], message: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(prev);
    h.update(message);
    h.finalize().into()
}


pub fn encrypt_message(session_key: &[u8; 16], session_id: u64, plain: &[u8]) -> Result<Vec<u8>> {
    let key = derive_encryption_key(session_key);
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| Error::Transport(e.to_string()))?;
    let mut nonce_field = [0u8; 16];
    nonce_field[4..12].copy_from_slice(&session_id.to_le_bytes());
    let gcm_nonce = &nonce_field[..12];
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(gcm_nonce), plain)
        .map_err(|e| Error::Transport(e.to_string()))?;
    let mut out = Vec::with_capacity(SMB2_TRANSFORM_HEADER_SIZE + ciphertext.len());
    out.extend_from_slice(&SMB2_TRANSFORM_PROTOCOL_ID);
    out.extend_from_slice(&[0u8; 16]); 
    out.extend_from_slice(&nonce_field);
    out.extend_from_slice(&(plain.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); 
    out.extend_from_slice(&SMB2_ENCRYPTION_AES128_GCM.to_le_bytes());
    out.extend_from_slice(&session_id.to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}


pub fn decrypt_message(session_key: &[u8; 16], framed: &[u8]) -> Result<Vec<u8>> {
    if framed.len() < SMB2_TRANSFORM_HEADER_SIZE {
        return Err(Error::Framing("transform too short".into()));
    }
    if framed[..4] != SMB2_TRANSFORM_PROTOCOL_ID {
        return Err(Error::Framing("not SMB2 transform".into()));
    }
    let nonce = &framed[20..32]; 
    let original_size =
        u32::from_le_bytes(framed[36..40].try_into().map_err(|_| Error::Framing("size".into()))?)
            as usize;
    let session_id =
        u64::from_le_bytes(framed[44..52].try_into().map_err(|_| Error::Framing("sid".into()))?);
    let ciphertext = &framed[SMB2_TRANSFORM_HEADER_SIZE..];
    let key = derive_encryption_key(session_key);
    let cipher = Aes128Gcm::new_from_slice(&key).map_err(|e| Error::Transport(e.to_string()))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| Error::Transport(e.to_string()))?;
    if plain.len() < original_size {
        return Err(Error::Framing("decrypted length mismatch".into()));
    }
    let _ = session_id;
    Ok(plain[..original_size].to_vec())
}
