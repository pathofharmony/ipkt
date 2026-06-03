use des::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use des::Des;
use ipkt_ntlm::crypto::{md5, rc4};




pub fn decrypt_drs_attribute(session_key: &[u8], attribute: &[u8]) -> Option<Vec<u8>> {
    if attribute.len() < 20 {
        return None;
    }
    let salt = &attribute[..16];
    let mut md5_in = Vec::with_capacity(session_key.len() + 16);
    md5_in.extend_from_slice(session_key);
    md5_in.extend_from_slice(salt);
    let rc4_key = md5(&md5_in);
    let plain = rc4(&rc4_key, &attribute[16..]);
    if plain.len() < 4 {
        return None;
    }
    Some(plain[4..].to_vec())
}


pub fn remove_des_layer(crypted_hash: &[u8], rid: u32) -> Option<[u8; 16]> {
    if crypted_hash.len() < 16 {
        return None;
    }
    let (key1, key2) = derive_des_keys(rid);
    let mut out = [0u8; 16];
    let cipher1 = Des::new_from_slice(&key1).ok()?;
    let mut b1 = GenericArray::from(*<&[u8; 8]>::try_from(&crypted_hash[..8]).ok()?);
    cipher1.decrypt_block(&mut b1);
    out[..8].copy_from_slice(b1.as_slice());
    let cipher2 = Des::new_from_slice(&key2).ok()?;
    let mut b2 = GenericArray::from(*<&[u8; 8]>::try_from(&crypted_hash[8..16]).ok()?);
    cipher2.decrypt_block(&mut b2);
    out[8..].copy_from_slice(b2.as_slice());
    Some(out)
}

fn derive_des_keys(rid: u32) -> ([u8; 8], [u8; 8]) {
    let r = rid.to_le_bytes();
    let key1 = transform_des_key([r[0], r[1], r[2], r[3], r[0], r[1], r[2]]);
    let key2 = transform_des_key([r[3], r[0], r[1], r[2], r[3], r[0], r[1]]);
    (key1, key2)
}

fn transform_des_key(key7: [u8; 7]) -> [u8; 8] {
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


pub fn remove_rc4_pek_layer(rc4_plain: &[u8], pek_list: &[[u8; 16]]) -> Option<Vec<u8>> {
    if rc4_plain.is_empty() {
        return None;
    }
    let pek_index = rc4_plain[0] as usize;
    if pek_index == 0 {
        return Some(rc4_plain[1..].to_vec());
    }
    if pek_index > pek_list.len() {
        return None;
    }
    let body = &rc4_plain[1..];
    if body.len() < 16 {
        return None;
    }
    let pek = pek_list[pek_index - 1];
    let mut md5_in = Vec::with_capacity(32);
    md5_in.extend_from_slice(&pek);
    md5_in.extend_from_slice(&body[8..16]);
    let rc4_key = md5(&md5_in);
    let mut head = rc4(&rc4_key, &body[..8]);
    let mut out = Vec::with_capacity(body.len());
    out.append(&mut head);
    out.extend_from_slice(&body[8..]);
    Some(out)
}


pub fn decrypt_pek_entry(session_key: &[u8], encrypted_pek: &[u8]) -> Option<[u8; 16]> {
    let plain = decrypt_drs_attribute(session_key, encrypted_pek)?;
    if plain.len() < 16 {
        return None;
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&plain[..16]);
    Some(key)
}


pub fn decrypt_nt_hash_from_replication(
    session_key: &[u8],
    rid: u32,
    encrypted_attr: &[u8],
    pek_list: &[[u8; 16]],
) -> Option<[u8; 16]> {
    let rc4_plain = decrypt_drs_attribute(session_key, encrypted_attr)?;
    let after_pek = if pek_list.is_empty() {
        rc4_plain
    } else {
        remove_rc4_pek_layer(&rc4_plain, pek_list)?
    };
    remove_des_layer(&after_pek, rid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn des_layer_roundtrip_length() {
        let rid = 500;
        let fake = [0xAB; 16];
        let keys = derive_des_keys(rid);
        assert_eq!(keys.0.len(), 8);
        let dec = remove_des_layer(&fake, rid);
        assert!(dec.is_some());
    }

    #[test]
    fn pek_layer_index_zero_passthrough() {
        let plain = remove_rc4_pek_layer(&[0, 1, 2, 3, 4, 5, 6, 7, 8], &[]).unwrap();
        assert_eq!(plain, &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
