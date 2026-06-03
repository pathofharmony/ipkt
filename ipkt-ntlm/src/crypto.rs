use des::cipher::generic_array::GenericArray;
use des::cipher::{BlockEncrypt, KeyInit};
use des::Des;
use hmac::{Hmac, Mac};
use md4::Md4;
use md5::{Digest, Md5};

use ipkt_core::text::encode_utf16le;


pub type Challenge = [u8; 8];



const LM_MAGIC: [u8; 8] = *b"KGS!@#$%";









#[must_use]
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize().into()
}


#[must_use]
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}



#[must_use]
pub fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    
    
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}






#[must_use]
pub fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    
    
    let mut state: [u8; 256] = core::array::from_fn(|i| i as u8);
    let mut j: u8 = 0;
    for i in 0..256usize {
        j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
        state.swap(i, j as usize);
    }

    let mut out = Vec::with_capacity(data.len());
    let (mut a, mut b): (u8, u8) = (0, 0);
    for &byte in data {
        a = a.wrapping_add(1);
        b = b.wrapping_add(state[a as usize]);
        state.swap(a as usize, b as usize);
        let k = state[state[a as usize].wrapping_add(state[b as usize]) as usize];
        out.push(byte ^ k);
    }
    out
}








fn des_key_from_56(key7: &[u8; 7]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = key7[0];
    out[1] = (key7[0] << 7) | (key7[1] >> 1);
    out[2] = (key7[1] << 6) | (key7[2] >> 2);
    out[3] = (key7[2] << 5) | (key7[3] >> 3);
    out[4] = (key7[3] << 4) | (key7[4] >> 4);
    out[5] = (key7[4] << 3) | (key7[5] >> 5);
    out[6] = (key7[5] << 2) | (key7[6] >> 6);
    out[7] = key7[6] << 1;
    out
}



fn des_encrypt(key56: &[u8; 7], block: &[u8; 8]) -> [u8; 8] {
    let key = des_key_from_56(key56);
    let cipher = Des::new(GenericArray::from_slice(&key));
    let mut buf = *GenericArray::from_slice(block);
    cipher.encrypt_block(&mut buf);
    buf.into()
}




#[must_use]
pub fn desl(key: &[u8; 16], data: &Challenge) -> [u8; 24] {
    let mut padded = [0u8; 21];
    padded[..16].copy_from_slice(key);

    let mut out = [0u8; 24];
    for chunk in 0..3 {
        let mut key7 = [0u8; 7];
        key7.copy_from_slice(&padded[chunk * 7..chunk * 7 + 7]);
        let block = des_encrypt(&key7, data);
        out[chunk * 8..chunk * 8 + 8].copy_from_slice(&block);
    }
    out
}


















#[must_use]
pub fn ntowf_v1(password: &str) -> [u8; 16] {
    md4(&encode_utf16le(password))
}







#[must_use]
pub fn lmowf_v1(password: &str) -> [u8; 16] {
    let upper = password.to_uppercase();
    let mut oem = [0u8; 14];
    for (slot, ch) in oem
        .iter_mut()
        .zip(upper.bytes().chain(core::iter::repeat(0)))
    {
        
        *slot = if ch < 0x80 { ch } else { b'?' };
    }

    let mut out = [0u8; 16];
    let left: [u8; 7] = oem[..7].try_into().expect("7-byte half");
    let right: [u8; 7] = oem[7..].try_into().expect("7-byte half");
    out[..8].copy_from_slice(&des_encrypt(&left, &LM_MAGIC));
    out[8..].copy_from_slice(&des_encrypt(&right, &LM_MAGIC));
    out
}






#[must_use]
pub fn ntowf_v2_from_nt_hash(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let identity = format!("{}{}", user.to_uppercase(), domain);
    hmac_md5(nt_hash, &encode_utf16le(&identity))
}






#[must_use]
pub fn ntowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    ntowf_v2_from_nt_hash(&ntowf_v1(password), user, domain)
}


#[must_use]
pub fn lmowf_v2(password: &str, user: &str, domain: &str) -> [u8; 16] {
    ntowf_v2(password, user, domain)
}






#[must_use]
pub fn ntlm_v1_response(nt_hash: &[u8; 16], server_challenge: &Challenge) -> [u8; 24] {
    desl(nt_hash, server_challenge)
}


#[must_use]
pub fn lm_v1_response(lm_hash: &[u8; 16], server_challenge: &Challenge) -> [u8; 24] {
    desl(lm_hash, server_challenge)
}







#[must_use]
pub fn ntlm_v1_extended_response(
    nt_hash: &[u8; 16],
    server_challenge: &Challenge,
    client_challenge: &Challenge,
) -> ([u8; 24], [u8; 24]) {
    let mut lm_response = [0u8; 24];
    lm_response[..8].copy_from_slice(client_challenge);

    let mut combined = [0u8; 16];
    combined[..8].copy_from_slice(server_challenge);
    combined[8..].copy_from_slice(client_challenge);
    let digest = md5(&combined);
    let mut session_hash = [0u8; 8];
    session_hash.copy_from_slice(&digest[..8]);

    let nt_response = desl(nt_hash, &session_hash);
    (lm_response, nt_response)
}


#[must_use]
pub fn ntlm_v1_session_base_key(nt_hash: &[u8; 16]) -> [u8; 16] {
    md4(nt_hash)
}






#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ntlmv2Response {
    
    proof: [u8; 16],
    
    
    temp: Vec<u8>,
    
    session_base_key: [u8; 16],
}

impl Ntlmv2Response {
    
    #[must_use]
    pub fn proof(&self) -> [u8; 16] {
        self.proof
    }

    
    #[must_use]
    pub fn session_base_key(&self) -> [u8; 16] {
        self.session_base_key
    }

    
    
    #[must_use]
    pub fn nt_challenge_response(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.temp.len());
        out.extend_from_slice(&self.proof);
        out.extend_from_slice(&self.temp);
        out
    }
}







#[must_use]
fn ntlm_v2_temp(timestamp: u64, client_challenge: &Challenge, target_info: &[u8]) -> Vec<u8> {
    let mut temp = Vec::with_capacity(28 + target_info.len() + 4);
    temp.push(0x01); 
    temp.push(0x01); 
    temp.extend_from_slice(&[0u8; 6]); 
    temp.extend_from_slice(&timestamp.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0u8; 4]); 
    temp.extend_from_slice(target_info);
    temp.extend_from_slice(&[0u8; 4]); 
    temp
}









#[must_use]
pub fn ntlm_v2_response(
    response_key: &[u8; 16],
    server_challenge: &Challenge,
    client_challenge: &Challenge,
    timestamp: u64,
    target_info: &[u8],
) -> Ntlmv2Response {
    let temp = ntlm_v2_temp(timestamp, client_challenge, target_info);

    
    let mut proof_input = Vec::with_capacity(8 + temp.len());
    proof_input.extend_from_slice(server_challenge);
    proof_input.extend_from_slice(&temp);
    let proof = hmac_md5(response_key, &proof_input);

    
    let session_base_key = hmac_md5(response_key, &proof);

    Ntlmv2Response {
        proof,
        temp,
        session_base_key,
    }
}



#[must_use]
pub fn lm_v2_response(
    response_key: &[u8; 16],
    server_challenge: &Challenge,
    client_challenge: &Challenge,
) -> [u8; 24] {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(server_challenge);
    input[8..].copy_from_slice(client_challenge);
    let hmac = hmac_md5(response_key, &input);

    let mut out = [0u8; 24];
    out[..16].copy_from_slice(&hmac);
    out[16..].copy_from_slice(client_challenge);
    out
}






#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum SessionKeyMode {
    
    Client,
    
    Server,
}



#[must_use]
pub fn key_exchange_key_ntlmv2(session_base_key: &[u8; 16]) -> [u8; 16] {
    *session_base_key
}



#[must_use]
pub fn key_exchange_key_ntlmv1_extended(
    session_base_key: &[u8; 16],
    server_challenge: &Challenge,
    lm_challenge_response: &[u8],
) -> [u8; 16] {
    let mut data = [0u8; 8];
    data.copy_from_slice(server_challenge);
    let mut input = Vec::with_capacity(16);
    input.extend_from_slice(&data);
    input.extend_from_slice(&lm_challenge_response[..8]);
    hmac_md5(session_base_key, &input)
}


#[must_use]
pub fn key_exchange_key_ntlmv1(session_base_key: &[u8; 16]) -> [u8; 16] {
    *session_base_key
}





#[must_use]
pub fn sign_key(
    flags: crate::NegotiateFlags,
    exported_session_key: &[u8; 16],
    mode: SessionKeyMode,
) -> Option<[u8; 16]> {
    if !flags.contains(crate::NegotiateFlags::NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        return None;
    }
    let magic = match mode {
        SessionKeyMode::Client => b"session key to client-to-server signing key magic constant\0",
        SessionKeyMode::Server => b"session key to server-to-client signing key magic constant\0",
    };
    let mut input = Vec::with_capacity(exported_session_key.len() + magic.len());
    input.extend_from_slice(exported_session_key);
    input.extend_from_slice(magic);
    Some(md5(&input))
}


#[must_use]
pub fn seal_key(
    flags: crate::NegotiateFlags,
    exported_session_key: &[u8; 16],
    mode: SessionKeyMode,
) -> [u8; 16] {
    if flags.contains(crate::NegotiateFlags::NEGOTIATE_EXTENDED_SESSIONSECURITY) {
        let (material, len) = if flags.contains(crate::NegotiateFlags::NEGOTIATE_128) {
            (exported_session_key.as_slice(), 16)
        } else if flags.contains(crate::NegotiateFlags::NEGOTIATE_56) {
            (&exported_session_key[..7], 7)
        } else {
            (&exported_session_key[..5], 5)
        };
        let magic = match mode {
            SessionKeyMode::Client => {
                b"session key to client-to-server sealing key magic constant\0"
            }
            SessionKeyMode::Server => {
                b"session key to server-to-client sealing key magic constant\0"
            }
        };
        let mut input = Vec::with_capacity(len + magic.len());
        input.extend_from_slice(&material[..len]);
        input.extend_from_slice(magic);
        return md5(&input);
    }

    
    if flags.contains(crate::NegotiateFlags::NEGOTIATE_56) {
        let mut key = [0u8; 16];
        key[..7].copy_from_slice(&exported_session_key[..7]);
        key[7] = 0xa0;
        key
    } else {
        let mut key = [0u8; 16];
        key[..5].copy_from_slice(&exported_session_key[..5]);
        key[5] = 0xe5;
        key[6] = 0x38;
        key[7] = 0xb0;
        key
    }
}




#[must_use]
pub fn seal_exported_session_key(
    key_exchange_key: &[u8; 16],
    exported_session_key: &[u8; 16],
) -> [u8; 16] {
    let wrapped = rc4(key_exchange_key, exported_session_key);
    let mut out = [0u8; 16];
    out.copy_from_slice(&wrapped);
    out
}




#[must_use]
pub fn mic(
    exported_session_key: &[u8; 16],
    negotiate_message: &[u8],
    challenge_message: &[u8],
    authenticate_message: &[u8],
) -> [u8; 16] {
    let mut input = Vec::with_capacity(
        negotiate_message.len() + challenge_message.len() + authenticate_message.len(),
    );
    input.extend_from_slice(negotiate_message);
    input.extend_from_slice(challenge_message);
    input.extend_from_slice(authenticate_message);
    hmac_md5(exported_session_key, &input)
}






#[must_use]
pub fn channel_bindings_hash(cert_hash: &[u8]) -> [u8; 16] {
    const PREFIX: &[u8] = b"tls-server-end-point:";
    let tls_len = (PREFIX.len() + cert_hash.len()) as u32;
    let mut channel = Vec::with_capacity(24 + PREFIX.len() + cert_hash.len());
    channel.extend_from_slice(&0u32.to_le_bytes());
    channel.extend_from_slice(&0u32.to_le_bytes());
    channel.extend_from_slice(&tls_len.to_le_bytes());
    channel.extend_from_slice(&0u32.to_le_bytes());
    channel.extend_from_slice(PREFIX);
    channel.extend_from_slice(cert_hash);
    md5(&channel)
}
