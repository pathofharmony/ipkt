use ipkt_ntlm::crypto::rc4;


#[must_use]
pub fn seal_payload(sealing_key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    rc4(sealing_key, data)
}


#[must_use]
pub fn unseal_payload(sealing_key: &[u8; 16], data: &[u8]) -> Vec<u8> {
    rc4(sealing_key, data)
}
