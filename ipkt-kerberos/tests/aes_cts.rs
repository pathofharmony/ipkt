#![allow(missing_docs)]
use ipkt_kerberos::{
    aes_string2key as string2key_aes256, decrypt_aes256, encrypt_aes256, KEY_USAGE_PA_ENC_TIMESTAMP,
};

#[test]
fn aes256_cts_roundtrip() {
    let key = string2key_aes256("password", b"EXAMPLE.COMuser", 4096).unwrap();
    let confounder = [0x11u8; 16];
    let plain = b"PA-ENC-TIMESTAMP test";
    let cipher = encrypt_aes256(&key, KEY_USAGE_PA_ENC_TIMESTAMP, plain, &confounder).unwrap();
    let dec = decrypt_aes256(&key, KEY_USAGE_PA_ENC_TIMESTAMP, &cipher).unwrap();
    assert_eq!(dec, plain);
}
