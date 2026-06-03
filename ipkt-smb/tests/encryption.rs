#![allow(missing_docs)]
use ipkt_smb::{decrypt_message, derive_encryption_key, encrypt_message, preauth_hash_sha512};

#[test]
fn smb3_transform_roundtrip() {
    let key = derive_encryption_key(&[0x42; 16]);
    let plain = vec![0xFE, b'S', b'M', b'B', 0, 0, 0, 0, 1, 2, 3];
    let enc = encrypt_message(&key, 0x99, &plain).unwrap();
    let dec = decrypt_message(&key, &enc).unwrap();
    assert_eq!(dec, plain);
}

#[test]
fn preauth_sha512_is_deterministic() {
    let zero = [0u8; 64];
    let h1 = preauth_hash_sha512(&zero, b"test");
    let h2 = preauth_hash_sha512(&zero, b"test");
    assert_eq!(h1, h2);
    assert_ne!(h1, preauth_hash_sha512(&zero, b"other"));
}
