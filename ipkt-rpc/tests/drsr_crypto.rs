#![allow(missing_docs)]
use ipkt_rpc::{decrypt_drs_attribute, remove_des_layer};

#[test]
fn drs_attribute_decrypt_requires_minimum_length() {
    assert!(decrypt_drs_attribute(&[0x11; 16], &[0u8; 10]).is_none());
}

#[test]
fn des_layer_produces_16_bytes() {
    let key = [0x42u8; 16];
    let out = remove_des_layer(&key, 1000).unwrap();
    assert_eq!(out.len(), 16);
}
