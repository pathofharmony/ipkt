#![allow(missing_docs)]
use ipkt_smb::{seal_payload, unseal_payload};

#[test]
fn seal_unseal_round_trip() {
    let key = [0x55u8; 16];
    let plain = b"hello pipe";
    let sealed = seal_payload(&key, plain);
    let back = unseal_payload(&key, &sealed);
    assert_eq!(back, plain);
}
