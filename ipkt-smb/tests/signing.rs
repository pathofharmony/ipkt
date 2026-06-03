use ipkt_smb::{compute_signature, sign_message, verify_signature, zero_signature};

#[test]
fn sign_and_verify_round_trip() {
    let key = [0x11u8; 16];
    let mut msg = vec![0u8; 128];
    msg[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
    msg[8..10].copy_from_slice(&0x0001u16.to_le_bytes());
    sign_message(&key, &mut msg);
    assert!(verify_signature(&key, &msg));
    let mut tampered = msg.clone();
    tampered[100] ^= 0xFF;
    assert!(!verify_signature(&key, &tampered));
}

#[test]
fn zero_signature_clears_field() {
    let mut msg = vec![0xABu8; 64];
    sign_message(&[0x22; 16], &mut msg);
    assert!(msg[48..64].iter().any(|&b| b != 0));
    zero_signature(&mut msg);
    assert!(msg[48..64].iter().all(|&b| b == 0));
}

#[test]
fn compute_signature_is_deterministic() {
    let key = [0x33u8; 16];
    let mut msg = vec![0u8; 80];
    zero_signature(&mut msg);
    let a = compute_signature(&key, &msg);
    let b = compute_signature(&key, &msg);
    assert_eq!(a, b);
}
