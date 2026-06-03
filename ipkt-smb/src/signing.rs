use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::header::Smb2Flags;

type HmacSha256 = Hmac<Sha256>;

pub const SMB2_SIGNATURE_LEN: usize = 16;

pub const SMB2_SIGNATURE_OFFSET: usize = 48;

#[must_use]
pub fn compute_signature(signing_key: &[u8], message: &[u8]) -> [u8; SMB2_SIGNATURE_LEN] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(signing_key).expect("HMAC-SHA256 accepts any key len");
    mac.update(message);
    let full = mac.finalize().into_bytes();
    let mut sig = [0u8; SMB2_SIGNATURE_LEN];
    sig.copy_from_slice(&full[..SMB2_SIGNATURE_LEN]);
    sig
}

pub fn zero_signature(message: &mut [u8]) {
    if message.len() >= SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN {
        message[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN].fill(0);
    }
}

pub fn sign_message(signing_key: &[u8], message: &mut [u8]) {
    zero_signature(message);
    let sig = compute_signature(signing_key, message);
    message[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN]
        .copy_from_slice(&sig);
}

#[must_use]
pub fn header_wants_signing(header_bytes: &[u8]) -> bool {
    if header_bytes.len() < 16 {
        return false;
    }

    let flags = u32::from_le_bytes(header_bytes[12..16].try_into().unwrap_or([0; 4]));
    Smb2Flags::from_bits_retain(flags).contains(Smb2Flags::SIGNED)
}

#[must_use]
pub fn verify_signature(signing_key: &[u8], message: &[u8]) -> bool {
    if message.len() < SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN {
        return false;
    }
    let mut stored = [0u8; SMB2_SIGNATURE_LEN];
    stored.copy_from_slice(
        &message[SMB2_SIGNATURE_OFFSET..SMB2_SIGNATURE_OFFSET + SMB2_SIGNATURE_LEN],
    );
    let mut copy = message.to_vec();
    zero_signature(&mut copy);
    stored == compute_signature(signing_key, &copy)
}

pub fn set_signed_flag(message: &mut [u8]) {
    if message.len() >= 16 {
        let flags = u32::from_le_bytes(message[12..16].try_into().unwrap_or([0; 4]));
        let signed = flags | Smb2Flags::SIGNED.bits();
        message[12..16].copy_from_slice(&signed.to_le_bytes());
    }
}
