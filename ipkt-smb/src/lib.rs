#![allow(missing_docs)] 

















mod client;
mod commands;
mod error;
mod header;
mod packet;
mod pipe;
mod session;
mod session_keys;
pub mod encryption;
mod sealing;
mod signing;

#[cfg(feature = "rpc")]
mod rpc_transport;

pub use client::SmbClient;
pub use commands::*;
pub use error::{Error, Result};
pub use header::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_PROTOCOL_ID};
pub use packet::{NetbiosSessionMessage, Smb2Packet};
pub use pipe::{ipc_unc, pipe_create_path, paths as pipe_paths};
pub use session::{parse_ntlm_challenge_from_packet, NtlmSessionSetup};
pub use session_keys::SmbSessionKeys;
pub use encryption::{
    decrypt_message, encrypt_message, encryption_cap_aes128_gcm, derive_encryption_key,
    preauth_hash_sha512, preauth_integrity_cap_sha512,
    SMB2_ENCRYPTION_AES128_GCM, SMB2_TRANSFORM_HEADER_SIZE,
};
pub use sealing::{seal_payload, unseal_payload};
pub use signing::{
    compute_signature, sign_message, verify_signature, zero_signature, SMB2_SIGNATURE_LEN,
    SMB2_SIGNATURE_OFFSET,
};

#[cfg(feature = "rpc")]
pub use rpc_transport::SmbRpcTransport;
