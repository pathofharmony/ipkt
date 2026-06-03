#![allow(missing_docs)]

mod client;
mod commands;
pub mod encryption;
mod error;
mod header;
mod packet;
mod pipe;
mod sealing;
mod session;
mod session_keys;
mod signing;

#[cfg(feature = "rpc")]
mod rpc_transport;

pub use client::SmbClient;
pub use commands::*;
pub use encryption::{
    decrypt_message, derive_encryption_key, encrypt_message, encryption_cap_aes128_gcm,
    preauth_hash_sha512, preauth_integrity_cap_sha512, SMB2_ENCRYPTION_AES128_GCM,
    SMB2_TRANSFORM_HEADER_SIZE,
};
pub use error::{Error, Result};
pub use header::{Smb2Command, Smb2Flags, Smb2Header, SMB2_HEADER_SIZE, SMB2_PROTOCOL_ID};
pub use packet::{NetbiosSessionMessage, Smb2Packet};
pub use pipe::{ipc_unc, paths as pipe_paths, pipe_create_path};
pub use sealing::{seal_payload, unseal_payload};
pub use session::{parse_ntlm_challenge_from_packet, NtlmSessionSetup};
pub use session_keys::SmbSessionKeys;
pub use signing::{
    compute_signature, sign_message, verify_signature, zero_signature, SMB2_SIGNATURE_LEN,
    SMB2_SIGNATURE_OFFSET,
};

#[cfg(feature = "rpc")]
pub use rpc_transport::SmbRpcTransport;
