pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] ipkt_core::Error),

    #[error("ntlm error: {0}")]
    Ntlm(String),

    #[error(transparent)]
    NtlmCrate(#[from] ipkt_ntlm::Error),

    #[error("smb status error: {status:#010x} on command {command}")]
    StatusError { status: u32, command: u16 },

    #[error("framing error: {0}")]
    Framing(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("signing error: {0}")]
    Signing(String),
}
