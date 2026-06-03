pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] ipkt_core::Error),

    #[error("invalid NTLMSSP signature: expected {expected:02x?}, found {found:02x?}")]
    InvalidSignature { expected: [u8; 8], found: [u8; 8] },

    #[error("unexpected NTLM message type: expected {expected}, found {found}")]
    UnexpectedMessageType { expected: u32, found: u32 },

    #[error("malformed AV_PAIR list: {0}")]
    MalformedAvPairs(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// Message Integrity Code verification failed — the message was tampered
    /// with or the session keys do not match.
    #[error("MIC verification failed")]
    MicMismatch,
}
