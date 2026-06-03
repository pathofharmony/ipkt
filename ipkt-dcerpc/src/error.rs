pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] ipkt_core::Error),
    #[error("invalid rpc pdu: {0}")]
    InvalidPdu(String),
}
