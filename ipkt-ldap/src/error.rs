pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] ipkt_core::Error),
    #[error("ber error: {0}")]
    Ber(String),

    #[error("transport error: {0}")]
    Transport(String),
}
