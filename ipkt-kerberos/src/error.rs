pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Codec(#[from] ipkt_core::Error),

    #[error("der error: {0}")]
    Der(String),

    #[error("invalid kerberos message: {0}")]
    InvalidMessage(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("KDC: {0}")]
    Kdc(Box<crate::krb_error::KrbError>),
}

impl From<crate::krb_error::KrbError> for Error {
    fn from(value: crate::krb_error::KrbError) -> Self {
        Self::Kdc(Box::new(value))
    }
}
