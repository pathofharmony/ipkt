use core::fmt;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("unexpected end of buffer: needed {needed} byte(s) but only {available} remained")]
    UnexpectedEof { needed: usize, available: usize },

    #[error(
        "offset {offset} with length {length} is out of bounds for a buffer of {total} byte(s)"
    )]
    OutOfBounds {
        offset: usize,

        length: usize,

        total: usize,
    },

    #[error("invalid data while parsing {context}: {message}")]
    InvalidData {
        context: &'static str,
        /// Details about why the value was rejected.
        message: String,
    },

    /// A fixed-size field did not contain the expected magic/signature bytes.
    #[error("invalid signature for {context}: expected {expected:02x?}, found {found:02x?}")]
    InvalidSignature {
        /// What structure the signature belongs to.
        context: &'static str,

        expected: Vec<u8>,

        found: Vec<u8>,
    },
}

impl Error {
    #[must_use]
    pub fn invalid_data(context: &'static str, message: impl fmt::Display) -> Self {
        Self::InvalidData {
            context,
            message: message.to_string(),
        }
    }
}
