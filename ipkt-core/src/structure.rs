use crate::bytes::{ByteReader, ByteWriter};
use crate::error::Result;

pub trait Pack {
    fn pack_into(&self, writer: &mut ByteWriter);

    #[must_use]
    fn pack(&self) -> Vec<u8> {
        let mut writer = ByteWriter::new();
        self.pack_into(&mut writer);
        writer.into_vec()
    }
}

pub trait Unpack: Sized {
    fn unpack_from(reader: &mut ByteReader<'_>) -> Result<Self>;

    /// Parses a value of `Self` from a complete byte slice.
    ///
    /// This is a provided method that constructs a [`ByteReader`] and calls
    /// [`unpack_from`](Unpack::unpack_from). Trailing bytes after the parsed
    /// value are ignored, which matches how variable-length network messages
    /// are framed.
    ///
    /// # Errors
    ///
    /// Returns an error if the input is truncated or contains values that are
    /// invalid for `Self`.
    fn unpack(bytes: &[u8]) -> Result<Self> {
        let mut reader = ByteReader::new(bytes);
        Self::unpack_from(&mut reader)
    }
}

/// Marker for types that can be both packed and unpacked.
///
/// This trait is blanket-implemented for every `T: Pack + Unpack`, so it can
/// be used as a single convenient bound (e.g. `fn round_trip<T: Structure>`).
pub trait Structure: Pack + Unpack {}

impl<T: Pack + Unpack> Structure for T {}
