use bitflags::bitflags;
use ipkt_core::text::encode_utf16le;
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

bitflags! {

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct TreeConnectFlags: u16 {

        const CLUSTER_RECONNECT = 0x0001;

        const REDIRECT_TO_OWNER = 0x0002;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectRequest {
    pub flags: TreeConnectFlags,

    pub path: String,
}

impl TreeConnectRequest {
    #[must_use]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            flags: TreeConnectFlags::empty(),
            path: path.into(),
        }
    }
}

impl Pack for TreeConnectRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let path_bytes = encode_utf16le(&self.path);
        let offset = 64 + 8;
        writer
            .write_u16_le(9)
            .write_u16_le(self.flags.bits())
            .write_u16_le(offset as u16)
            .write_u16_le(path_bytes.len() as u16);
        writer.write_bytes(&path_bytes);
    }
}

impl Unpack for TreeConnectRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 9 {
            return Err(ipkt_core::Error::invalid_data(
                "TREE_CONNECT request",
                format!("structure size {structure_size}"),
            ));
        }
        let flags = TreeConnectFlags::from_bits_retain(reader.read_u16_le()?);
        let offset = reader.read_u16_le()? as usize;
        let length = reader.read_u16_le()? as usize;
        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(offset)?;
        let raw = at.read_bytes(length)?;
        let path = ipkt_core::text::decode_utf16le(raw)?;
        Ok(Self { flags, path })
    }
}

/// TREE_CONNECT response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectResponse {
    /// Share type flags from server.
    pub share_type: u8,
}

impl Pack for TreeConnectResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(16)
            .write_u8(self.share_type)
            .write_u8(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0);
    }
}

impl Unpack for TreeConnectResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 16 {
            return Err(ipkt_core::Error::invalid_data(
                "TREE_CONNECT response",
                format!("structure size {structure_size}"),
            ));
        }
        let share_type = reader.read_u8()?;
        let _ = reader.read_bytes(1 + 4 + 4 + 4 + 4)?;
        Ok(Self { share_type })
    }
}
