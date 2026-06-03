use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRequest {
    pub file_id: [u8; 16],

    pub offset: u64,

    pub data: Vec<u8>,
}

impl Pack for WriteRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(49)
            .write_u16_le(0)
            .write_u32_le(self.data.len() as u32)
            .write_u64_le(self.offset)
            .write_bytes(&self.file_id)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u16_le(0)
            .write_u16_le(0);
    }
}

impl Unpack for WriteRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 49 {
            return Err(ipkt_core::Error::invalid_data(
                "WRITE request",
                format!("structure size {structure_size}"),
            ));
        }
        let data_offset = reader.read_u16_le()? as usize;
        let length = reader.read_u32_le()? as usize;
        let offset = reader.read_u64_le()?;
        let file_id = reader.read_array::<16>()?;
        let _ = reader.read_bytes(4 + 4 + 2 + 2)?;
        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(data_offset)?;
        let data = at.read_bytes(length)?.to_vec();
        Ok(Self {
            file_id,
            offset,
            data,
        })
    }
}

/// WRITE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteResponse {
    /// Count of bytes written.
    pub count: u32,
}

impl Pack for WriteResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(17)
            .write_u16_le(0)
            .write_u32_le(self.count)
            .write_u32_le(0)
            .write_u32_le(0);
    }
}

impl Unpack for WriteResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 17 {
            return Err(ipkt_core::Error::invalid_data(
                "WRITE response",
                format!("structure size {structure_size}"),
            ));
        }
        let _ = reader.read_u16_le()?;
        let count = reader.read_u32_le()?;
        Ok(Self { count })
    }
}
