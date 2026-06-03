use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequest {
    
    pub file_id: [u8; 16],
    
    pub offset: u64,
    
    pub length: u32,
}

impl Pack for ReadRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(49)
            .write_u8(0)
            .write_u8(0)
            .write_u32_le(self.length)
            .write_u64_le(self.offset)
            .write_bytes(&self.file_id)
            .write_u32_le(0) 
            .write_u32_le(0) 
            .write_u32_le(0)
            .write_u16_le(0)
            .write_u16_le(0);
    }
}

impl Unpack for ReadRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 49 {
            return Err(ipkt_core::Error::invalid_data(
                "READ request",
                format!("structure size {structure_size}"),
            ));
        }
        let _ = reader.read_bytes(2)?;
        let length = reader.read_u32_le()?;
        let offset = reader.read_u64_le()?;
        let file_id = reader.read_array::<16>()?;
        Ok(Self {
            file_id,
            offset,
            length,
        })
    }
}

/// READ response (data in packet payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadResponse {
    /// Data offset from start of SMB2 header.
    pub data_offset: u8,
    /// Length of data in payload.
    pub data_length: u32,
}

impl Unpack for ReadResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 17 {
            return Err(ipkt_core::Error::invalid_data(
                "READ response",
                format!("structure size {structure_size}"),
            ));
        }
        let data_offset = reader.read_u8()?;
        let _ = reader.read_u8()?;
        let data_length = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        Ok(Self {
            data_offset,
            data_length,
        })
    }
}

impl Pack for ReadResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(17)
            .write_u8(self.data_offset)
            .write_u8(0)
            .write_u32_le(self.data_length)
            .write_u32_le(0)
            .write_u32_le(0);
    }
}
