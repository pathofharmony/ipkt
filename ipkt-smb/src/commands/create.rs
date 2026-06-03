use ipkt_core::text::encode_utf16le;
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FileAttributes(pub u32);

impl FileAttributes {
    
    pub const NORMAL: Self = Self(0x80);
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateRequest {
    
    pub desired_access: u32,
    
    pub file_attributes: FileAttributes,
    
    pub name: String,
}

impl CreateRequest {
    
    #[must_use]
    pub fn open(name: impl Into<String>) -> Self {
        Self {
            desired_access: 0x0012_0089, 
            file_attributes: FileAttributes::NORMAL,
            name: name.into(),
        }
    }
}

impl Pack for CreateRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let name_bytes = encode_utf16le(&self.name);
        let offset = 64 + 56;
        writer
            .write_u16_le(57)
            .write_u8(0) 
            .write_u8(0)
            .write_u32_le(self.desired_access)
            .write_u32_le(0) 
            .write_u32_le(self.file_attributes.0)
            .write_u32_le(0) 
            .write_u32_le(1) 
            .write_u32_le(0) 
            .write_u16_le(offset as u16)
            .write_u16_le(name_bytes.len() as u16)
            .write_u32_le(0) 
            .write_u32_le(0);
        writer.write_bytes(&name_bytes);
    }
}

impl Unpack for CreateRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 57 {
            return Err(ipkt_core::Error::invalid_data(
                "CREATE request",
                format!("structure size {structure_size}"),
            ));
        }
        let _ = reader.read_bytes(1 + 1 + 4 + 4 + 4 + 4 + 4 + 4)?;
        let offset = reader.read_u16_le()? as usize;
        let length = reader.read_u16_le()? as usize;
        let _ = reader.read_bytes(4 + 4)?;
        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(offset)?;
        let name = ipkt_core::text::decode_utf16le(at.read_bytes(length)?)?;
        Ok(Self {
            desired_access: 0,
            file_attributes: FileAttributes::NORMAL,
            name,
        })
    }
}

/// CREATE response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateResponse {
    /// File id (persistent + volatile).
    pub file_id: [u8; 16],
}

impl Pack for CreateResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(89)
            .write_u8(0)
            .write_u8(0)
            .write_u32_le(0)
            .write_u64_le(0)
            .write_u64_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_bytes(&self.file_id)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u32_le(0);
    }
}

impl Unpack for CreateResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 89 {
            return Err(ipkt_core::Error::invalid_data(
                "CREATE response",
                format!("structure size {structure_size}"),
            ));
        }
        let _ = reader.read_bytes(1 + 1 + 4 + 8 + 8 + 4 + 4)?;
        let file_id = reader.read_array::<16>()?;
        Ok(Self { file_id })
    }
}
