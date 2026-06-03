use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseRequest {
    pub file_id: [u8; 16],
}

impl Pack for CloseRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(24)
            .write_u16_le(1)
            .write_u32_le(0)
            .write_bytes(&self.file_id);
    }
}

impl Unpack for CloseRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 24 {
            return Err(ipkt_core::Error::invalid_data(
                "CLOSE request",
                format!("structure size {structure_size}"),
            ));
        }
        let _ = reader.read_bytes(2 + 4)?;
        let file_id = reader.read_array::<16>()?;
        Ok(Self { file_id })
    }
}

/// CLOSE response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CloseResponse;

impl Pack for CloseResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer.write_u16_le(60).write_u16_le(0).write_u32_le(0);
        writer.write_bytes(&[0u8; 52]);
    }
}

impl Unpack for CloseResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 60 {
            return Err(ipkt_core::Error::invalid_data(
                "CLOSE response",
                format!("structure size {structure_size}"),
            ));
        }
        let remaining = 2 + 4 + 52;
        let _ = reader.read_bytes(remaining)?;
        Ok(Self)
    }
}
