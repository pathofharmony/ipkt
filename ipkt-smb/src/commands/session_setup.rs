use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupRequest {
    pub flags: u8,

    pub security_buffer: Vec<u8>,
}

impl SessionSetupRequest {
    #[must_use]
    pub fn with_security_buffer(buffer: Vec<u8>) -> Self {
        Self {
            flags: 0,
            security_buffer: buffer,
        }
    }
}

impl Pack for SessionSetupRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let offset = 64 + 24;
        writer
            .write_u16_le(25)
            .write_u8(self.flags)
            .write_u8(0)
            .write_u32_le(0)
            .write_u32_le(0)
            .write_u16_le(0)
            .write_u16_le(0)
            .write_u64_le(0);
        let off = writer.len();
        writer.patch(off - 12, &(offset as u16).to_le_bytes());
        writer.patch(off - 10, &(self.security_buffer.len() as u16).to_le_bytes());
        writer.write_bytes(&self.security_buffer);
    }
}

impl Unpack for SessionSetupRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 25 {
            return Err(ipkt_core::Error::invalid_data(
                "SESSION_SETUP request",
                format!("structure size {structure_size}"),
            ));
        }
        let flags = reader.read_u8()?;
        let _ = reader.read_u8()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        let sec_offset = reader.read_u16_le()? as usize;
        let sec_len = reader.read_u16_le()? as usize;
        let _ = reader.read_u64_le()?;
        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(sec_offset)?;
        let security_buffer = at.read_bytes(sec_len)?.to_vec();
        Ok(Self {
            flags,
            security_buffer,
        })
    }
}

/// SMB2 SESSION_SETUP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    /// Established session id.
    pub session_id: u64,
    /// Server security buffer (NTLM challenge, etc.).
    pub security_buffer: Vec<u8>,
}

impl Unpack for SessionSetupResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 9 {
            return Err(ipkt_core::Error::invalid_data(
                "SESSION_SETUP response",
                format!("structure size {structure_size}"),
            ));
        }
        let session_flags = reader.read_u16_le()?;
        let _ = session_flags;
        let sec_offset = reader.read_u16_le()? as usize;
        let sec_len = reader.read_u16_le()? as usize;
        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(sec_offset)?;
        let security_buffer = at.read_bytes(sec_len)?.to_vec();

        Ok(Self {
            session_id: 0,
            security_buffer,
        })
    }
}

impl Pack for SessionSetupResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let offset = 64 + 8;
        writer
            .write_u16_le(9)
            .write_u16_le(0)
            .write_u16_le(offset as u16)
            .write_u16_le(self.security_buffer.len() as u16);
        writer.write_bytes(&self.security_buffer);
    }
}
