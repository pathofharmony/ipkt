use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrpcThis {
    pub flags: u32,
    pub cid: u32,
}

impl Pack for OrpcThis {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer.write_u32_le(self.flags).write_u32_le(self.cid);
    }
}

impl Unpack for OrpcThis {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        Ok(Self {
            flags: reader.read_u32_le()?,
            cid: reader.read_u32_le()?,
        })
    }
}

/// ORPCTHAT response stub (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct OrpcThat {
    pub flags: u32,
    pub extensions: u32,
}

impl Pack for OrpcThat {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u32_le(self.flags)
            .write_u32_le(self.extensions);
    }
}

impl Unpack for OrpcThat {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        Ok(Self {
            flags: reader.read_u32_le()?,
            extensions: reader.read_u32_le()?,
        })
    }
}
