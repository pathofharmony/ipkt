use ipkt_core::{ByteReader, ByteWriter, Result as CoreResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FieldRef {
    pub len: u16,

    pub offset: u32,
}

impl FieldRef {
    pub(crate) fn read(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let len = reader.read_u16_le()?;
        let _max_len = reader.read_u16_le()?;
        let offset = reader.read_u32_le()?;
        Ok(Self { len, offset })
    }

    /// Writes the 8-byte descriptor into the header (`MaxLen == Len`).
    pub(crate) fn write(self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(self.len)
            .write_u16_le(self.len)
            .write_u32_le(self.offset);
    }

    /// Resolves this descriptor against the full message buffer, returning the
    /// referenced bytes.
    pub(crate) fn resolve<'a>(self, message: &mut ByteReader<'a>) -> CoreResult<&'a [u8]> {
        let mut at = message.at(self.offset as usize)?;
        at.read_bytes(self.len as usize)
    }
}

pub(crate) struct PayloadBuilder {
    base: usize,
    buffer: Vec<u8>,
}

impl PayloadBuilder {
    pub(crate) fn new(header_size: usize) -> Self {
        Self {
            base: header_size,
            buffer: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, data: &[u8]) -> FieldRef {
        let offset = (self.base + self.buffer.len()) as u32;
        self.buffer.extend_from_slice(data);
        FieldRef {
            len: data.len() as u16,
            offset,
        }
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.buffer
    }
}
