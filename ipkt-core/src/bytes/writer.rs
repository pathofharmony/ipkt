#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteWriter {
    buffer: Vec<u8>,
}

impl ByteWriter {
    #[must_use]
    pub const fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.buffer
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(bytes);
        self
    }

    pub fn write_u8(&mut self, value: u8) -> &mut Self {
        self.buffer.push(value);
        self
    }

    pub fn write_u16_le(&mut self, value: u16) -> &mut Self {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u32_le(&mut self, value: u32) -> &mut Self {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u64_le(&mut self, value: u64) -> &mut Self {
        self.write_bytes(&value.to_le_bytes())
    }

    pub fn write_u16_be(&mut self, value: u16) -> &mut Self {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_u32_be(&mut self, value: u32) -> &mut Self {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn patch(&mut self, offset: usize, bytes: &[u8]) -> &mut Self {
        let end = offset + bytes.len();
        assert!(
            end <= self.buffer.len(),
            "patch region {offset}..{end} exceeds buffer length {}",
            self.buffer.len()
        );
        self.buffer[offset..end].copy_from_slice(bytes);
        self
    }
}

impl From<ByteWriter> for Vec<u8> {
    fn from(writer: ByteWriter) -> Self {
        writer.into_vec()
    }
}

impl AsRef<[u8]> for ByteWriter {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
