use crate::error::{Error, Result};



















#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    buffer: &'a [u8],
    position: usize,
}

impl<'a> ByteReader<'a> {
    
    #[must_use]
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    /// Returns the full underlying buffer, ignoring the current position.
    #[must_use]
    pub const fn buffer(&self) -> &'a [u8] {
        self.buffer
    }

    
    #[must_use]
    pub const fn position(&self) -> usize {
        self.position
    }

    
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buffer.len() - self.position
    }

    
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    
    
    
    
    
    
    
    pub fn seek(&mut self, position: usize) -> Result<()> {
        if position > self.buffer.len() {
            return Err(Error::OutOfBounds {
                offset: position,
                length: 0,
                total: self.buffer.len(),
            });
        }
        self.position = position;
        Ok(())
    }

    
    
    
    
    
    
    
    
    
    
    
    
    pub fn at(&self, offset: usize) -> Result<ByteReader<'a>> {
        if offset > self.buffer.len() {
            return Err(Error::OutOfBounds {
                offset,
                length: 0,
                total: self.buffer.len(),
            });
        }
        Ok(ByteReader {
            buffer: self.buffer,
            position: offset,
        })
    }

    /// Reads `len` bytes and advances the cursor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if fewer than `len` bytes remain.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if len > self.remaining() {
            return Err(Error::UnexpectedEof {
                needed: len,
                available: self.remaining(),
            });
        }
        let start = self.position;
        self.position += len;
        Ok(&self.buffer[start..self.position])
    }

    
    
    
    
    
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.read_bytes(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    
    
    
    
    
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    
    
    
    
    
    pub fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    
    
    
    
    
    pub fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    
    
    
    
    
    pub fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    
    
    
    
    
    pub fn read_u16_be(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    
    
    
    
    
    pub fn read_u32_be(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }
}
