use ipkt_core::ByteWriter;


#[derive(Debug, Default)]
pub struct NdrWriter {
    buffer: ByteWriter,
    
    _referent_id: u32,
}

impl NdrWriter {
    
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: ByteWriter::new(),
            _referent_id: 0x0002_0000,
        }
    }

    
    pub fn align(&mut self, boundary: usize) {
        let pad = (boundary - (self.buffer.len() % boundary)) % boundary;
        for _ in 0..pad {
            self.buffer.write_u8(0);
        }
    }

    
    pub fn write_u32(&mut self, value: u32) -> &mut Self {
        self.align(4);
        self.buffer.write_u32_le(value);
        self
    }

    
    pub fn write_u16(&mut self, value: u16) -> &mut Self {
        self.align(2);
        self.buffer.write_u16_le(value);
        self
    }

    
    pub fn write_unicode_string(&mut self, value: &str) -> &mut Self {
        let units: Vec<u16> = value.encode_utf16().collect();
        let max = units.len() as u32;
        let offset = units.len() as u32;
        self.write_u32(max);
        self.write_u32(offset);
        self.write_u32(max);
        self.align(2);
        for u in units {
            self.buffer.write_u16_le(u);
        }
        self
    }

    
    pub fn write_bytes16(&mut self, bytes: &[u8; 16]) -> &mut Self {
        self.align(4);
        self.buffer.write_bytes(bytes);
        self
    }

    
    pub fn write_sampr_handle(&mut self, handle: &[u8; 20]) -> &mut Self {
        let handle_type = u32::from_le_bytes(handle[0..4].try_into().expect("4 bytes"));
        self.write_u32(handle_type);
        self.align(4);
        self.buffer.write_bytes(&handle[4..20]);
        self
    }

    
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buffer.into_vec()
    }
}


#[derive(Debug)]
pub struct NdrReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> NdrReader<'a> {
    
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn align(&mut self, boundary: usize) {
        let pad = (boundary - (self.pos % boundary)) % boundary;
        self.pos += pad;
    }

    /// Reads `u32`.
    pub fn read_u32(&mut self) -> Option<u32> {
        self.align(4);
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    /// Reads 16 raw bytes (e.g. RPC context handle uuid part).
    pub fn read_bytes16(&mut self) -> Option<[u8; 16]> {
        self.align(4);
        if self.pos + 16 > self.data.len() {
            return None;
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.data[self.pos..self.pos + 16]);
        self.pos += 16;
        Some(out)
    }

    /// Remaining unconsumed bytes.
    #[must_use]
    pub fn remaining(&self) -> &[u8] {
        &self.data[self.pos..]
    }
}
