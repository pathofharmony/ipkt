use crate::prefix_table::{PrefixEntry, PrefixTable};

#[derive(Debug)]
pub struct NdrDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

#[allow(dead_code)]
impl<'a> NdrDecoder<'a> {
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn align(&mut self, boundary: usize) {
        let pad = (boundary - (self.pos % boundary)) % boundary;
        self.pos += pad;
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        self.align(4);
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().ok()?);
        self.pos += 4;
        Some(v)
    }

    pub fn read_u16(&mut self) -> Option<u16> {
        self.align(2);
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let v = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().ok()?);
        self.pos += 2;
        Some(v)
    }

    pub fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        self.align(4);
        if self.pos + n > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    pub fn read_ptr(&mut self) -> Option<u32> {
        let p = self.read_u32()?;
        if p == 0 {
            None
        } else {
            Some(p)
        }
    }

    pub fn read_uuid(&mut self) -> Option<[u8; 16]> {
        let b = self.read_bytes(16)?;
        b.try_into().ok()
    }

    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Current offset in the stub.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Full stub bytes.
    #[must_use]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn at(&self, offset: usize) -> Option<Self> {
        if offset < self.data.len() {
            Some(Self {
                data: self.data,
                pos: offset,
            })
        } else {
            None
        }
    }

    pub fn read_conformant_u32_array(&mut self) -> Option<Vec<u32>> {
        let _max = self.read_u32()?;
        let offset = self.read_u32()?;
        let actual = self.read_u32()?;
        if actual == 0 {
            return Some(Vec::new());
        }
        let _ = offset;
        let mut out = Vec::with_capacity(actual as usize);
        for _ in 0..actual {
            out.push(self.read_u32()?);
        }
        Some(out)
    }

    pub fn read_conformant_octets(&mut self) -> Option<Vec<u8>> {
        let _max = self.read_u32()?;
        let offset = self.read_u32()?;
        let actual = self.read_u32()?;
        if actual == 0 {
            return Some(Vec::new());
        }
        let _ = offset;
        self.align(4);
        if self.pos + actual as usize > self.data.len() {
            return None;
        }
        let out = self.data[self.pos..self.pos + actual as usize].to_vec();
        self.pos += actual as usize;
        Some(out)
    }

    pub fn read_conformant_utf16(&mut self) -> Option<String> {
        let max = self.read_u32()?;
        let offset = self.read_u32()?;
        let actual = self.read_u32()?;
        let _ = (max, offset);
        if actual == 0 {
            return Some(String::new());
        }
        self.align(2);
        let byte_len = actual as usize * 2;
        if self.pos + byte_len > self.data.len() {
            return None;
        }
        let mut units = Vec::with_capacity(actual as usize);
        for chunk in self.data[self.pos..self.pos + byte_len].chunks_exact(2) {
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
        }
        self.pos += byte_len;
        String::from_utf16(&units).ok()
    }
}

#[allow(dead_code)]
pub fn scan_prefix_table(stub: &[u8]) -> PrefixTable {
    let mut table = PrefixTable::default();
    let mut i = 0usize;
    while i + 8 < stub.len() {
        let count = u32::from_le_bytes(stub[i..i + 4].try_into().unwrap_or([0; 4]));
        if count > 0 && count < 64 && i + 4 + count as usize * 8 < stub.len() {
            let mut entries = Vec::new();
            let mut at = i + 8;
            for ndx in 0..count {
                if at + 12 > stub.len() {
                    break;
                }
                let plen =
                    u32::from_le_bytes(stub[at + 4..at + 8].try_into().unwrap_or([0; 4])) as usize;
                at += 8;
                if plen > 0 && plen < 32 && at + plen <= stub.len() {
                    entries.push(PrefixEntry {
                        ndx,
                        prefix: stub[at..at + plen].to_vec(),
                    });
                    at += plen;
                    at = (at + 3) & !3;
                }
            }
            if !entries.is_empty() {
                table.replace_entries(entries);
                return table;
            }
        }
        i += 4;
    }
    table
}

pub fn rid_from_sid(sid: &[u8]) -> Option<u32> {
    if sid.len() < 12 || sid[0] != 1 {
        return None;
    }
    let subauth_count = sid[1] as usize;
    if sid.len() < 8 + subauth_count * 4 {
        return None;
    }
    let off = 8 + (subauth_count - 1) * 4;
    Some(u32::from_le_bytes(sid[off..off + 4].try_into().ok()?))
}
