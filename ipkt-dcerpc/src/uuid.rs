use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Uuid {
    pub const NIL: Self = Self {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };

    pub fn parse(s: &str) -> crate::Result<Self> {
        let hex: String = s.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 {
            return Err(crate::Error::InvalidPdu("uuid length".into()));
        }
        let bytes = hex::decode(&hex).map_err(|e| crate::Error::InvalidPdu(e.to_string()))?;
        Ok(Self {
            data1: u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
            data2: u16::from_be_bytes(bytes[4..6].try_into().unwrap()),
            data3: u16::from_be_bytes(bytes[6..8].try_into().unwrap()),
            data4: bytes[8..16].try_into().unwrap(),
        })
    }
}

impl Pack for Uuid {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u32_le(self.data1)
            .write_u16_le(self.data2)
            .write_u16_le(self.data3)
            .write_bytes(&self.data4);
    }
}

impl Unpack for Uuid {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        Ok(Self {
            data1: reader.read_u32_le()?,
            data2: reader.read_u16_le()?,
            data3: reader.read_u16_le()?,
            data4: reader.read_array::<8>()?,
        })
    }
}
