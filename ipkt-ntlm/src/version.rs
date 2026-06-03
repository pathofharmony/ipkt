use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


pub const NTLMSSP_REVISION_W2K3: u8 = 0x0F;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Version {
    
    pub major: u8,
    
    pub minor: u8,
    
    pub build: u16,
    
    pub revision: u8,
}

impl Version {
    
    pub const SIZE: usize = 8;

    
    #[must_use]
    pub const fn new(major: u8, minor: u8, build: u16) -> Self {
        Self {
            major,
            minor,
            build,
            revision: NTLMSSP_REVISION_W2K3,
        }
    }
}

impl Default for Version {
    
    fn default() -> Self {
        Self::new(10, 0, 19041)
    }
}

impl Pack for Version {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u8(self.major)
            .write_u8(self.minor)
            .write_u16_le(self.build)
            
            .write_bytes(&[0, 0, 0])
            .write_u8(self.revision);
    }
}

impl Unpack for Version {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let major = reader.read_u8()?;
        let minor = reader.read_u8()?;
        let build = reader.read_u16_le()?;
        let _reserved = reader.read_bytes(3)?;
        let revision = reader.read_u8()?;
        Ok(Self {
            major,
            minor,
            build,
            revision,
        })
    }
}
