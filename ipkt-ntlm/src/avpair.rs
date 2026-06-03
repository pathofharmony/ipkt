use ipkt_core::text::{decode_utf16le, encode_utf16le};
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AvId {
    Eol,

    NbComputerName,

    NbDomainName,

    DnsComputerName,

    DnsDomainName,

    DnsTreeName,

    Flags,

    Timestamp,

    SingleHost,

    TargetName,

    ChannelBindings,

    Unknown(u16),
}

impl AvId {
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Eol => 0x0000,
            Self::NbComputerName => 0x0001,
            Self::NbDomainName => 0x0002,
            Self::DnsComputerName => 0x0003,
            Self::DnsDomainName => 0x0004,
            Self::DnsTreeName => 0x0005,
            Self::Flags => 0x0006,
            Self::Timestamp => 0x0007,
            Self::SingleHost => 0x0008,
            Self::TargetName => 0x0009,
            Self::ChannelBindings => 0x000A,
            Self::Unknown(value) => value,
        }
    }

    #[must_use]
    pub const fn from_u16(value: u16) -> Self {
        match value {
            0x0000 => Self::Eol,
            0x0001 => Self::NbComputerName,
            0x0002 => Self::NbDomainName,
            0x0003 => Self::DnsComputerName,
            0x0004 => Self::DnsDomainName,
            0x0005 => Self::DnsTreeName,
            0x0006 => Self::Flags,
            0x0007 => Self::Timestamp,
            0x0008 => Self::SingleHost,
            0x0009 => Self::TargetName,
            0x000A => Self::ChannelBindings,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AvPair {
    pub id: AvId,

    pub value: Vec<u8>,
}

impl AvPair {
    #[must_use]
    pub fn new(id: AvId, value: impl Into<Vec<u8>>) -> Self {
        Self {
            id,
            value: value.into(),
        }
    }

    #[must_use]
    pub fn string(id: AvId, value: &str) -> Self {
        Self::new(id, encode_utf16le(value))
    }

    pub fn as_string(&self) -> Result<String> {
        Ok(decode_utf16le(&self.value)?)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TargetInfo {
    pairs: Vec<AvPair>,
}

impl TargetInfo {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn pairs(&self) -> &[AvPair] {
        &self.pairs
    }

    #[must_use]
    pub fn with(mut self, pair: AvPair) -> Self {
        self.pairs.push(pair);
        self
    }

    pub fn push(&mut self, pair: AvPair) {
        self.pairs.push(pair);
    }

    #[must_use]
    pub fn get(&self, id: AvId) -> Option<&AvPair> {
        self.pairs.iter().find(|pair| pair.id == id)
    }

    #[must_use]
    pub fn timestamp(&self) -> Option<u64> {
        let pair = self.get(AvId::Timestamp)?;
        let bytes: [u8; 8] = pair.value.as_slice().try_into().ok()?;
        Some(u64::from_le_bytes(bytes))
    }

    #[must_use]
    pub fn flags(&self) -> Option<u32> {
        let pair = self.get(AvId::Flags)?;
        let bytes: [u8; 4] = pair.value.as_slice().try_into().ok()?;
        Some(u32::from_le_bytes(bytes))
    }
}

impl Pack for TargetInfo {
    fn pack_into(&self, writer: &mut ByteWriter) {
        for pair in &self.pairs {
            writer
                .write_u16_le(pair.id.as_u16())
                .write_u16_le(pair.value.len() as u16)
                .write_bytes(&pair.value);
        }

        writer.write_u16_le(AvId::Eol.as_u16()).write_u16_le(0);
    }
}

impl Unpack for TargetInfo {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let mut pairs = Vec::new();
        loop {
            let id = AvId::from_u16(reader.read_u16_le()?);
            let len = reader.read_u16_le()? as usize;
            if id == AvId::Eol {
                // A well-formed EOL has length 0; trailing bytes are ignored.
                break;
            }
            let value = reader.read_bytes(len)?.to_vec();
            pairs.push(AvPair { id, value });
        }
        Ok(Self { pairs })
    }
}

impl TargetInfo {
    /// Parses a `TargetInfo` list, surfacing a domain-specific error instead of
    /// the generic codec error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedAvPairs`] if the list is truncated or a value
    /// length runs past the end of the buffer.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        Self::unpack(bytes).map_err(|err| Error::MalformedAvPairs(err.to_string()))
    }
}
