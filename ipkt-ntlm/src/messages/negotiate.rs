use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::flags::NegotiateFlags;
use crate::payload::{FieldRef, PayloadBuilder};
use crate::version::Version;

use super::{encode_oem, read_header, MESSAGE_TYPE_NEGOTIATE};

const HEADER_BASE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NegotiateMessage {
    pub flags: NegotiateFlags,

    pub domain: Option<String>,

    pub workstation: Option<String>,

    pub version: Option<Version>,
}

impl NegotiateMessage {
    #[must_use]
    pub fn new(flags: NegotiateFlags) -> Self {
        Self {
            flags,
            domain: None,
            workstation: None,
            version: None,
        }
    }

    #[must_use]
    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self.flags |= NegotiateFlags::NEGOTIATE_OEM_DOMAIN_SUPPLIED;
        self
    }

    #[must_use]
    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = Some(workstation.into());
        self.flags |= NegotiateFlags::NEGOTIATE_OEM_WORKSTATION_SUPPLIED;
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self.flags |= NegotiateFlags::NEGOTIATE_VERSION;
        self
    }
}

impl Pack for NegotiateMessage {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let flags = self.flags;
        let header_size = HEADER_BASE
            + if self.version.is_some() {
                Version::SIZE
            } else {
                0
            };

        let mut payload = PayloadBuilder::new(header_size);
        let domain_field = payload.add(&self.domain.as_deref().map(encode_oem).unwrap_or_default());
        let workstation_field = payload.add(
            &self
                .workstation
                .as_deref()
                .map(encode_oem)
                .unwrap_or_default(),
        );

        writer
            .write_bytes(&super::NTLMSSP_SIGNATURE)
            .write_u32_le(MESSAGE_TYPE_NEGOTIATE)
            .write_u32_le(flags.bits());
        domain_field.write(writer);
        workstation_field.write(writer);
        if let Some(version) = self.version {
            version.pack_into(writer);
        }
        writer.write_bytes(&payload.into_bytes());
    }
}

impl Unpack for NegotiateMessage {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let message = reader.buffer();
        read_header(reader, MESSAGE_TYPE_NEGOTIATE)
            .map_err(|err| ipkt_core::Error::invalid_data("NTLM NEGOTIATE header", err))?;

        let flags = NegotiateFlags::from_bits_retain(reader.read_u32_le()?);
        let domain_field = FieldRef::read(reader)?;
        let workstation_field = FieldRef::read(reader)?;
        let version = if flags.contains(NegotiateFlags::NEGOTIATE_VERSION) {
            Some(Version::unpack_from(reader)?)
        } else {
            None
        };

        let mut msg = ByteReader::new(message);
        let domain = read_optional_oem(&mut msg, domain_field)?;
        let workstation = read_optional_oem(&mut msg, workstation_field)?;

        Ok(Self {
            flags,
            domain,
            workstation,
            version,
        })
    }
}

/// Resolves an OEM-encoded payload field, returning `None` for empty fields.
fn read_optional_oem(message: &mut ByteReader<'_>, field: FieldRef) -> CoreResult<Option<String>> {
    if field.len == 0 {
        return Ok(None);
    }
    let bytes = field.resolve(message)?;
    Ok(Some(bytes.iter().map(|&b| b as char).collect()))
}
