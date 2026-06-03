use ipkt_core::text::{decode_utf16le, encode_utf16le};
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::avpair::TargetInfo;
use crate::crypto::Challenge;
use crate::flags::NegotiateFlags;
use crate::payload::{FieldRef, PayloadBuilder};
use crate::version::Version;

use super::{encode_oem, read_header, MESSAGE_TYPE_CHALLENGE};

const HEADER_BASE: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ChallengeMessage {
    pub flags: NegotiateFlags,

    pub target_name: Option<String>,

    pub server_challenge: Challenge,

    pub target_info: TargetInfo,

    pub version: Option<Version>,

    #[cfg_attr(feature = "serde", serde(skip))]
    raw_target_info: Vec<u8>,
}

impl ChallengeMessage {
    #[must_use]
    pub fn new(
        flags: NegotiateFlags,
        server_challenge: Challenge,
        target_info: TargetInfo,
    ) -> Self {
        let mut flags = flags;
        flags.set(
            NegotiateFlags::NEGOTIATE_TARGET_INFO,
            !target_info.pairs().is_empty(),
        );
        Self {
            flags,
            target_name: None,
            server_challenge,
            target_info,
            version: None,
            raw_target_info: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_target_name(mut self, target_name: impl Into<String>) -> Self {
        self.target_name = Some(target_name.into());
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self.flags |= NegotiateFlags::NEGOTIATE_VERSION;
        self
    }

    #[must_use]
    pub fn target_info_bytes(&self) -> Vec<u8> {
        if self.raw_target_info.is_empty() {
            self.target_info.pack()
        } else {
            self.raw_target_info.clone()
        }
    }

    fn encode_target_name(&self, flags: NegotiateFlags) -> Vec<u8> {
        match &self.target_name {
            None => Vec::new(),
            Some(name) if flags.uses_unicode() => encode_utf16le(name),
            Some(name) => encode_oem(name),
        }
    }
}

impl Pack for ChallengeMessage {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let flags = self.flags;
        let header_size = HEADER_BASE
            + if self.version.is_some() {
                Version::SIZE
            } else {
                0
            };

        let target_name = self.encode_target_name(flags);
        let target_info = self.target_info_bytes();

        let mut payload = PayloadBuilder::new(header_size);
        let target_name_field = payload.add(&target_name);
        let target_info_field = payload.add(&target_info);

        writer
            .write_bytes(&super::NTLMSSP_SIGNATURE)
            .write_u32_le(MESSAGE_TYPE_CHALLENGE);
        target_name_field.write(writer);
        writer
            .write_u32_le(flags.bits())
            .write_bytes(&self.server_challenge)
            .write_bytes(&[0u8; 8]);
        target_info_field.write(writer);
        if let Some(version) = self.version {
            version.pack_into(writer);
        }
        writer.write_bytes(&payload.into_bytes());
    }
}

impl Unpack for ChallengeMessage {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let message = reader.buffer();
        read_header(reader, MESSAGE_TYPE_CHALLENGE)
            .map_err(|err| ipkt_core::Error::invalid_data("NTLM CHALLENGE header", err))?;

        let target_name_field = FieldRef::read(reader)?;
        let flags = NegotiateFlags::from_bits_retain(reader.read_u32_le()?);
        let server_challenge = reader.read_array::<8>()?;
        let _reserved = reader.read_array::<8>()?;
        let target_info_field = FieldRef::read(reader)?;
        let version = if flags.contains(NegotiateFlags::NEGOTIATE_VERSION) {
            Some(Version::unpack_from(reader)?)
        } else {
            None
        };

        let mut msg = ByteReader::new(message);
        let target_name = if target_name_field.len == 0 {
            None
        } else {
            let bytes = target_name_field.resolve(&mut msg)?;
            Some(if flags.uses_unicode() {
                decode_utf16le(bytes)?
            } else {
                bytes.iter().map(|&b| b as char).collect()
            })
        };

        let raw_target_info = target_info_field.resolve(&mut msg)?.to_vec();
        let target_info = if raw_target_info.is_empty() {
            TargetInfo::new()
        } else {
            TargetInfo::unpack(&raw_target_info)?
        };

        Ok(Self {
            flags,
            target_name,
            server_challenge,
            target_info,
            version,
            raw_target_info,
        })
    }
}
