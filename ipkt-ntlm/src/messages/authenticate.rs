use ipkt_core::text::{decode_utf16le, encode_utf16le};
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::flags::NegotiateFlags;
use crate::payload::{FieldRef, PayloadBuilder};
use crate::version::Version;

use super::{encode_oem, read_header, MESSAGE_TYPE_AUTHENTICATE};

const HEADER_BASE: usize = 64;

pub const MIC_OFFSET: usize = HEADER_BASE + Version::SIZE;

pub const MIC_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticateMessage {
    pub flags: NegotiateFlags,

    pub lm_challenge_response: Vec<u8>,

    pub nt_challenge_response: Vec<u8>,

    pub domain: Option<String>,

    pub user: Option<String>,

    pub workstation: Option<String>,

    pub encrypted_session_key: Option<Vec<u8>>,

    pub version: Option<Version>,

    pub mic: Option<[u8; MIC_LEN]>,
}

impl AuthenticateMessage {
    #[must_use]
    pub fn new(
        flags: NegotiateFlags,
        lm_challenge_response: Vec<u8>,
        nt_challenge_response: Vec<u8>,
    ) -> Self {
        Self {
            flags,
            lm_challenge_response,
            nt_challenge_response,
            domain: None,
            user: None,
            workstation: None,
            encrypted_session_key: None,
            version: None,
            mic: None,
        }
    }

    #[must_use]
    pub fn with_identity(mut self, domain: impl Into<String>, user: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self.user = Some(user.into());
        self
    }

    #[must_use]
    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = Some(workstation.into());
        self
    }

    #[must_use]
    pub fn with_encrypted_session_key(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.encrypted_session_key = Some(key.into());
        self
    }

    #[must_use]
    pub fn with_version(mut self, version: Version) -> Self {
        self.version = Some(version);
        self.flags |= NegotiateFlags::NEGOTIATE_VERSION;
        self
    }

    #[must_use]
    pub fn with_mic_placeholder(mut self) -> Self {
        self.ensure_version();
        self.mic = Some([0u8; MIC_LEN]);
        self
    }

    pub fn set_mic(&mut self, mic: [u8; MIC_LEN]) {
        self.ensure_version();
        self.mic = Some(mic);
    }

    fn ensure_version(&mut self) {
        if self.version.is_none() {
            self.version = Some(Version::default());
        }
        self.flags |= NegotiateFlags::NEGOTIATE_VERSION;
    }

    fn includes_version(&self) -> bool {
        self.version.is_some() || self.mic.is_some()
    }

    fn header_size(&self) -> usize {
        HEADER_BASE
            + if self.includes_version() {
                Version::SIZE
            } else {
                0
            }
            + if self.mic.is_some() { MIC_LEN } else { 0 }
    }

    fn encode_text(&self, value: &Option<String>) -> Vec<u8> {
        match value {
            None => Vec::new(),
            Some(text) if self.flags.uses_unicode() => encode_utf16le(text),
            Some(text) => encode_oem(text),
        }
    }
}

impl Pack for AuthenticateMessage {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let header_size = self.header_size();
        let mut payload = PayloadBuilder::new(header_size);

        let lm_field = payload.add(&self.lm_challenge_response);
        let nt_field = payload.add(&self.nt_challenge_response);
        let domain_field = payload.add(&self.encode_text(&self.domain));
        let user_field = payload.add(&self.encode_text(&self.user));
        let workstation_field = payload.add(&self.encode_text(&self.workstation));
        let session_key_field =
            payload.add(self.encrypted_session_key.as_deref().unwrap_or_default());

        writer
            .write_bytes(&super::NTLMSSP_SIGNATURE)
            .write_u32_le(MESSAGE_TYPE_AUTHENTICATE);
        lm_field.write(writer);
        nt_field.write(writer);
        domain_field.write(writer);
        user_field.write(writer);
        workstation_field.write(writer);
        session_key_field.write(writer);
        writer.write_u32_le(self.flags.bits());

        if self.includes_version() {
            self.version.unwrap_or_default().pack_into(writer);
        }
        if let Some(mic) = self.mic {
            writer.write_bytes(&mic);
        }
        writer.write_bytes(&payload.into_bytes());
    }
}

impl Unpack for AuthenticateMessage {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let message = reader.buffer();
        read_header(reader, MESSAGE_TYPE_AUTHENTICATE)
            .map_err(|err| ipkt_core::Error::invalid_data("NTLM AUTHENTICATE header", err))?;

        let lm_field = FieldRef::read(reader)?;
        let nt_field = FieldRef::read(reader)?;
        let domain_field = FieldRef::read(reader)?;
        let user_field = FieldRef::read(reader)?;
        let workstation_field = FieldRef::read(reader)?;
        let session_key_field = FieldRef::read(reader)?;
        let flags = NegotiateFlags::from_bits_retain(reader.read_u32_le()?);

        let version = if flags.contains(NegotiateFlags::NEGOTIATE_VERSION) {
            Some(Version::unpack_from(reader)?)
        } else {
            None
        };

        // Detect an optional MIC: it occupies the gap between the end of the
        // fixed header and the first populated payload field.
        let header_end = reader.position();
        let first_payload = [
            lm_field,
            nt_field,
            domain_field,
            user_field,
            workstation_field,
            session_key_field,
        ]
        .into_iter()
        .filter(|f| f.len > 0)
        .map(|f| f.offset as usize)
        .min();

        let mic = match first_payload {
            Some(offset) if offset >= header_end + MIC_LEN => Some(reader.read_array::<MIC_LEN>()?),
            _ => None,
        };

        let mut msg = ByteReader::new(message);
        let decode = |field: FieldRef, msg: &mut ByteReader<'_>| -> CoreResult<Option<String>> {
            if field.len == 0 {
                return Ok(None);
            }
            let bytes = field.resolve(msg)?;
            Ok(Some(if flags.uses_unicode() {
                decode_utf16le(bytes)?
            } else {
                bytes.iter().map(|&b| b as char).collect()
            }))
        };

        let lm_challenge_response = lm_field.resolve(&mut msg)?.to_vec();
        let nt_challenge_response = nt_field.resolve(&mut msg)?.to_vec();
        let domain = decode(domain_field, &mut msg)?;
        let user = decode(user_field, &mut msg)?;
        let workstation = decode(workstation_field, &mut msg)?;
        let encrypted_session_key = if session_key_field.len == 0 {
            None
        } else {
            Some(session_key_field.resolve(&mut msg)?.to_vec())
        };

        Ok(Self {
            flags,
            lm_challenge_response,
            nt_challenge_response,
            domain,
            user,
            workstation,
            encrypted_session_key,
            version,
            mic,
        })
    }
}
