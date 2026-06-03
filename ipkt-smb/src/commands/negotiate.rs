use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


pub const SMB2_PREAUTH_INTEGRITY_CAP: u16 = 0x0001;
pub const SMB2_ENCRYPTION_CAP: u16 = 0x0002;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Dialect {
    
    Smb202 = 0x0202,
    
    Smb21 = 0x0210,
    
    Smb30 = 0x0300,
    
    Smb302 = 0x0302,
    
    Smb311 = 0x0311,
}

impl Dialect {
    
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateContext {
    
    pub context_type: u16,
    
    pub data: Vec<u8>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    
    pub dialects: Vec<Dialect>,
    
    pub contexts: Vec<NegotiateContext>,
}

impl Default for NegotiateRequest {
    fn default() -> Self {
        Self {
            dialects: vec![
                Dialect::Smb311,
                Dialect::Smb302,
                Dialect::Smb30,
                Dialect::Smb21,
            ],
            contexts: vec![
                NegotiateContext {
                    context_type: SMB2_PREAUTH_INTEGRITY_CAP,
                    data: crate::encryption::preauth_integrity_cap_sha512(),
                },
                NegotiateContext {
                    context_type: SMB2_ENCRYPTION_CAP,
                    data: crate::encryption::encryption_cap_aes128_gcm(),
                },
            ],
        }
    }
}

fn pad_to_8(len: usize) -> usize {
    (8 - (len % 8)) % 8
}

fn pack_negotiate_contexts(contexts: &[NegotiateContext]) -> Vec<u8> {
    let mut out = Vec::new();
    for ctx in contexts {
        let mut entry = Vec::with_capacity(8 + ctx.data.len());
        entry.extend_from_slice(&ctx.context_type.to_le_bytes());
        entry.extend_from_slice(&(ctx.data.len() as u16).to_le_bytes());
        entry.extend_from_slice(&0u32.to_le_bytes());
        entry.extend_from_slice(&ctx.data);
        entry.resize(entry.len() + pad_to_8(entry.len()), 0);
        out.extend(entry);
    }
    out.resize(out.len() + pad_to_8(out.len()), 0);
    out
}

impl Pack for NegotiateRequest {
    fn pack_into(&self, writer: &mut ByteWriter) {
        let dialect_bytes: Vec<u8> = self
            .dialects
            .iter()
            .flat_map(|d| d.as_u16().to_le_bytes())
            .collect();
        let negotiate_offset = 64 + 36u32;
        let negotiate_length = dialect_bytes.len() as u16;

        let smb311 = self.dialects.contains(&Dialect::Smb311);
        let context_blob = if smb311 && !self.contexts.is_empty() {
            pack_negotiate_contexts(&self.contexts)
        } else {
            Vec::new()
        };
        let dialect_padded_len = dialect_bytes.len() + pad_to_8(dialect_bytes.len());
        let context_offset = if context_blob.is_empty() {
            0u32
        } else {
            negotiate_offset + dialect_padded_len as u32
        };
        let context_count = if context_blob.is_empty() {
            0u16
        } else {
            self.contexts.len() as u16
        };

        writer
            .write_u16_le(36)
            .write_u16_le(self.dialects.len() as u16)
            .write_u16_le(0) 
            .write_u16_le(0)
            .write_u32_le(negotiate_offset)
            .write_u16_le(negotiate_length)
            .write_u16_le(0)
            .write_u32_le(context_offset)
            .write_u16_le(context_count)
            .write_u16_le(0);

        writer.write_bytes(&dialect_bytes);
        let pad = pad_to_8(dialect_bytes.len());
        if pad > 0 {
            writer.write_bytes(&vec![0u8; pad]);
        }
        if !context_blob.is_empty() {
            writer.write_bytes(&context_blob);
        }
    }
}

impl Unpack for NegotiateRequest {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 36 {
            return Err(ipkt_core::Error::invalid_data(
                "NEGOTIATE request",
                format!("structure size {structure_size}"),
            ));
        }
        let dialect_count = reader.read_u16_le()? as usize;
        let _sec_off = reader.read_u16_le()?;
        let _sec_len = reader.read_u16_le()?;
        let dialect_offset = reader.read_u32_le()? as usize;
        let dialect_length = reader.read_u16_le()? as usize;
        let _ = reader.read_u16_le()?;
        let _ctx_offset = reader.read_u32_le()?;
        let _ctx_count = reader.read_u16_le()?;
        let _ = reader.read_u16_le()?;

        let message = reader.buffer();
        let mut at = ByteReader::new(message).at(dialect_offset)?;
        let dialect_raw = at.read_bytes(dialect_length)?;
        let mut dialects = Vec::with_capacity(dialect_count);
        for chunk in dialect_raw.chunks_exact(2) {
            let val = u16::from_le_bytes([chunk[0], chunk[1]]);
            dialects.push(match val {
                0x0202 => Dialect::Smb202,
                0x0210 => Dialect::Smb21,
                0x0300 => Dialect::Smb30,
                0x0302 => Dialect::Smb302,
                0x0311 => Dialect::Smb311,
                _ => Dialect::Smb302,
            });
        }
        Ok(Self {
            dialects,
            contexts: Vec::new(),
        })
    }
}

/// SMB2 security mode flags (MS-SMB2 §2.2.3.1.2).
pub const SMB2_NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
/// Signing required by server.
pub const SMB2_NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;

/// SMB2 NEGOTIATE response (minimal fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    /// Security mode from server.
    pub security_mode: u16,
    /// Selected dialect.
    pub dialect: Dialect,
    /// Server GUID.
    pub server_guid: [u8; 16],
    /// Maximum transaction size advertised.
    pub max_transact_size: u32,
}

impl NegotiateResponse {
    /// Returns `true` if the server advertises SMB2 signing.
    #[must_use]
    pub const fn signing_enabled(&self) -> bool {
        self.security_mode & SMB2_NEGOTIATE_SIGNING_ENABLED != 0
    }

    /// Returns `true` if the server requires SMB2 signing.
    #[must_use]
    pub const fn signing_required(&self) -> bool {
        self.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED != 0
    }
}

impl Unpack for NegotiateResponse {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let structure_size = reader.read_u16_le()?;
        if structure_size != 65 {
            return Err(ipkt_core::Error::invalid_data(
                "NEGOTIATE response",
                format!("structure size {structure_size}"),
            ));
        }
        let security_mode = reader.read_u16_le()?;
        let dialect_revision = reader.read_u16_le()?;
        let dialect = match dialect_revision {
            0x0202 => Dialect::Smb202,
            0x0210 => Dialect::Smb21,
            0x0300 => Dialect::Smb30,
            0x0302 => Dialect::Smb302,
            0x0311 => Dialect::Smb311,
            _ => Dialect::Smb302,
        };
        let _ctx_count = reader.read_u16_le()?;
        let server_guid = reader.read_array::<16>()?;
        let _caps = reader.read_u32_le()?;
        let max_transact_size = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u16_le()?;
        let _ = reader.read_u16_le()?;
        let _ = reader.read_u32_le()?;
        let _ = reader.read_u16_le()?;
        let _ = reader.read_u16_le()?;
        Ok(Self {
            security_mode,
            dialect,
            server_guid,
            max_transact_size,
        })
    }
}

impl Pack for NegotiateResponse {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u16_le(65)
            .write_u16_le(1) 
            .write_u16_le(self.dialect.as_u16())
            .write_u16_le(0)
            .write_bytes(&self.server_guid)
            .write_u32_le(0) 
            .write_u32_le(self.max_transact_size)
            .write_u32_le(65536)
            .write_u32_le(65536)
            .write_u32_le(65536)
            .write_u16_le(0)
            .write_u16_le(0)
            .write_u32_le(0)
            .write_u16_le(0)
            .write_u16_le(0);
    }
}
