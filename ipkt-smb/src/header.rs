use bitflags::bitflags;
use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};


pub const SMB2_PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];


pub const SMB2_HEADER_SIZE: usize = 64;

bitflags! {
    
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct Smb2Flags: u32 {
        
        const SERVER_TO_REDIR = 0x0000_0001;
        
        const ASYNC_COMMAND = 0x0000_0002;
        
        const RELATED_OPERATIONS = 0x0000_0004;
        
        const SIGNED = 0x0000_0008;
        
        const DFS_OPERATIONS = 0x1000_0000;
        
        const REPLAY_OPERATION = 0x2000_0000;
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum Smb2Command {
    
    Negotiate = 0x0000,
    
    SessionSetup = 0x0001,
    
    Logoff = 0x0002,
    
    TreeConnect = 0x0003,
    
    TreeDisconnect = 0x0004,
    
    Create = 0x0005,
    
    Close = 0x0006,
    
    Read = 0x0008,
    
    Write = 0x0009,
    
    Echo = 0x000E,
}

impl Smb2Command {
    
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        Some(match value {
            0x0000 => Self::Negotiate,
            0x0001 => Self::SessionSetup,
            0x0002 => Self::Logoff,
            0x0003 => Self::TreeConnect,
            0x0004 => Self::TreeDisconnect,
            0x0005 => Self::Create,
            0x0006 => Self::Close,
            0x0008 => Self::Read,
            0x0009 => Self::Write,
            0x000E => Self::Echo,
            _ => return None,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Header {
    
    pub credit_charge: u16,
    
    pub status: u32,
    
    pub command: Smb2Command,
    
    pub credits: u16,
    
    pub flags: Smb2Flags,
    
    pub next_command: u32,
    
    pub message_id: u64,
    
    pub tree_id: u32,
    
    pub session_id: u64,
    
    pub signature: [u8; 16],
}

impl Smb2Header {
    
    #[must_use]
    pub fn request(command: Smb2Command, message_id: u64, session_id: u64, tree_id: u32) -> Self {
        Self {
            credit_charge: 0,
            status: 0,
            command,
            credits: 1,
            flags: Smb2Flags::empty(),
            next_command: 0,
            message_id,
            tree_id,
            session_id,
            signature: [0; 16],
        }
    }

    
    #[must_use]
    pub fn is_success(&self) -> bool {
        
        self.status == 0 || (self.status & 0xC000_0000) == 0
    }
}

impl Pack for Smb2Header {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_bytes(&SMB2_PROTOCOL_ID)
            .write_u16_le(64) 
            .write_u16_le(self.credit_charge)
            .write_u32_le(self.status)
            .write_u16_le(self.command.as_u16())
            .write_u16_le(self.credits)
            .write_u32_le(self.flags.bits())
            .write_u32_le(self.next_command)
            .write_u64_le(self.message_id)
            .write_u32_le(0) 
            .write_u32_le(self.tree_id)
            .write_u64_le(self.session_id)
            .write_bytes(&self.signature);
    }
}

impl Unpack for Smb2Header {
    fn unpack_from(reader: &mut ByteReader<'_>) -> CoreResult<Self> {
        let proto = reader.read_array::<4>()?;
        if proto != SMB2_PROTOCOL_ID {
            return Err(ipkt_core::Error::InvalidSignature {
                context: "SMB2",
                expected: SMB2_PROTOCOL_ID.to_vec(),
                found: proto.to_vec(),
            });
        }
        let structure_size = reader.read_u16_le()?;
        if structure_size != 64 {
            return Err(ipkt_core::Error::invalid_data(
                "SMB2 header",
                format!("structure size {structure_size}, expected 64"),
            ));
        }
        let credit_charge = reader.read_u16_le()?;
        let status = reader.read_u32_le()?;
        let command = reader.read_u16_le()?;
        let command = Smb2Command::from_u16(command).ok_or_else(|| {
            ipkt_core::Error::invalid_data("SMB2 header", format!("unknown command {command}"))
        })?;
        let credits = reader.read_u16_le()?;
        let flags = Smb2Flags::from_bits_retain(reader.read_u32_le()?);
        let next_command = reader.read_u32_le()?;
        let message_id = reader.read_u64_le()?;
        let _async = reader.read_u32_le()?;
        let tree_id = reader.read_u32_le()?;
        let session_id = reader.read_u64_le()?;
        let signature = reader.read_array::<16>()?;
        Ok(Self {
            credit_charge,
            status,
            command,
            credits,
            flags,
            next_command,
            message_id,
            tree_id,
            session_id,
            signature,
        })
    }
}
