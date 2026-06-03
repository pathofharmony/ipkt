use ipkt_core::{ByteReader, ByteWriter, Pack, Result as CoreResult, Unpack};

use crate::header::{Smb2Header, SMB2_HEADER_SIZE};


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Smb2Packet<B> {
    
    pub header: Smb2Header,
    
    pub body: B,
    
    pub payload: Vec<u8>,
}

impl<B: Pack> Smb2Packet<B> {
    
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        let mut writer = ByteWriter::with_capacity(SMB2_HEADER_SIZE + 256);
        self.header.pack_into(&mut writer);
        self.body.pack_into(&mut writer);
        writer.write_bytes(&self.payload);
        writer.into_vec()
    }
}

impl<B: Unpack> Smb2Packet<B> {
    
    pub fn unpack(bytes: &[u8]) -> CoreResult<Self> {
        let mut reader = ByteReader::new(bytes);
        let header = Smb2Header::unpack_from(&mut reader)?;
        let body = B::unpack_from(&mut reader)?;
        let payload = reader.read_bytes(reader.remaining())?.to_vec();
        Ok(Self {
            header,
            body,
            payload,
        })
    }
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetbiosSessionMessage {
    
    pub msg_type: u8,
    
    pub payload: Vec<u8>,
}

impl NetbiosSessionMessage {
    
    #[must_use]
    pub fn wrap(smb_payload: Vec<u8>) -> Vec<u8> {
        let len = smb_payload.len();
        let mut out = Vec::with_capacity(4 + len);
        out.push(0x00); 
        out.push(((len >> 16) & 0xFF) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(&smb_payload);
        out
    }

    
    
    
    
    
    pub fn unwrap(bytes: &[u8]) -> crate::Result<(Self, usize)> {
        if bytes.len() < 4 {
            return Err(crate::Error::Framing("buffer shorter than 4 bytes".into()));
        }
        let msg_type = bytes[0];
        let len = ((bytes[1] as usize) << 16) | ((bytes[2] as usize) << 8) | (bytes[3] as usize);
        let total = 4 + len;
        if bytes.len() < total {
            return Err(crate::Error::Framing(format!(
                "need {total} bytes, have {}",
                bytes.len()
            )));
        }
        Ok((
            Self {
                msg_type,
                payload: bytes[4..total].to_vec(),
            },
            total,
        ))
    }
}
