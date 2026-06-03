mod authenticate;
mod challenge;
mod negotiate;

pub use authenticate::{AuthenticateMessage, MIC_LEN, MIC_OFFSET};
pub use challenge::ChallengeMessage;
pub use negotiate::NegotiateMessage;

use ipkt_core::ByteReader;

use crate::error::{Error, Result};


pub const NTLMSSP_SIGNATURE: [u8; 8] = *b"NTLMSSP\0";


pub const MESSAGE_TYPE_NEGOTIATE: u32 = 1;

pub const MESSAGE_TYPE_CHALLENGE: u32 = 2;

pub const MESSAGE_TYPE_AUTHENTICATE: u32 = 3;








pub(crate) fn read_header(reader: &mut ByteReader<'_>, expected: u32) -> Result<()> {
    let signature = reader.read_array::<8>()?;
    if signature != NTLMSSP_SIGNATURE {
        return Err(Error::InvalidSignature {
            expected: NTLMSSP_SIGNATURE,
            found: signature,
        });
    }
    let message_type = reader.read_u32_le()?;
    if message_type != expected {
        return Err(Error::UnexpectedMessageType {
            expected,
            found: message_type,
        });
    }
    Ok(())
}

/// Encodes a string as OEM (single-byte) text, substituting `?` for any
/// character outside the printable ASCII range. NTLM uses OEM encoding only
/// for the (rarely populated) domain/workstation fields of the NEGOTIATE
/// message.
pub(crate) fn encode_oem(value: &str) -> Vec<u8> {
    value
        .chars()
        .map(|c| if c.is_ascii() { c as u8 } else { b'?' })
        .collect()
}
