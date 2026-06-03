use ipkt_core::{ByteReader, ByteWriter};

use crate::error::{Error, Result};


const CLASS_APPLICATION: u8 = 0x60;
const CLASS_CONTEXT: u8 = 0xA0;
const TAG_INTEGER: u8 = 0x02;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_GENERAL_STRING: u8 = 0x1B;
const TAG_OCTET_STRING: u8 = 0x04;


pub fn encode_length_public(writer: &mut ByteWriter, len: usize) {
    encode_length(writer, len);
}

fn encode_length(writer: &mut ByteWriter, len: usize) {
    if len < 128 {
        writer.write_u8(len as u8);
    } else if len < 256 {
        writer.write_u8(0x81).write_u8(len as u8);
    } else {
        writer
            .write_u8(0x82)
            .write_u8(((len >> 8) & 0xFF) as u8)
            .write_u8((len & 0xFF) as u8);
    }
}


pub fn read_length(reader: &mut ByteReader<'_>) -> Result<usize> {
    let first = reader.read_u8()?;
    if first < 128 {
        return Ok(first as usize);
    }
    let num = (first & 0x7F) as usize;
    if num == 1 {
        return Ok(reader.read_u8()? as usize);
    }
    if num == 2 {
        let hi = reader.read_u8()? as usize;
        let lo = reader.read_u8()? as usize;
        return Ok((hi << 8) | lo);
    }
    Err(Error::Der(format!(
        "unsupported length encoding {first:#x}"
    )))
}

/// Wraps `content` in a DER SEQUENCE.
pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(TAG_SEQUENCE);
    encode_length(&mut w, content.len());
    w.write_bytes(content);
    w.into_vec()
}

/// Encodes a context-specific constructed tag `[n]`.
pub fn encode_context(n: u8, content: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(CLASS_CONTEXT | n);
    encode_length(&mut w, content.len());
    w.write_bytes(content);
    w.into_vec()
}

/// Encodes `[APPLICATION n] EXPLICIT`.
pub fn encode_application(n: u8, content: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(CLASS_APPLICATION | n);
    encode_length(&mut w, content.len());
    w.write_bytes(content);
    w.into_vec()
}

/// Encodes a DER INTEGER (non-negative, fits in u32).
pub fn encode_integer(value: u32) -> Vec<u8> {
    let bytes = if value <= 0xFF {
        vec![value as u8]
    } else if value <= 0xFFFF {
        vec![((value >> 8) & 0xFF) as u8, (value & 0xFF) as u8]
    } else {
        vec![
            ((value >> 24) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    };
    let mut w = ByteWriter::new();
    w.write_u8(TAG_INTEGER);
    encode_length(&mut w, bytes.len());
    w.write_bytes(&bytes);
    w.into_vec()
}

/// Encodes an OCTET STRING.
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(TAG_OCTET_STRING);
    encode_length(&mut w, data.len());
    w.write_bytes(data);
    w.into_vec()
}

/// Encodes `GeneralString` (UTF-8 subset for KerberosString).
pub fn encode_general_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut w = ByteWriter::new();
    w.write_u8(TAG_GENERAL_STRING);
    encode_length(&mut w, bytes.len());
    w.write_bytes(bytes);
    w.into_vec()
}

/// Reads a DER INTEGER as `u32` (small values only).
pub fn decode_integer(reader: &mut ByteReader<'_>) -> Result<u32> {
    let tag = reader.read_u8()?;
    if tag != TAG_INTEGER {
        return Err(Error::Der(format!("expected INTEGER, got {tag:#x}")));
    }
    let len = read_length(reader)?;
    let bytes = reader.read_bytes(len)?;
    let mut value = 0u32;
    for &b in bytes {
        value = (value << 8) | u32::from(b);
    }
    Ok(value)
}


pub fn decode_general_string(reader: &mut ByteReader<'_>) -> Result<String> {
    let tag = reader.read_u8()?;
    if tag != TAG_GENERAL_STRING {
        return Err(Error::Der(format!("expected GeneralString, got {tag:#x}")));
    }
    let len = read_length(reader)?;
    let bytes = reader.read_bytes(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|e| Error::Der(e.to_string()))
}

