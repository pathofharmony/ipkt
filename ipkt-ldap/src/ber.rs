use ipkt_core::{ByteReader, ByteWriter};

use crate::error::{Error, Result};

fn encode_len(writer: &mut ByteWriter, len: usize) {
    if len < 128 {
        writer.write_u8(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let num = 8 - start;
        writer.write_u8(0x80 | num as u8);
        writer.write_bytes(&bytes[start..]);
    }
}

pub fn read_len(reader: &mut ByteReader<'_>) -> Result<usize> {
    let first = reader.read_u8()?;
    if first < 128 {
        return Ok(first as usize);
    }
    let num = (first & 0x7F) as usize;
    let mut len = 0usize;
    for _ in 0..num {
        len = (len << 8) | reader.read_u8()? as usize;
    }
    Ok(len)
}

pub fn encode_sequence(content: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(0x30);
    encode_len(&mut w, content.len());
    w.write_bytes(content);
    w.into_vec()
}

pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(0x04);
    encode_len(&mut w, data.len());
    w.write_bytes(data);
    w.into_vec()
}

/// Encodes a BER INTEGER (RFC 4511 message id, etc.).
pub fn encode_integer(value: i32) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(0x02);
    let encoded: Vec<u8> = if value == 0 {
        vec![0]
    } else if value > 0 && value < 128 {
        vec![value as u8]
    } else {
        let be = value.to_be_bytes();
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        be[start..].to_vec()
    };
    encode_len(&mut w, encoded.len());
    w.write_bytes(&encoded);
    w.into_vec()
}

pub fn encode_enumerated(value: u8) -> Vec<u8> {
    let mut w = ByteWriter::new();
    w.write_u8(0x0A);
    encode_len(&mut w, 1);
    w.write_u8(value);
    w.into_vec()
}

#[allow(dead_code)]
pub fn decode_octet_string(reader: &mut ByteReader<'_>) -> Result<Vec<u8>> {
    let tag = reader.read_u8()?;
    if tag != 0x04 {
        return Err(Error::Ber(format!("expected OCTET STRING, got {tag:#x}")));
    }
    let len = read_len(reader)?;
    Ok(reader.read_bytes(len)?.to_vec())
}
