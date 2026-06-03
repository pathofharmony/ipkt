use ipkt_core::text::{decode_utf16le, encode_utf16le};
use ipkt_core::{ByteReader, ByteWriter, Error, Pack, Unpack};

#[test]
fn reader_reads_little_endian_integers() {
    let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut reader = ByteReader::new(&data);
    assert_eq!(reader.read_u8().unwrap(), 0x01);
    assert_eq!(reader.read_u16_le().unwrap(), 0x0302);
    assert_eq!(reader.read_u32_le().unwrap(), 0x0706_0504);
    assert_eq!(reader.remaining(), 1);
}

#[test]
fn reader_reads_big_endian_integers() {
    let data = [0x01, 0x02, 0x03, 0x04];
    let mut reader = ByteReader::new(&data);
    assert_eq!(reader.read_u16_be().unwrap(), 0x0102);
    assert_eq!(reader.read_u16_be().unwrap(), 0x0304);
}

#[test]
fn reader_reports_eof_without_panicking() {
    let data = [0x00, 0x01];
    let mut reader = ByteReader::new(&data);
    let err = reader.read_u32_le().unwrap_err();
    assert_eq!(
        err,
        Error::UnexpectedEof {
            needed: 4,
            available: 2,
        }
    );

    assert_eq!(reader.position(), 0);
}

#[test]
fn reader_at_resolves_absolute_offsets() {
    let data = [0xAA, 0xBB, 0xCC, 0xDD];
    let reader = ByteReader::new(&data);
    let mut at = reader.at(2).unwrap();
    assert_eq!(at.read_u8().unwrap(), 0xCC);

    assert!(reader.at(4).unwrap().is_empty());

    assert!(reader.at(5).is_err());
}

#[test]
fn writer_patches_previously_written_region() {
    let mut writer = ByteWriter::new();
    writer.write_u32_le(0).write_u16_le(0xFFFF);
    let offset = 0;
    writer.patch(offset, &0xDEAD_BEEFu32.to_le_bytes());
    assert_eq!(writer.as_slice(), &[0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xFF]);
}

#[test]
fn utf16le_round_trips() {
    let text = "Administrator@CONTOSO";
    let encoded = encode_utf16le(text);
    assert_eq!(encoded.len(), text.chars().count() * 2);
    assert_eq!(decode_utf16le(&encoded).unwrap(), text);
}

#[test]
fn utf16le_rejects_odd_length() {
    assert!(decode_utf16le(&[0x41]).is_err());
}

#[derive(Debug, PartialEq)]
struct Sample {
    a: u32,
    b: u16,
    tail: Vec<u8>,
}

impl Pack for Sample {
    fn pack_into(&self, writer: &mut ByteWriter) {
        writer
            .write_u32_le(self.a)
            .write_u16_le(self.b)
            .write_u16_le(self.tail.len() as u16)
            .write_bytes(&self.tail);
    }
}

impl Unpack for Sample {
    fn unpack_from(reader: &mut ByteReader<'_>) -> ipkt_core::Result<Self> {
        let a = reader.read_u32_le()?;
        let b = reader.read_u16_le()?;
        let len = reader.read_u16_le()? as usize;
        let tail = reader.read_bytes(len)?.to_vec();
        Ok(Self { a, b, tail })
    }
}

#[test]
fn pack_unpack_round_trips_a_custom_structure() {
    let value = Sample {
        a: 0x1122_3344,
        b: 0x5566,
        tail: vec![1, 2, 3, 4, 5],
    };
    let bytes = value.pack();
    let parsed = Sample::unpack(&bytes).unwrap();
    assert_eq!(parsed, value);
}
