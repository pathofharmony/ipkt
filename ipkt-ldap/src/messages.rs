use ipkt_core::ByteReader;

use crate::ber::{
    encode_enumerated, encode_integer, encode_octet_string, encode_sequence, read_len,
};
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdapOp {
    BindRequest = 0,
    BindResponse = 1,
    SearchRequest = 3,
    SearchResultEntry = 4,
    SearchResultDone = 5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindAuth {
    Simple(Vec<u8>),

    Sasl {
        mechanism: String,

        credentials: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindRequest {
    pub version: u8,
    pub name: String,
    pub auth: BindAuth,
}

impl BindRequest {
    #[must_use]
    pub fn simple(version: u8, name: impl Into<String>, password: impl AsRef<[u8]>) -> Self {
        Self {
            version,
            name: name.into(),
            auth: BindAuth::Simple(password.as_ref().to_vec()),
        }
    }

    #[must_use]
    pub fn sasl_gssapi_init(version: u8, name: impl Into<String>) -> Self {
        Self::sasl(
            version,
            name,
            "GSSAPI",
            crate::spnego::gssapi_sasl_credentials(),
        )
    }

    #[must_use]
    pub fn sasl(
        version: u8,
        name: impl Into<String>,
        mechanism: impl Into<String>,
        credentials: Vec<u8>,
    ) -> Self {
        Self {
            version,
            name: name.into(),
            auth: BindAuth::Sasl {
                mechanism: mechanism.into(),
                credentials,
            },
        }
    }

    pub fn encode(&self, message_id: i32) -> Vec<u8> {
        let mut auth_field = Vec::new();
        match &self.auth {
            BindAuth::Simple(pw) => {
                auth_field.push(0x80);
                auth_field.extend(encode_octet_string(pw));
            }
            BindAuth::Sasl {
                mechanism,
                credentials,
            } => {
                let mut sasl = Vec::new();
                sasl.extend(encode_octet_string(mechanism.as_bytes()));
                if !credentials.is_empty() {
                    sasl.extend(encode_octet_string(credentials));
                }
                auth_field.push(0xA3);
                let body = encode_sequence(&sasl);
                auth_field.extend(encode_len_bytes(body.len()));
                auth_field.extend(body);
            }
        }
        let mut inner = Vec::new();
        inner.extend(encode_enumerated(self.version));
        inner.extend(encode_octet_string(self.name.as_bytes()));
        inner.extend(auth_field);
        let mut seq = Vec::new();
        seq.extend(encode_integer(message_id));
        seq.extend(encode_enumerated(LdapOp::BindRequest as u8));
        seq.extend(encode_sequence(&inner));
        encode_sequence(&seq)
    }
}

fn encode_len_bytes(len: usize) -> Vec<u8> {
    let mut w = ipkt_core::ByteWriter::new();
    if len < 128 {
        w.write_u8(len as u8);
    } else if len < 256 {
        w.write_u8(0x81).write_u8(len as u8);
    } else {
        w.write_u8(0x82)
            .write_u8(((len >> 8) & 0xFF) as u8)
            .write_u8((len & 0xFF) as u8);
    }
    w.into_vec()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base_object: String,
    pub filter: String,
    pub scope: u8,
}

impl SearchRequest {
    pub fn encode(&self, message_id: i32) -> Vec<u8> {
        let mut search = Vec::new();
        search.extend(encode_octet_string(self.base_object.as_bytes()));
        search.extend(encode_enumerated(self.scope));
        search.extend(encode_enumerated(0));
        search.extend(encode_enumerated(0));
        search.extend(encode_enumerated(0));
        search.extend(encode_enumerated(0));
        search.extend(encode_octet_string(self.filter.as_bytes()));
        let mut seq = Vec::new();
        seq.extend(encode_integer(message_id));
        seq.extend(encode_enumerated(LdapOp::SearchRequest as u8));
        seq.extend(encode_sequence(&search));
        encode_sequence(&seq)
    }
}

pub fn decode_message_id(bytes: &[u8]) -> Result<i32> {
    let mut reader = ByteReader::new(bytes);
    if reader.read_u8()? != 0x30 {
        return Err(Error::Ber("expected SEQUENCE".into()));
    }
    let _ = read_len(&mut reader)?;
    let tag = reader.read_u8()?;
    if tag != 0x02 {
        return Err(Error::Ber(format!(
            "expected INTEGER message id, got {tag:#x}"
        )));
    }
    let len = read_len(&mut reader)?;
    let bytes = reader.read_bytes(len)?;
    let mut id = 0i32;
    for &b in bytes {
        id = (id << 8) | i32::from(b);
    }
    Ok(id)
}
