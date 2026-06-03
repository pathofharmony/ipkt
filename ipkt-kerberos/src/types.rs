#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Realm(pub String);

impl Realm {
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalName {
    pub name_type: u32,

    pub components: Vec<String>,
}

impl PrincipalName {
    #[must_use]
    pub fn new(name_type: u32, components: Vec<String>) -> Self {
        Self {
            name_type,
            components,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedData {
    pub etype: i32,

    pub kvno: Option<i32>,

    pub cipher: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub tkt_vno: u32,

    pub realm: Realm,

    pub sname: PrincipalName,

    pub enc_part: EncryptedData,
}
