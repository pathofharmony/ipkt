pub const ATTID_UNICODE_PWD: u32 = 589_914;
pub const ATTID_DBCS_PWD: u32 = 589_879;
pub const ATTID_SAM_ACCOUNT_NAME: u32 = 590_689;
pub const ATTID_OBJECT_SID: u32 = 590_610;
pub const ATTID_USER_PRINCIPAL_NAME: u32 = 590_480;

pub const ATTID_PEK_LIST: u32 = 589_921;


pub const OID_UNICODE_PWD: &str = "1.2.840.113556.1.4.90";
pub const OID_DBCS_PWD: &str = "1.2.840.113556.1.4.55";
pub const OID_SAM_ACCOUNT_NAME: &str = "1.2.840.113556.1.4.221";
pub const OID_OBJECT_SID: &str = "1.2.840.113556.1.4.146";
pub const OID_USER_PRINCIPAL_NAME: &str = "1.2.840.113556.1.4.656";


pub const DEFAULT_REPL_ATTIDS: &[(&str, u32)] = &[
    (OID_UNICODE_PWD, ATTID_UNICODE_PWD),
    (OID_DBCS_PWD, ATTID_DBCS_PWD),
    (OID_SAM_ACCOUNT_NAME, ATTID_SAM_ACCOUNT_NAME),
    (OID_OBJECT_SID, ATTID_OBJECT_SID),
    (OID_USER_PRINCIPAL_NAME, ATTID_USER_PRINCIPAL_NAME),
];


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrefixEntry {
    pub ndx: u32,
    pub prefix: Vec<u8>,
}


#[derive(Debug, Default, Clone)]
pub struct PrefixTable {
    entries: Vec<PrefixEntry>,
}

impl PrefixTable {
    
    pub fn replace_entries(&mut self, entries: Vec<PrefixEntry>) {
        self.entries = entries;
    }

    
    pub fn default_repl_attr_typs(&mut self) -> Vec<u32> {
        DEFAULT_REPL_ATTIDS
            .iter()
            .map(|(oid, _)| make_attid(self, oid))
            .collect()
    }

    
    pub fn resolve_attid(&self, attr_typ: u32) -> u32 {
        oid_from_attid(self, attr_typ).unwrap_or(attr_typ)
    }
}


#[must_use]
pub fn ber_oid_body(oid: &str) -> Vec<u8> {
    let nums: Vec<u32> = oid
        .split('.')
        .filter_map(|p| p.parse().ok())
        .collect();
    if nums.len() < 2 {
        return Vec::new();
    }
    let mut out = vec![(40 * nums[0] + nums[1]) as u8];
    for &p in &nums[2..] {
        encode_base128(p, &mut out);
    }
    out
}

fn encode_base128(mut value: u32, out: &mut Vec<u8>) {
    let mut stack = Vec::new();
    loop {
        stack.push((value & 0x7F) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }
    for (i, b) in stack.iter().rev().enumerate() {
        let mut byte = *b;
        if i + 1 < stack.len() {
            byte |= 0x80;
        }
        out.push(byte);
    }
}


pub fn make_attid(table: &mut PrefixTable, oid: &str) -> u32 {
    let last_value: u32 = oid.rsplit('.').next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let binary = ber_oid_body(oid);
    let oid_prefix = if last_value < 128 {
        binary[..binary.len().saturating_sub(1)].to_vec()
    } else {
        binary[..binary.len().saturating_sub(2)].to_vec()
    };

    let mut pos = table.entries.len() as u32;
    for (j, entry) in table.entries.iter().enumerate() {
        if entry.prefix == oid_prefix {
            pos = j as u32;
            break;
        }
    }
    if pos == table.entries.len() as u32 {
        table.entries.push(PrefixEntry {
            ndx: pos,
            prefix: oid_prefix,
        });
    }

    let mut lower = last_value % 16_384;
    if last_value >= 16_384 {
        lower += 32_768;
    }
    (pos << 16) | lower
}


pub fn oid_from_attid(table: &PrefixTable, attr_typ: u32) -> Option<u32> {
    let upper = attr_typ >> 16;
    let mut lower = attr_typ & 0xFFFF;
    if lower >= 32_768 {
        lower -= 32_768;
    }
    let entry = table.entries.get(upper as usize)?;
    let mut oid_bytes = entry.prefix.clone();
    if lower < 128 {
        oid_bytes.push(lower as u8);
    } else {
        encode_base128(lower, &mut oid_bytes);
    }
    attid_from_ber_oid_tail(&oid_bytes)
}

fn attid_from_ber_oid_tail(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut parts: Vec<u32> = Vec::new();
    let first = bytes[0];
    parts.push(u32::from(first / 40));
    parts.push(u32::from(first % 40));
    let mut i = 1usize;
    while i < bytes.len() {
        let mut v = 0u32;
        loop {
            if i >= bytes.len() {
                break;
            }
            let b = bytes[i];
            i += 1;
            v = (v << 7) | u32::from(b & 0x7F);
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(v);
    }
    let last = *parts.last()?;
    for (oid, attid) in DEFAULT_REPL_ATTIDS {
        if oid.rsplit('.').next().and_then(|s| s.parse().ok()) == Some(last) {
            return Some(*attid);
        }
    }
    Some(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_attid_round_trip_unicode_pwd() {
        let mut table = PrefixTable::default();
        let wire = make_attid(&mut table, OID_UNICODE_PWD);
        let attid = oid_from_attid(&table, wire).unwrap();
        assert_eq!(attid, ATTID_UNICODE_PWD);
    }
}
