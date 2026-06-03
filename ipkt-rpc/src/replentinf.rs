use crate::drsr::DrsUsnVector;
use crate::drsr_crypto::{decrypt_nt_hash_from_replication, decrypt_pek_entry};
use crate::drsr_parse::DrsUserSecret;
use crate::ndr_decode::{rid_from_sid, NdrDecoder};
use crate::prefix_table::{
    ATTID_DBCS_PWD, ATTID_PEK_LIST, ATTID_SAM_ACCOUNT_NAME, ATTID_UNICODE_PWD, PrefixEntry,
    PrefixTable,
};


#[derive(Debug, Clone)]
pub struct DrsGetNcChangesReplyV6 {
    pub uuid_dsa_obj_src: [u8; 16],
    pub uuid_invoc_id_src: [u8; 16],
    pub prefix_table_src: PrefixTable,
    pub ul_extended_ret: u32,
    pub c_num_objects: u32,
    pub f_more_data: bool,
    pub usnvec_to: DrsUsnVector,
    pub secrets: Vec<DrsUserSecret>,
    pub pek_list: Vec<[u8; 16]>,
}


pub fn decode_get_nc_changes_reply(stub: &[u8], session_key: &[u8]) -> Option<DrsGetNcChangesReplyV6> {
    let mut dec = NdrDecoder::new(stub);
    let out_version = dec.read_u32()?;
    let union_tag = dec.read_u32()?;
    let body_ptr = dec.read_ptr()?;
    let body_off = body_ptr as usize;
    let mut body = dec.at(body_off)?;
    match union_tag {
        6 | 8 => decode_reply_v6_body(&mut body, dec.data(), session_key, out_version),
        _ => None,
    }
}

fn decode_reply_v6_body(
    body: &mut NdrDecoder<'_>,
    data: &[u8],
    session_key: &[u8],
    out_version: u32,
) -> Option<DrsGetNcChangesReplyV6> {
    let uuid_dsa_obj_src = body.read_uuid()?;
    let uuid_invoc_id_src = body.read_uuid()?;
    let prefix_table_src = read_schema_prefix_table(body, data)?;
    let ul_extended_ret = body.read_u32()?;
    let c_num_objects = body.read_u32()?;
    let f_more_data = body.read_u32()? != 0;
    let objects_ptr = body.read_ptr();
    let usnvec_to = DrsUsnVector {
        usn_high_obj_update: body.read_u32()?,
        usn_reserved: body.read_u32()?,
        usn_high_prop_update: body.read_u32()?,
    };
    let _ = out_version;
    let mut secrets = Vec::new();
    let mut pek_list = Vec::new();
    if let Some(list_off) = objects_ptr {
        let list_secrets = decode_replentinflist(
            data,
            list_off as usize,
            &prefix_table_src,
            session_key,
            &mut pek_list,
        );
        secrets = list_secrets;
    }
    Some(DrsGetNcChangesReplyV6 {
        uuid_dsa_obj_src,
        uuid_invoc_id_src,
        prefix_table_src,
        ul_extended_ret,
        c_num_objects,
        f_more_data,
        usnvec_to,
        secrets,
        pek_list,
    })
}

/// `SCHEMA_PREFIX_TABLE` ([MS-DRSR] §5.16.4).
pub fn read_schema_prefix_table(dec: &mut NdrDecoder<'_>, data: &[u8]) -> Option<PrefixTable> {
    let count = dec.read_u32()?;
    let entries_ptr = dec.read_ptr();
    let mut table = PrefixTable::default();
    if count == 0 {
        return Some(table);
    }
    let Some(entries_off) = entries_ptr else {
        return Some(table);
    };
    let mut ent = NdrDecoder::new(data).at(entries_off as usize)?;
    let max_count = ent.read_u32()?;
    let offset = ent.read_u32()?;
    let actual = ent.read_u32()?;
    let _ = (max_count, offset);
    let n = actual.min(count);
    let mut entries = Vec::new();
    for ndx in 0..n {
        let _index = ent.read_u32()?;
        let plen = ent.read_u32()?;
        if plen > 0 && plen < 64 {
            let prefix = ent.read_bytes(plen as usize)?.to_vec();
            ent.align(4);
            entries.push(PrefixEntry { ndx, prefix });
        }
    }
    table.replace_entries(entries);
    Some(table)
}

fn decode_replentinflist(
    data: &[u8],
    list_off: usize,
    prefix: &PrefixTable,
    session_key: &[u8],
    pek_list: &mut Vec<[u8; 16]>,
) -> Vec<DrsUserSecret> {
    let mut by_rid = std::collections::BTreeMap::new();
    let mut off = list_off;
    let mut hops = 0u32;
    loop {
        if hops > 32_768 {
            break;
        }
        hops += 1;
        let mut node = match NdrDecoder::new(data).at(off) {
            Some(d) => d,
            None => break,
        };
        let next_ptr = node.read_ptr();
        let ent_ptr = node.read_ptr();
        if let Some(ent_off) = ent_ptr {
            if let Some(user) =
                decode_entinf(data, ent_off as usize, prefix, session_key, pek_list)
            {
                merge_user(&mut by_rid, user);
            }
        }
        match next_ptr {
            Some(next) if (next as usize) < data.len() => off = next as usize,
            _ => break,
        }
    }
    by_rid.into_values().collect()
}

fn decode_entinf(
    data: &[u8],
    off: usize,
    prefix: &PrefixTable,
    session_key: &[u8],
    pek_list: &mut Vec<[u8; 16]>,
) -> Option<DrsUserSecret> {
    decode_entinf_layout(data, off, EntinfLayout::NameFlagsAttr, prefix, session_key, pek_list)
        .or_else(|| {
            decode_entinf_layout(data, off, EntinfLayout::AttrFlagsName, prefix, session_key, pek_list)
        })
        .or_else(|| {
            decode_entinf_layout(data, off, EntinfLayout::FlagsAttrOnly, prefix, session_key, pek_list)
        })
}

#[derive(Clone, Copy)]
enum EntinfLayout {
    
    NameFlagsAttr,
    
    AttrFlagsName,
    
    FlagsAttrOnly,
}

fn decode_entinf_layout(
    data: &[u8],
    off: usize,
    layout: EntinfLayout,
    prefix: &PrefixTable,
    session_key: &[u8],
    pek_list: &mut Vec<[u8; 16]>,
) -> Option<DrsUserSecret> {
    let mut dec = NdrDecoder::new(data).at(off)?;
    match layout {
        EntinfLayout::NameFlagsAttr => {
            let _name_ptr = dec.read_ptr();
            let _ul_flags = dec.read_u32()?;
            decode_attrblock(&mut dec, data, prefix, session_key, pek_list)
        }
        EntinfLayout::AttrFlagsName => {
            if let Some(user) = decode_attrblock(&mut dec, data, prefix, session_key, pek_list) {
                return Some(user);
            }
            let mut tail = NdrDecoder::new(data).at(off)?;
            let _ = decode_attrblock(&mut tail, data, prefix, session_key, pek_list)?;
            let _name_ptr = tail.read_ptr();
            let _ul_flags = tail.read_u32();
            None
        }
        EntinfLayout::FlagsAttrOnly => {
            let flags = dec.read_u32()?;
            let _ = flags;
            decode_attrblock(&mut dec, data, prefix, session_key, pek_list)
        }
    }
}

fn decode_attrblock(
    dec: &mut NdrDecoder<'_>,
    data: &[u8],
    prefix: &PrefixTable,
    session_key: &[u8],
    pek_list: &mut Vec<[u8; 16]>,
) -> Option<DrsUserSecret> {
    let attr_count = dec.read_u32()?;
    let attr_ptr = dec.read_ptr();
    if attr_count == 0 {
        return None;
    }
    let mut user = DrsUserSecret {
        username: String::new(),
        rid: 0,
        lm_hash: None,
        nt_hash: None,
    };
    let attr_base = attr_ptr? as usize;
    let mut attr_dec = NdrDecoder::new(data).at(attr_base)?;
    let max_count = attr_dec.read_u32()?;
    let offset = attr_dec.read_u32()?;
    let actual = attr_dec.read_u32()?;
    let _ = (max_count, offset);
    for _ in 0..actual.min(attr_count) {
        let attr_typ = attr_dec.read_u32()?;
        let val_count = attr_dec.read_u32()?;
        let aval_ptr = attr_dec.read_ptr();
        let attid = prefix.resolve_attid(attr_typ);
        if val_count == 0 {
            continue;
        }
        let Some(blob) = read_attrval(data, aval_ptr, val_count) else {
            continue;
        };
        match attid {
            ATTID_UNICODE_PWD => {
                if user.rid != 0 {
                    user.nt_hash =
                        decrypt_nt_hash_from_replication(session_key, user.rid, &blob, pek_list);
                }
            }
            ATTID_DBCS_PWD => {
                if user.rid != 0 {
                    user.lm_hash =
                        decrypt_nt_hash_from_replication(session_key, user.rid, &blob, pek_list);
                }
            }
            ATTID_SAM_ACCOUNT_NAME => user.username = decode_utf16(&blob).unwrap_or_default(),
            id if id == crate::prefix_table::ATTID_OBJECT_SID => {
                user.rid = rid_from_sid(&blob).unwrap_or(0);
            }
            ATTID_PEK_LIST => {
                if let Some(pek) = decrypt_pek_entry(session_key, &blob) {
                    pek_list.push(pek);
                }
            }
            _ => {}
        }
    }
    if user.nt_hash.is_some() || user.lm_hash.is_some() || !user.username.is_empty() {
        Some(user)
    } else {
        None
    }
}

fn read_attrval(data: &[u8], ptr: Option<u32>, val_count: u32) -> Option<Vec<u8>> {
    let off = ptr? as usize;
    let mut dec = NdrDecoder::new(data).at(off)?;
    let max_vals = dec.read_u32()?;
    let offset = dec.read_u32()?;
    let actual = dec.read_u32()?;
    let _ = (max_vals, offset);
    if actual == 0 || val_count == 0 {
        return None;
    }
    let pval = dec.read_ptr();
    if let Some(poff) = pval {
        let mut inner = NdrDecoder::new(data).at(poff as usize)?;
        return inner.read_conformant_octets();
    }
    dec.read_conformant_octets()
}

fn decode_utf16(blob: &[u8]) -> Option<String> {
    if blob.len() < 2 || blob.len() % 2 != 0 {
        return None;
    }
    let mut units = Vec::new();
    for chunk in blob.chunks_exact(2) {
        let u = u16::from_le_bytes([chunk[0], chunk[1]]);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16(&units).ok()
}

pub(crate) fn merge_user(map: &mut std::collections::BTreeMap<u32, DrsUserSecret>, user: DrsUserSecret) {
    let rid = user.rid;
    if rid == 0 {
        return;
    }
    map.entry(rid)
        .and_modify(|e| {
            if user.nt_hash.is_some() {
                e.nt_hash = user.nt_hash;
            }
            if user.lm_hash.is_some() {
                e.lm_hash = user.lm_hash;
            }
            if e.username.is_empty() && !user.username.is_empty() {
                e.username = user.username.clone();
            }
        })
        .or_insert(user);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usn_vector_read_from_v6_tail() {
        let body_off = 12usize;
        let mut stub = vec![0u8; body_off + 80];
        stub[0..4].copy_from_slice(&1u32.to_le_bytes());
        stub[4..8].copy_from_slice(&6u32.to_le_bytes());
        stub[8..12].copy_from_slice(&(body_off as u32).to_le_bytes());
        let b = &mut stub[body_off..];
        b[0..16].copy_from_slice(&[0x11; 16]);
        b[16..32].copy_from_slice(&[0x22; 16]);
        let mut o = 32usize;
        b[o..o + 4].copy_from_slice(&0u32.to_le_bytes()); // prefix count
        o += 4;
        b[o..o + 4].copy_from_slice(&0u32.to_le_bytes()); // prefix ptr
        o += 4;
        o += 16; // extended, num, more, objects ptr
        b[o..o + 4].copy_from_slice(&100u32.to_le_bytes());
        b[o + 4..o + 8].copy_from_slice(&0u32.to_le_bytes());
        b[o + 8..o + 12].copy_from_slice(&200u32.to_le_bytes());
        let reply = decode_get_nc_changes_reply(&stub, &[0u8; 16]).expect("v6");
        assert_eq!(reply.usnvec_to.usn_high_obj_update, 100);
        assert_eq!(reply.usnvec_to.usn_high_prop_update, 200);
    }
}
