use ipkt_core::ByteReader;

use crate::asn1::{
    decode_general_string, decode_integer, encode_application, encode_context,
    encode_general_string, encode_integer, encode_sequence,
};
use crate::types::{PrincipalName, Realm};
use crate::Result;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdcReqBody {
    
    pub kdc_options: u32,
    
    pub cname: PrincipalName,
    
    pub realm: Realm,
    
    pub sname: Option<PrincipalName>,
    
    pub nonce: u32,
    
    pub etype: Vec<i32>,
}

fn encode_principal(name: &PrincipalName) -> Vec<u8> {
    let mut parts = Vec::new();
    parts.extend(encode_context(0, &encode_integer(name.name_type)));
    let mut strings = Vec::new();
    for c in &name.components {
        strings.extend(encode_sequence(&encode_general_string(c)));
    }
    parts.extend(encode_context(1, &encode_sequence(&strings)));
    encode_sequence(&parts)
}

fn encode_kdc_req_body(body: &KdcReqBody) -> Vec<u8> {
    let mut inner = Vec::new();
    inner.extend(encode_context(0, &encode_integer(body.kdc_options)));
    inner.extend(encode_context(1, &encode_principal(&body.cname)));
    inner.extend(encode_context(
        2,
        &encode_general_string(body.realm.as_str()),
    ));
    if let Some(sname) = &body.sname {
        inner.extend(encode_context(3, &encode_principal(sname)));
    }
    inner.extend(encode_context(7, &encode_integer(body.nonce)));
    let mut etypes = Vec::new();
    for &e in &body.etype {
        etypes.extend(encode_integer(e as u32));
    }
    inner.extend(encode_context(8, &encode_sequence(&etypes)));
    encode_sequence(&inner)
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsReq {
    
    pub pvno: u32,
    
    pub msg_type: u32,
    
    pub req_body: KdcReqBody,
}


pub fn encode_as_req(req: &AsReq) -> Result<Vec<u8>> {
    encode_as_req_with_padata(req, None)
}


pub fn encode_as_req_with_padata(req: &AsReq, padata: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut kdc = Vec::new();
    kdc.extend(encode_context(1, &encode_integer(req.pvno)));
    kdc.extend(encode_context(2, &encode_integer(req.msg_type)));
    if let Some(pa) = padata {
        kdc.extend(encode_context(3, pa));
    }
    kdc.extend(encode_context(4, &encode_kdc_req_body(&req.req_body)));
    let seq = encode_sequence(&kdc);
    Ok(encode_application(10, &seq))
}


pub fn decode_as_req(bytes: &[u8]) -> Result<AsReq> {
    let mut reader = ByteReader::new(bytes);
    let app_tag = reader.read_u8()?;
    if app_tag != 0x6A {
        return Err(crate::Error::Der(format!(
            "expected APPLICATION 10, got {app_tag:#x}"
        )));
    }
    let app_len = crate::asn1::read_length(&mut reader)?;
    let app_body = reader.read_bytes(app_len)?;
    let mut seq_reader = ByteReader::new(app_body);
    if seq_reader.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected inner SEQUENCE".into()));
    }
    let seq_len = crate::asn1::read_length(&mut seq_reader)?;
    let seq_body = seq_reader.read_bytes(seq_len)?;
    let mut r = ByteReader::new(seq_body);
    let mut pvno = 5u32;
    let mut msg_type = 10u32;
    let mut req_body = None;
    while !r.is_empty() {
        let tag = r.read_u8()?;
        let len = crate::asn1::read_length(&mut r)?;
        let chunk = r.read_bytes(len)?;
        match tag {
            0xA1 => {
                let mut inner = ByteReader::new(chunk);
                pvno = decode_integer(&mut inner)?;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                msg_type = decode_integer(&mut inner)?;
            }
            0xA4 => req_body = Some(decode_kdc_req_body(chunk)?),
            _ => {}
        }
    }
    Ok(AsReq {
        pvno,
        msg_type,
        req_body: req_body
            .ok_or_else(|| crate::Error::InvalidMessage("missing req_body".into()))?,
    })
}

fn decode_kdc_req_body(bytes: &[u8]) -> Result<KdcReqBody> {
    let mut reader = ByteReader::new(bytes);
    let seq = reader.read_u8()?;
    if seq != 0x30 {
        return Err(crate::Error::Der("expected SEQUENCE".into()));
    }
    let _ = crate::asn1::read_length(&mut reader)?;
    let mut kdc_options = 0u32;
    let mut cname = PrincipalName::new(1, vec!["user".into()]);
    let mut realm = Realm::new("EXAMPLE.COM");
    let mut sname = None;
    let mut nonce = 0u32;
    let mut etype = Vec::new();
    while !reader.is_empty() {
        let ctx = reader.read_u8()?;
        let len = crate::asn1::read_length(&mut reader)?;
        let chunk = reader.read_bytes(len)?;
        match ctx {
            0xA0 => {
                let mut inner = ByteReader::new(chunk);
                kdc_options = decode_integer(&mut inner)?;
            }
            0xA1 => cname = decode_principal(chunk)?,
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                realm = Realm::new(decode_general_string(&mut inner)?);
            }
            0xA3 => sname = Some(decode_principal(chunk)?),
            0xA7 => {
                let mut inner = ByteReader::new(chunk);
                nonce = decode_integer(&mut inner)?;
            }
            0xA8 => {
                let mut inner = ByteReader::new(chunk);
                let _seq = inner.read_u8()?;
                let elen = crate::asn1::read_length(&mut inner)?;
                let mut er = ByteReader::new(inner.read_bytes(elen)?);
                while !er.is_empty() {
                    etype.push(decode_integer(&mut er)? as i32);
                }
            }
            _ => {}
        }
    }
    Ok(KdcReqBody {
        kdc_options,
        cname,
        realm,
        sname,
        nonce,
        etype,
    })
}

fn decode_principal(bytes: &[u8]) -> Result<PrincipalName> {
    let mut reader = ByteReader::new(bytes);
    let _ = reader.read_u8()?;
    let _ = crate::asn1::read_length(&mut reader)?;
    let mut name_type = 1u32;
    let mut components = Vec::new();
    while !reader.is_empty() {
        let ctx = reader.read_u8()?;
        let len = crate::asn1::read_length(&mut reader)?;
        let mut inner = ByteReader::new(reader.read_bytes(len)?);
        if ctx == 0xA0 {
            name_type = decode_integer(&mut inner)?;
        } else if ctx == 0xA1 {
            let _ = inner.read_u8()?;
            let slen = crate::asn1::read_length(&mut inner)?;
            let mut sr = ByteReader::new(inner.read_bytes(slen)?);
            while !sr.is_empty() {
                let _ = sr.read_u8()?;
                let plen = crate::asn1::read_length(&mut sr)?;
                let mut pr = ByteReader::new(sr.read_bytes(plen)?);
                components.push(decode_general_string(&mut pr)?);
            }
        }
    }
    Ok(PrincipalName::new(name_type, components))
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TgsReq {
    pub pvno: u32,
    pub msg_type: u32,
    pub req_body: KdcReqBody,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsRep {
    pub pvno: u32,
    pub msg_type: u32,
    pub crealm: Realm,
    pub cname: PrincipalName,
    pub ticket: Vec<u8>,
    pub enc_part: Vec<u8>,
}


pub fn encode_as_rep(rep: &AsRep) -> Result<Vec<u8>> {
    let mut kdc = Vec::new();
    kdc.extend(encode_context(1, &encode_integer(rep.pvno)));
    kdc.extend(encode_context(2, &encode_integer(rep.msg_type)));
    kdc.extend(encode_context(
        3,
        &encode_general_string(rep.crealm.as_str()),
    ));
    kdc.extend(encode_context(4, &encode_principal(&rep.cname)));
    kdc.extend(encode_context(5, &rep.ticket));
    kdc.extend(encode_context(6, &rep.enc_part));
    Ok(encode_application(11, &encode_sequence(&kdc)))
}


pub fn decode_as_rep(bytes: &[u8]) -> Result<AsRep> {
    let mut reader = ByteReader::new(bytes);
    let app_tag = reader.read_u8()?;
    if app_tag != 0x6B {
        return Err(crate::Error::Der(format!(
            "expected APPLICATION 11, got {app_tag:#x}"
        )));
    }
    let app_len = crate::asn1::read_length(&mut reader)?;
    let app_body = reader.read_bytes(app_len)?;
    let mut r = ByteReader::new(app_body);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected SEQUENCE".into()));
    }
    let slen = crate::asn1::read_length(&mut r)?;
    let seq = r.read_bytes(slen)?;
    let mut sr = ByteReader::new(seq);
    let mut pvno = 5u32;
    let mut msg_type = 11u32;
    let mut crealm = Realm::new("EXAMPLE.COM");
    let mut cname = PrincipalName::new(1, vec!["user".into()]);
    let mut ticket = Vec::new();
    let mut enc_part = Vec::new();
    while !sr.is_empty() {
        let tag = sr.read_u8()?;
        let len = crate::asn1::read_length(&mut sr)?;
        let chunk = sr.read_bytes(len)?;
        match tag {
            0xA1 => {
                let mut inner = ByteReader::new(chunk);
                pvno = decode_integer(&mut inner)?;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                msg_type = decode_integer(&mut inner)?;
            }
            0xA3 => {
                let mut inner = ByteReader::new(chunk);
                crealm = Realm::new(decode_general_string(&mut inner)?);
            }
            0xA4 => cname = decode_principal(chunk)?,
            0xA5 => ticket = chunk.to_vec(),
            0xA6 => enc_part = chunk.to_vec(),
            _ => {}
        }
    }
    Ok(AsRep {
        pvno,
        msg_type,
        crealm,
        cname,
        ticket,
        enc_part,
    })
}


pub type TgsRep = AsRep;


pub fn encode_tgs_req_with_padata(req: &TgsReq, padata: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut kdc = Vec::new();
    kdc.extend(encode_context(1, &encode_integer(req.pvno)));
    kdc.extend(encode_context(2, &encode_integer(req.msg_type)));
    if let Some(pa) = padata {
        kdc.extend(encode_context(3, pa));
    }
    kdc.extend(encode_context(4, &encode_kdc_req_body(&req.req_body)));
    Ok(encode_application(12, &encode_sequence(&kdc)))
}


pub fn encode_tgs_req(req: &TgsReq) -> Result<Vec<u8>> {
    encode_tgs_req_with_padata(req, None)
}


pub fn decode_tgs_rep(bytes: &[u8]) -> Result<TgsRep> {
    let mut reader = ByteReader::new(bytes);
    let app_tag = reader.read_u8()?;
    if app_tag != 0x6D {
        return Err(crate::Error::Der(format!(
            "expected APPLICATION 13, got {app_tag:#x}"
        )));
    }
    let app_len = crate::asn1::read_length(&mut reader)?;
    let app_body = reader.read_bytes(app_len)?;
    let mut r = ByteReader::new(app_body);
    if r.read_u8()? != 0x30 {
        return Err(crate::Error::Der("expected SEQUENCE".into()));
    }
    let slen = crate::asn1::read_length(&mut r)?;
    let seq = r.read_bytes(slen)?;
    let mut sr = ByteReader::new(seq);
    let mut pvno = 5u32;
    let mut msg_type = 13u32;
    let mut crealm = Realm::new("EXAMPLE.COM");
    let mut cname = PrincipalName::new(1, vec!["user".into()]);
    let mut ticket = Vec::new();
    let mut enc_part = Vec::new();
    while !sr.is_empty() {
        let tag = sr.read_u8()?;
        let len = crate::asn1::read_length(&mut sr)?;
        let chunk = sr.read_bytes(len)?;
        match tag {
            0xA1 => {
                let mut inner = ByteReader::new(chunk);
                pvno = decode_integer(&mut inner)?;
            }
            0xA2 => {
                let mut inner = ByteReader::new(chunk);
                msg_type = decode_integer(&mut inner)?;
            }
            0xA3 => {
                let mut inner = ByteReader::new(chunk);
                crealm = Realm::new(decode_general_string(&mut inner)?);
            }
            0xA4 => cname = decode_principal(chunk)?,
            0xA5 => ticket = chunk.to_vec(),
            0xA6 => enc_part = chunk.to_vec(),
            _ => {}
        }
    }
    Ok(TgsRep {
        pvno,
        msg_type,
        crealm,
        cname,
        ticket,
        enc_part,
    })
}
