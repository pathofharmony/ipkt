const OID_SPNEGO: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

const OID_KRB5: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];

#[must_use]
pub fn neg_token_init_spnego() -> Vec<u8> {
    vec![0x60, 0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
}

#[must_use]
pub fn neg_token_init_kerberos(ap_req: &[u8]) -> Vec<u8> {
    let mech_list = encode_sequence(&[encode_oid(OID_KRB5)]);
    let mech_token = encode_context0_octet_string(ap_req);
    let neg_token = encode_sequence(&[encode_context0(&mech_list), encode_context2(&mech_token)]);
    let app_choice = encode_sequence(&[
        encode_context0(&encode_oid(OID_SPNEGO)),
        encode_context1(&neg_token),
    ]);
    let mut out = vec![0x60];
    out.extend(encode_length(app_choice.len()));
    out.extend(app_choice);
    out
}

#[must_use]
pub fn gssapi_sasl_credentials() -> Vec<u8> {
    neg_token_init_spnego()
}

#[must_use]
pub fn gssapi_kerberos_credentials(ap_req: &[u8]) -> Vec<u8> {
    neg_token_init_kerberos(ap_req)
}

#[must_use]
pub fn neg_token_resp_kerberos(ap_rep: &[u8]) -> Vec<u8> {
    let response_token = encode_context2_octet_string(ap_rep);
    let neg_token = encode_sequence(&[encode_context1(&response_token)]);
    let app_choice = encode_sequence(&[encode_context1(&neg_token)]);
    let mut out = vec![0x60];
    out.extend(encode_length(app_choice.len()));
    out.extend(app_choice);
    out
}

#[must_use]
pub fn gssapi_kerberos_response(ap_rep: &[u8]) -> Vec<u8> {
    neg_token_resp_kerberos(ap_rep)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTokenTarg {
    pub neg_result: Option<u8>,

    pub response_token: Option<Vec<u8>>,
}

pub fn parse_neg_token_targ(spnego: &[u8]) -> Option<NegTokenTarg> {
    let neg_result = find_context_tag_enum(spnego, 0xA0);
    let response_token =
        find_context_tag_octets(spnego, 0xA2).or_else(|| find_application_token(spnego, 0x6e));
    if neg_result.is_none() && response_token.is_none() {
        return None;
    }
    Some(NegTokenTarg {
        neg_result,
        response_token,
    })
}

pub fn extract_krb5_token_from_neg_token(spnego: &[u8]) -> Option<Vec<u8>> {
    parse_neg_token_targ(spnego)
        .and_then(|t| t.response_token)
        .or_else(|| find_context_tag_octets(spnego, 0xA2))
}

fn find_application_token(data: &[u8], app_tag: u8) -> Option<Vec<u8>> {
    let mut i = 0usize;
    while i < data.len() {
        if data.get(i) == Some(&app_tag) {
            let (len, hdr) = read_der_len(data, i + 1)?;
            let start = i + 1 + hdr;
            if start + len <= data.len() {
                let mut out = vec![app_tag];
                out.extend(encode_length(len));
                out.extend_from_slice(&data[start..start + len]);
                return Some(out);
            }
        }
        let tag = *data.get(i)?;
        i += 1;
        let (len, hdr) = read_der_len(data, i)?;
        i += hdr;
        if i + len <= data.len() {
            if tag == 0x30 || tag == 0xA0 || tag == 0xA1 || tag == 0xA2 || tag == 0x60 {
                if let Some(inner) = find_application_token(&data[i..i + len], app_tag) {
                    return Some(inner);
                }
            }
            i += len;
        } else {
            break;
        }
    }
    None
}

fn find_context_tag_enum(data: &[u8], want_tag: u8) -> Option<u8> {
    let body = find_tag_body(data, want_tag)?;
    body.first().copied()
}

fn find_context_tag_octets(data: &[u8], want_tag: u8) -> Option<Vec<u8>> {
    let body = find_tag_body(data, want_tag)?;
    extract_octet_string(body).or_else(|| Some(body.to_vec()))
}

fn find_tag_body(data: &[u8], want_tag: u8) -> Option<&[u8]> {
    let mut i = 0usize;
    while i < data.len() {
        let tag = *data.get(i)?;
        i += 1;
        let (len, hdr) = read_der_len(data, i)?;
        i += hdr;
        if i + len > data.len() {
            break;
        }
        let body = &data[i..i + len];
        if tag == want_tag {
            return Some(body);
        }
        if tag == 0x30 || tag == 0xA0 || tag == 0xA1 || tag == 0xA2 || tag == 0x60 {
            if let Some(found) = find_tag_body(body, want_tag) {
                return Some(found);
            }
        }
        i += len;
    }
    None
}

fn encode_context2_octet_string(data: &[u8]) -> Vec<u8> {
    let mut oct = vec![0x04];
    oct.extend(encode_length(data.len()));
    oct.extend_from_slice(data);
    encode_context2(&oct)
}

fn extract_octet_string(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() == Some(&0x04) {
        let (len, hdr) = read_der_len(data, 1)?;
        return Some(data.get(hdr + 1..hdr + 1 + len)?.to_vec());
    }
    None
}

fn read_der_len(data: &[u8], off: usize) -> Option<(usize, usize)> {
    let first = *data.get(off)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 1 {
        return Some((usize::from(*data.get(off + 1)?), 2));
    }
    if n == 2 {
        let hi = usize::from(*data.get(off + 1)?);
        let lo = usize::from(*data.get(off + 2)?);
        return Some(((hi << 8) | lo, 3));
    }
    None
}

fn encode_oid(oid_body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    out.extend(encode_length(oid_body.len()));
    out.extend_from_slice(oid_body);
    out
}

fn encode_context0(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0];
    out.extend(encode_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn encode_context1(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa1];
    out.extend(encode_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn encode_context2(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa2];
    out.extend(encode_length(inner.len()));
    out.extend_from_slice(inner);
    out
}

fn encode_context0_octet_string(data: &[u8]) -> Vec<u8> {
    let mut oct = vec![0x04];
    oct.extend(encode_length(data.len()));
    oct.extend_from_slice(data);
    encode_context0(&oct)
}

fn encode_sequence(children: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = children.iter().flatten().copied().collect();
    let mut out = vec![0x30];
    out.extend(encode_length(payload.len()));
    out.extend(payload);
    out
}

fn encode_length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xFF) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn krb5_neg_token_starts_with_gssapi_wrapper() {
        let token = neg_token_init_kerberos(&[0x6e, 0x82, 0x01, 0x00]);
        assert_eq!(token[0], 0x60);
        assert!(token.windows(9).any(|w| w == OID_KRB5));
    }
}
