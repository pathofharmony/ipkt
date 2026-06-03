pub const ETYPE_AES256_CTS_HMAC_SHA1_96: i32 = 18;


#[must_use]
pub fn n_fold(length: usize, data: &[u8]) -> Vec<u8> {
    let lcm = lcm(data.len(), length);
    let mut out = vec![0u8; length];
    let mut sum = 0usize;
    while sum < lcm {
        for (i, &b) in data.iter().enumerate() {
            let idx = (sum + i) % length;
            out[idx] ^= b;
        }
        sum += data.len();
    }
    out
}

fn lcm(a: usize, b: usize) -> usize {
    a * b / gcd(a, b)
}

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}


pub fn string2key_aes256(
    password: &str,
    salt: &[u8],
    params: Option<&[u8]>,
) -> crate::Result<[u8; 32]> {
    let t_iter = params
        .and_then(|p| {
            if p.len() >= 4 {
                Some(u32::from_be_bytes(p[..4].try_into().ok()?))
            } else {
                None
            }
        })
        .unwrap_or(4096);
    crate::aes_cts::string2key_aes256(password, salt, t_iter)
}

