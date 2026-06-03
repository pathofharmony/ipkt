#![allow(missing_docs)]
use ipkt_kerberos::{build_pa_enc_timestamp, encode_pa_enc_timestamp};

#[test]
fn pa_enc_timestamp_round_trips_encode() {
    let enc = build_pa_enc_timestamp("password", "EXAMPLE.COM", "user", 1_234_567, 0).unwrap();
    let der = encode_pa_enc_timestamp(&enc);
    assert!(!der.is_empty());
    assert_eq!(enc.etype, 18);
}
