use ipkt_core::Pack;
use ipkt_ntlm::avpair::{AvId, AvPair, TargetInfo};
use ipkt_ntlm::crypto::*;
use ipkt_ntlm::NegotiateFlags;



const USER: &str = "User";
const DOMAIN: &str = "Domain";
const PASSWORD: &str = "Password";
const SERVER_CHALLENGE: Challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const CLIENT_CHALLENGE: Challenge = [0xaa; 8];

fn hexa(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex literal")
}



#[test]
fn ntowf_v1_matches_spec() {
    
    assert_eq!(
        ntowf_v1(PASSWORD).to_vec(),
        hexa("a4f49c406510bdcab6824ee7c30fd852")
    );
}

#[test]
fn lmowf_v1_matches_spec() {
    
    assert_eq!(
        lmowf_v1(PASSWORD).to_vec(),
        hexa("e52cac67419a9a224a3b108f3fa6cb6d")
    );
}

#[test]
fn ntlm_v1_session_base_key_matches_spec() {
    
    let nt = ntowf_v1(PASSWORD);
    assert_eq!(
        ntlm_v1_session_base_key(&nt).to_vec(),
        hexa("d87262b0cde4b1cb7499becccdf10784")
    );
}

#[test]
fn ntlm_v1_responses_match_spec() {
    let nt = ntowf_v1(PASSWORD);
    let lm = lmowf_v1(PASSWORD);

    
    assert_eq!(
        ntlm_v1_response(&nt, &SERVER_CHALLENGE).to_vec(),
        hexa("67c43011f30298a2ad35ece64f16331c44bdbed927841f94")
    );
    
    assert_eq!(
        lm_v1_response(&lm, &SERVER_CHALLENGE).to_vec(),
        hexa("98def7b87f88aa5dafe2df779688a172def11c7d5ccdef13")
    );
}



#[test]
fn ntlm_v1_extended_session_security_matches_spec() {
    let nt = ntowf_v1(PASSWORD);
    let (lm, nt_resp) = ntlm_v1_extended_response(&nt, &SERVER_CHALLENGE, &CLIENT_CHALLENGE);

    
    assert_eq!(
        lm.to_vec(),
        hexa("aaaaaaaaaaaaaaaa00000000000000000000000000000000")
    );
    
    assert_eq!(
        nt_resp.to_vec(),
        hexa("7537f803ae367128ca458204bde7caf81e97ed2683267232")
    );
}





fn spec_target_info() -> TargetInfo {
    TargetInfo::new()
        .with(AvPair::string(AvId::NbDomainName, "Domain"))
        .with(AvPair::string(AvId::NbComputerName, "Server"))
}

#[test]
fn spec_target_info_serializes_exactly() {
    
    let expected = hexa(concat!(
        "02000c00",
        "44006f006d00610069006e00", 
        "01000c00",
        "530065007200760065007200", 
        "00000000",                 
    ));
    assert_eq!(spec_target_info().pack(), expected);
}

#[test]
fn ntowf_v2_matches_spec() {
    
    let expected = hexa("0c868a403bfd7a93a3001ef22ef02e3f");
    assert_eq!(ntowf_v2(PASSWORD, USER, DOMAIN).to_vec(), expected);
    assert_eq!(lmowf_v2(PASSWORD, USER, DOMAIN).to_vec(), expected);
}

#[test]
fn ntlm_v2_proof_and_session_key_match_spec() {
    let response_key = ntowf_v2(PASSWORD, USER, DOMAIN);
    let target_info = spec_target_info().pack();

    let response = ntlm_v2_response(
        &response_key,
        &SERVER_CHALLENGE,
        &CLIENT_CHALLENGE,
        0, 
        &target_info,
    );

    
    assert_eq!(
        response.proof().to_vec(),
        hexa("68cd0ab851e51c96aabc927bebef6a1c")
    );

    
    assert_eq!(
        response.session_base_key().to_vec(),
        hexa("8de40ccadbc14a82f15cb0ad0de95ca3")
    );

    
    
    let full = response.nt_challenge_response();
    assert_eq!(&full[..16], response.proof());
    assert_eq!(&full[16..18], &[0x01, 0x01]);
}

#[test]
fn lm_v2_response_matches_spec() {
    let response_key = ntowf_v2(PASSWORD, USER, DOMAIN);
    
    assert_eq!(
        lm_v2_response(&response_key, &SERVER_CHALLENGE, &CLIENT_CHALLENGE).to_vec(),
        hexa("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
    );
}



#[test]
fn rc4_is_symmetric() {
    let key = b"sixteen byte key";
    let plaintext = b"the quick brown fox";
    let ciphertext = rc4(key, plaintext);
    assert_ne!(ciphertext, plaintext);
    assert_eq!(rc4(key, &ciphertext), plaintext);
}

#[test]
fn rc4_matches_known_answer() {
    
    let ct = rc4(b"Key", b"Plaintext");
    assert_eq!(ct, hexa("bbf316e8d940af0ad3"));
}

#[test]
fn sealed_session_key_unwraps_with_rc4() {
    let kek = [0x55u8; 16];
    let exported = [0x99u8; 16];
    let sealed = seal_exported_session_key(&kek, &exported);
    
    assert_eq!(rc4(&kek, &sealed), exported.to_vec());
}

#[test]
fn sign_and_seal_keys_are_deterministic() {
    let session_key = [0xAB; 16];
    let flags = NegotiateFlags::NEGOTIATE_EXTENDED_SESSIONSECURITY | NegotiateFlags::NEGOTIATE_128;
    let sign = sign_key(flags, &session_key, SessionKeyMode::Client).expect("sign key");
    assert_eq!(
        sign,
        sign_key(flags, &session_key, SessionKeyMode::Client).unwrap()
    );
    let seal = seal_key(flags, &session_key, SessionKeyMode::Client);
    assert_eq!(seal, seal_key(flags, &session_key, SessionKeyMode::Client));
}

#[test]
fn mic_is_deterministic_and_key_dependent() {
    let key_a = [0x01u8; 16];
    let key_b = [0x02u8; 16];
    let neg = b"negotiate";
    let chal = b"challenge";
    let auth = b"authenticate";

    let mic_a = mic(&key_a, neg, chal, auth);
    assert_eq!(mic_a, mic(&key_a, neg, chal, auth));
    assert_ne!(mic_a, mic(&key_b, neg, chal, auth));
}
