use ipkt_core::{Pack, Unpack};
use ipkt_ntlm::avpair::{AvId, AvPair, TargetInfo};
use ipkt_ntlm::{
    AuthenticateMessage, ChallengeMessage, Credentials, NegotiateFlags, NegotiateMessage,
    NtlmClient, NtlmVariant, Version,
};

const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

fn sample_target_info() -> TargetInfo {
    TargetInfo::new()
        .with(AvPair::string(AvId::NbDomainName, "CONTOSO"))
        .with(AvPair::string(AvId::NbComputerName, "DC01"))
        .with(AvPair::string(AvId::DnsDomainName, "contoso.local"))
}

#[test]
fn negotiate_message_round_trips() {
    let msg = NegotiateMessage::new(NegotiateFlags::client_defaults())
        .with_domain("CONTOSO")
        .with_workstation("CLIENT01")
        .with_version(Version::default());

    let bytes = msg.pack();
    assert_eq!(&bytes[..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 1);

    let parsed = NegotiateMessage::unpack(&bytes).unwrap();
    assert_eq!(parsed, msg);
}

#[test]
fn challenge_message_round_trips_and_preserves_target_info() {
    let msg = ChallengeMessage::new(
        NegotiateFlags::client_defaults(),
        SERVER_CHALLENGE,
        sample_target_info(),
    )
    .with_target_name("CONTOSO")
    .with_version(Version::default());

    let bytes = msg.pack();
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 2);

    let parsed = ChallengeMessage::unpack(&bytes).unwrap();
    assert_eq!(parsed.server_challenge, SERVER_CHALLENGE);
    assert_eq!(parsed.target_name.as_deref(), Some("CONTOSO"));
    assert_eq!(parsed.target_info.pairs().len(), 3);
    
    assert_eq!(parsed.target_info_bytes(), msg.target_info_bytes());
}

#[test]
fn authenticate_message_round_trips_with_mic() {
    let msg = AuthenticateMessage::new(
        NegotiateFlags::client_defaults(),
        vec![0xAA; 24],
        vec![0xBB; 48],
    )
    .with_identity("CONTOSO", "alice")
    .with_workstation("CLIENT01")
    .with_encrypted_session_key(vec![0xCC; 16])
    .with_mic_placeholder();

    let bytes = msg.pack();
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);

    let parsed = AuthenticateMessage::unpack(&bytes).unwrap();
    assert_eq!(parsed.domain.as_deref(), Some("CONTOSO"));
    assert_eq!(parsed.user.as_deref(), Some("alice"));
    assert_eq!(parsed.workstation.as_deref(), Some("CLIENT01"));
    assert_eq!(parsed.lm_challenge_response, vec![0xAA; 24]);
    assert_eq!(parsed.nt_challenge_response, vec![0xBB; 48]);
    assert_eq!(
        parsed.encrypted_session_key.as_deref(),
        Some(&[0xCC; 16][..])
    );
    assert!(parsed.mic.is_some());
}

#[test]
fn authenticate_message_round_trips_without_mic() {
    let msg = AuthenticateMessage::new(
        NegotiateFlags::NEGOTIATE_UNICODE | NegotiateFlags::NEGOTIATE_NTLM,
        vec![0x11; 24],
        vec![0x22; 24],
    )
    .with_identity("WORKGROUP", "bob");

    let parsed = AuthenticateMessage::unpack(&msg.pack()).unwrap();
    assert_eq!(parsed.mic, None);
    assert_eq!(parsed, msg);
}

#[test]
fn rejects_wrong_signature() {
    let mut bytes = NegotiateMessage::new(NegotiateFlags::client_defaults()).pack();
    bytes[0] = b'X';
    assert!(NegotiateMessage::unpack(&bytes).is_err());
}

#[test]
fn rejects_wrong_message_type() {
    
    let challenge = ChallengeMessage::new(
        NegotiateFlags::client_defaults(),
        SERVER_CHALLENGE,
        TargetInfo::new(),
    )
    .pack();
    assert!(NegotiateMessage::unpack(&challenge).is_err());
}

#[test]
fn malformed_av_pairs_are_rejected() {
    
    let truncated = [0x01, 0x00, 0xFF, 0xFF, 0x00];
    assert!(TargetInfo::parse(&truncated).is_err());
}




#[test]
fn full_ntlmv2_handshake_produces_verifiable_proof() {
    use ipkt_ntlm::crypto::{ntlm_v2_response, ntowf_v2};

    let credentials = Credentials::new("CONTOSO", "alice", "S3cr3t!");
    let client = NtlmClient::new(credentials)
        .with_workstation("CLIENT01")
        .with_client_challenge([0x42; 8])
        .with_exported_session_key([0x77; 16]);

    
    let negotiate = client.negotiate();
    let negotiate_bytes = negotiate.pack();

    
    let challenge = ChallengeMessage::new(
        NegotiateFlags::client_defaults(),
        SERVER_CHALLENGE,
        sample_target_info(),
    );
    let challenge_bytes = challenge.pack();
    let parsed_challenge = ChallengeMessage::unpack(&challenge_bytes).unwrap();

    
    let outcome = client
        .authenticate(&parsed_challenge, &negotiate_bytes, &challenge_bytes)
        .unwrap();

    
    let response_key = ntowf_v2("S3cr3t!", "alice", "CONTOSO");
    
    let sent = &outcome.message.nt_challenge_response;
    let (sent_proof, temp) = sent.split_at(16);
    
    
    let target_info = parsed_challenge.target_info_bytes();
    let timestamp = u64::from_le_bytes(temp[8..16].try_into().unwrap());
    let recomputed = ntlm_v2_response(
        &response_key,
        &SERVER_CHALLENGE,
        &[0x42; 8],
        timestamp,
        &target_info,
    );

    assert_eq!(sent_proof, recomputed.proof());
    assert_eq!(outcome.exported_session_key, [0x77; 16]);
    
    assert!(outcome.message.encrypted_session_key.is_some());
}

#[test]
fn ntlmv1_handshake_round_trips() {
    let client = NtlmClient::new(Credentials::new("CONTOSO", "alice", "S3cr3t!"))
        .with_variant(NtlmVariant::V1)
        .with_client_challenge([0x42; 8])
        .with_exported_session_key([0x77; 16]);

    let negotiate = client.negotiate();
    let challenge = ChallengeMessage::new(
        NegotiateFlags::client_defaults(),
        SERVER_CHALLENGE,
        TargetInfo::new(),
    );
    let challenge_bytes = challenge.pack();

    let outcome = client
        .authenticate(&challenge, &negotiate.pack(), &challenge_bytes)
        .unwrap();

    
    assert_eq!(outcome.message.nt_challenge_response.len(), 24);
    assert_eq!(outcome.message.lm_challenge_response.len(), 24);

    
    let parsed = AuthenticateMessage::unpack(&outcome.message_bytes).unwrap();
    assert_eq!(parsed.user.as_deref(), Some("alice"));
}
