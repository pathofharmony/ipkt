use ipkt_core::Pack;
use ipkt_ntlm::{
    channel_bindings_hash, ChallengeMessage, Credentials, NegotiateFlags, NtlmClient, TargetInfo,
};

#[test]
fn channel_bindings_hash_is_stable() {
    let cert = [0xAAu8; 32];
    let h1 = channel_bindings_hash(&cert);
    let h2 = channel_bindings_hash(&cert);
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 16]);
}

#[test]
fn anonymous_authenticate_has_empty_responses() {
    let client = NtlmClient::anonymous()
        .with_client_challenge([0x01; 8])
        .with_exported_session_key([0x02; 16]);
    let negotiate = client.negotiate().pack();
    let challenge = ChallengeMessage::new(
        NegotiateFlags::client_defaults() | NegotiateFlags::NEGOTIATE_ANONYMOUS,
        [0x11; 8],
        TargetInfo::new(),
    );
    let challenge_bytes = challenge.pack();
    let outcome = client
        .authenticate(&challenge, &negotiate, &challenge_bytes)
        .unwrap();
    assert!(outcome.message.lm_challenge_response.is_empty());
    assert!(outcome.message.nt_challenge_response.is_empty());
}

#[test]
fn client_with_channel_bindings_builds_negotiate() {
    let hash = channel_bindings_hash(b"fingerprint");
    let client =
        NtlmClient::new(Credentials::new("DOM", "user", "pass")).with_channel_bindings(hash);
    assert!(client
        .negotiate()
        .flags
        .contains(NegotiateFlags::NEGOTIATE_NTLM));
}
