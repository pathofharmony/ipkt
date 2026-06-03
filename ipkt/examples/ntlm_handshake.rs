use ipkt::core::{Pack, Unpack};
use ipkt::ntlm::avpair::{AvId, AvPair, TargetInfo};
use ipkt::ntlm::crypto::{ntowf_v2, Challenge};
use ipkt::ntlm::{ChallengeMessage, Credentials, NegotiateFlags, NtlmClient};


fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    
    let domain = "CONTOSO";
    let user = "alice";
    let password = "S3cr3t!";

    
    let server_challenge: Challenge = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];

    
    let client = NtlmClient::new(Credentials::new(domain, user, password))
        .with_workstation("CLIENT01")
        
        .with_client_challenge([0x42; 8])
        .with_exported_session_key([0x77; 16]);

    let negotiate = client.negotiate();
    let negotiate_bytes = negotiate.pack();
    println!("--> NEGOTIATE  ({} bytes)", negotiate_bytes.len());
    println!("    flags: {:?}", negotiate.flags);

    
    let target_info = TargetInfo::new()
        .with(AvPair::string(AvId::NbDomainName, domain))
        .with(AvPair::string(AvId::NbComputerName, "DC01"))
        .with(AvPair::string(AvId::DnsDomainName, "contoso.local"));

    let challenge = ChallengeMessage::new(
        NegotiateFlags::client_defaults(),
        server_challenge,
        target_info,
    )
    .with_target_name(domain);

    let challenge_bytes = challenge.pack();
    println!("<-- CHALLENGE  ({} bytes)", challenge_bytes.len());
    println!("    server challenge: {}", hex(&server_challenge));

    
    let parsed_challenge = ChallengeMessage::unpack(&challenge_bytes).unwrap();

    
    let outcome = client
        .authenticate(&parsed_challenge, &negotiate_bytes, &challenge_bytes)
        .expect("handshake should succeed");

    println!("--> AUTHENTICATE ({} bytes)", outcome.message_bytes.len());
    println!(
        "    NTProofStr (first 16 bytes of NT response): {}",
        hex(&outcome.message.nt_challenge_response[..16])
    );
    println!(
        "    exported session key: {}",
        hex(&outcome.exported_session_key)
    );

    
    
    
    let response_key = ntowf_v2(password, user, domain);
    let sent = &outcome.message.nt_challenge_response;
    let (sent_proof, temp) = sent.split_at(16);
    let timestamp = u64::from_le_bytes(temp[8..16].try_into().unwrap());

    let recomputed = ipkt::ntlm::crypto::ntlm_v2_response(
        &response_key,
        &server_challenge,
        &[0x42; 8],
        timestamp,
        &parsed_challenge.target_info_bytes(),
    );

    if sent_proof == recomputed.proof() {
        println!("\n[+] Authentication SUCCESS — NTProofStr verified.");
    } else {
        println!("\n[-] Authentication FAILED — proof mismatch.");
        std::process::exit(1);
    }
}
