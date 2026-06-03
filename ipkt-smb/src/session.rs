use ipkt_core::{Pack, Unpack};
use ipkt_ntlm::{ChallengeMessage, Credentials, NtlmClient};

use crate::commands::{SessionSetupRequest, SessionSetupResponse};
use crate::error::{Error, Result};
use crate::header::{Smb2Command, Smb2Header};
use crate::packet::Smb2Packet;


#[derive(Debug)]
pub struct NtlmSessionSetup {
    ntlm: NtlmClient,
    negotiate_bytes: Vec<u8>,
    challenge_bytes: Option<Vec<u8>>,
}

impl NtlmSessionSetup {
    
    #[must_use]
    pub fn new(credentials: Credentials) -> Self {
        let ntlm = NtlmClient::new(credentials);
        let negotiate_bytes = ntlm.negotiate().pack();
        Self {
            ntlm,
            negotiate_bytes,
            challenge_bytes: None,
        }
    }

    
    #[must_use]
    pub fn first_request(&self, message_id: u64) -> Smb2Packet<SessionSetupRequest> {
        let header = Smb2Header::request(Smb2Command::SessionSetup, message_id, 0, 0);
        let body = SessionSetupRequest::with_security_buffer(self.negotiate_bytes.clone());
        Smb2Packet {
            header,
            body,
            payload: Vec::new(),
        }
    }

    
    
    
    
    
    pub fn absorb_challenge(
        &mut self,
        response: &SessionSetupResponse,
    ) -> Result<ChallengeMessage> {
        let challenge = ChallengeMessage::unpack(&response.security_buffer)
            .map_err(|e| Error::Ntlm(e.to_string()))?;
        self.challenge_bytes = Some(response.security_buffer.clone());
        Ok(challenge)
    }

    
    
    
    
    
    pub fn second_request(
        &self,
        challenge: &ChallengeMessage,
        message_id: u64,
        session_id: u64,
    ) -> Result<Smb2Packet<SessionSetupRequest>> {
        let challenge_bytes = self
            .challenge_bytes
            .as_ref()
            .ok_or(Error::Ntlm("missing challenge bytes".into()))?;
        let outcome = self
            .ntlm
            .authenticate(challenge, &self.negotiate_bytes, challenge_bytes)?;
        let header = Smb2Header::request(Smb2Command::SessionSetup, message_id, session_id, 0);
        Ok(Smb2Packet {
            header,
            body: SessionSetupRequest::with_security_buffer(outcome.message_bytes),
            payload: Vec::new(),
        })
    }

    
    pub fn exported_session_key(&self, challenge: &ChallengeMessage) -> Result<[u8; 16]> {
        let challenge_bytes = self
            .challenge_bytes
            .as_ref()
            .ok_or(Error::Ntlm("missing challenge".into()))?;
        Ok(self
            .ntlm
            .authenticate(challenge, &self.negotiate_bytes, challenge_bytes)?
            .exported_session_key)
    }
}


pub fn parse_ntlm_challenge_from_packet(bytes: &[u8]) -> Result<ChallengeMessage> {
    let packet = Smb2Packet::<SessionSetupResponse>::unpack(bytes).map_err(Error::Codec)?;
    ChallengeMessage::unpack(&packet.body.security_buffer).map_err(|e| Error::Ntlm(e.to_string()))
}
