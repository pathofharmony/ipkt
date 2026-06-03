use ipkt_core::Pack;

use crate::avpair::{AvId, AvPair};
use crate::credentials::Credentials;
use crate::crypto::{
    self, key_exchange_key_ntlmv1, key_exchange_key_ntlmv1_extended, key_exchange_key_ntlmv2,
    lm_v2_response, mic, ntowf_v2_from_nt_hash, seal_exported_session_key, Challenge,
};
use crate::error::Result;
use crate::flags::NegotiateFlags;
use crate::messages::{AuthenticateMessage, ChallengeMessage, NegotiateMessage};
use crate::version::Version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum NtlmVariant {
    V1,

    V1Extended,

    V2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOutcome {
    pub message: AuthenticateMessage,

    pub message_bytes: Vec<u8>,

    pub exported_session_key: [u8; 16],
}

#[derive(Debug, Clone)]
pub struct NtlmClient {
    credentials: Credentials,
    flags: NegotiateFlags,
    workstation: Option<String>,
    variant: NtlmVariant,
    version: Option<Version>,
    compute_mic: bool,
    client_challenge: Option<Challenge>,
    timestamp: Option<u64>,
    exported_session_key: Option<[u8; 16]>,
    channel_bindings: Option<[u8; 16]>,
}

impl NtlmClient {
    #[must_use]
    pub fn new(credentials: Credentials) -> Self {
        Self {
            credentials,
            flags: NegotiateFlags::client_defaults(),
            workstation: None,
            variant: NtlmVariant::V2,
            version: Some(Version::default()),
            compute_mic: false,
            client_challenge: None,
            timestamp: None,
            exported_session_key: None,
            channel_bindings: None,
        }
    }

    #[must_use]
    pub fn anonymous() -> Self {
        Self::new(Credentials::anonymous())
            .with_flags(NegotiateFlags::client_defaults() | NegotiateFlags::NEGOTIATE_ANONYMOUS)
    }

    #[must_use]
    pub fn with_channel_bindings(mut self, hash: [u8; 16]) -> Self {
        self.channel_bindings = Some(hash);
        self
    }

    #[must_use]
    pub fn with_flags(mut self, flags: NegotiateFlags) -> Self {
        self.flags = flags;
        self
    }

    #[must_use]
    pub fn with_workstation(mut self, workstation: impl Into<String>) -> Self {
        self.workstation = Some(workstation.into());
        self
    }

    #[must_use]
    pub fn with_variant(mut self, variant: NtlmVariant) -> Self {
        self.variant = variant;
        self
    }

    #[must_use]
    pub fn with_mic(mut self, enabled: bool) -> Self {
        self.compute_mic = enabled;
        self
    }

    #[must_use]
    pub fn with_client_challenge(mut self, challenge: Challenge) -> Self {
        self.client_challenge = Some(challenge);
        self
    }

    #[must_use]
    pub fn with_timestamp(mut self, timestamp: u64) -> Self {
        self.timestamp = Some(timestamp);
        self
    }

    #[must_use]
    pub fn with_exported_session_key(mut self, key: [u8; 16]) -> Self {
        self.exported_session_key = Some(key);
        self
    }

    #[must_use]
    pub fn negotiate(&self) -> NegotiateMessage {
        let mut msg = NegotiateMessage::new(self.flags);
        if let Some(version) = self.version {
            msg = msg.with_version(version);
        }
        msg
    }

    pub fn authenticate(
        &self,
        challenge: &ChallengeMessage,
        negotiate_bytes: &[u8],
        challenge_bytes: &[u8],
    ) -> Result<AuthOutcome> {
        let flags = self.flags & challenge.flags;
        if flags.contains(NegotiateFlags::NEGOTIATE_ANONYMOUS) {
            let message = AuthenticateMessage::new(flags, Vec::new(), Vec::new());
            let message_bytes = message.pack();
            return Ok(AuthOutcome {
                message,
                message_bytes,
                exported_session_key: [0u8; 16],
            });
        }
        let client_challenge = self.resolve_client_challenge()?;

        let (lm_response, nt_response, session_base_key) = match self.variant {
            NtlmVariant::V1 => self.compute_v1(challenge),
            NtlmVariant::V1Extended => self.compute_v1_extended(challenge, &client_challenge),
            NtlmVariant::V2 => self.compute_v2(challenge, &client_challenge),
        };

        let kek = match self.variant {
            NtlmVariant::V2 => key_exchange_key_ntlmv2(&session_base_key),
            NtlmVariant::V1Extended => key_exchange_key_ntlmv1_extended(
                &session_base_key,
                &challenge.server_challenge,
                &lm_response,
            ),
            NtlmVariant::V1 => key_exchange_key_ntlmv1(&session_base_key),
        };
        let (exported_session_key, encrypted_session_key) =
            if flags.contains(NegotiateFlags::NEGOTIATE_KEY_EXCH) {
                let exported = self.resolve_exported_session_key()?;
                let wrapped = seal_exported_session_key(&kek, &exported);
                (exported, Some(wrapped.to_vec()))
            } else {
                (kek, None)
            };

        let mut message = AuthenticateMessage::new(flags, lm_response, nt_response)
            .with_identity(self.credentials.domain(), self.credentials.user());
        if let Some(workstation) = &self.workstation {
            message = message.with_workstation(workstation.clone());
        }
        if let Some(version) = self.version {
            message = message.with_version(version);
        }
        if let Some(key) = encrypted_session_key {
            message = message.with_encrypted_session_key(key);
        }

        let message_bytes = if self.compute_mic && self.variant == NtlmVariant::V2 {
            message = message.with_mic_placeholder();
            let mut bytes = message.pack();
            let computed = mic(
                &exported_session_key,
                negotiate_bytes,
                challenge_bytes,
                &bytes,
            );
            bytes[crate::messages::MIC_OFFSET
                ..crate::messages::MIC_OFFSET + crate::messages::MIC_LEN]
                .copy_from_slice(&computed);
            message.set_mic(computed);
            bytes
        } else {
            message.pack()
        };

        Ok(AuthOutcome {
            message,
            message_bytes,
            exported_session_key,
        })
    }

    fn compute_v1(&self, challenge: &ChallengeMessage) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
        let nt_hash = self.credentials.nt_hash();
        let lm_hash = match self.credentials.secret() {
            crate::credentials::Secret::Password(p) => crypto::lmowf_v1(p),

            crate::credentials::Secret::NtHash(_) => nt_hash,
        };
        let nt = crypto::ntlm_v1_response(&nt_hash, &challenge.server_challenge).to_vec();
        let lm = crypto::lm_v1_response(&lm_hash, &challenge.server_challenge).to_vec();
        let session_base_key = crypto::ntlm_v1_session_base_key(&nt_hash);
        (lm, nt, session_base_key)
    }

    fn compute_v1_extended(
        &self,
        challenge: &ChallengeMessage,
        client_challenge: &Challenge,
    ) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
        let nt_hash = self.credentials.nt_hash();
        let (lm, nt) = crypto::ntlm_v1_extended_response(
            &nt_hash,
            &challenge.server_challenge,
            client_challenge,
        );
        let session_base_key = crypto::ntlm_v1_session_base_key(&nt_hash);
        (lm.to_vec(), nt.to_vec(), session_base_key)
    }

    fn compute_v2(
        &self,
        challenge: &ChallengeMessage,
        client_challenge: &Challenge,
    ) -> (Vec<u8>, Vec<u8>, [u8; 16]) {
        let response_key = ntowf_v2_from_nt_hash(
            &self.credentials.nt_hash(),
            self.credentials.user(),
            self.credentials.domain(),
        );

        let server_has_timestamp = challenge.target_info.timestamp().is_some();
        let timestamp = self
            .timestamp
            .or_else(|| challenge.target_info.timestamp())
            .unwrap_or(0);

        let target_info_bytes = if self.compute_mic || self.channel_bindings.is_some() {
            let mut info = challenge.target_info.clone();
            if let Some(cb) = self.channel_bindings {
                info.push(AvPair::new(AvId::ChannelBindings, cb.to_vec()));
            }
            if self.compute_mic {
                info.push(AvPair::new(
                    AvId::Flags,
                    0x0000_0002u32.to_le_bytes().to_vec(),
                ));
            }
            info.pack()
        } else {
            challenge.target_info_bytes()
        };

        let v2 = crypto::ntlm_v2_response(
            &response_key,
            &challenge.server_challenge,
            client_challenge,
            timestamp,
            &target_info_bytes,
        );

        let lm = if server_has_timestamp {
            vec![0u8; 24]
        } else {
            lm_v2_response(&response_key, &challenge.server_challenge, client_challenge).to_vec()
        };

        (lm, v2.nt_challenge_response(), v2.session_base_key())
    }

    fn resolve_client_challenge(&self) -> Result<Challenge> {
        if let Some(challenge) = self.client_challenge {
            return Ok(challenge);
        }
        random_array().ok_or(crate::error::Error::MissingField("client_challenge"))
    }

    fn resolve_exported_session_key(&self) -> Result<[u8; 16]> {
        if let Some(key) = self.exported_session_key {
            return Ok(key);
        }
        random_array().ok_or(crate::error::Error::MissingField("exported_session_key"))
    }
}

fn random_array<const N: usize>() -> Option<[u8; N]> {
    #[cfg(feature = "rand")]
    {
        use rand::RngCore;
        let mut out = [0u8; N];
        rand::thread_rng().fill_bytes(&mut out);
        Some(out)
    }
    #[cfg(not(feature = "rand"))]
    {
        None
    }
}
