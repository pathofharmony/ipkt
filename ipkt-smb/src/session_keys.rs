use ipkt_ntlm::{NegotiateFlags, SessionKeyMode, sign_key, seal_key};


#[derive(Debug, Clone)]
pub struct SmbSessionKeys {
    
    pub exported_session_key: [u8; 16],
    
    pub signing_key: Option<[u8; 16]>,
    
    pub sealing_key: [u8; 16],
    
    pub negotiate_flags: NegotiateFlags,
}

impl SmbSessionKeys {
    
    #[must_use]
    pub fn from_ntlm(exported_session_key: [u8; 16], negotiate_flags: NegotiateFlags) -> Self {
        Self {
            exported_session_key,
            signing_key: sign_key(
                negotiate_flags,
                &exported_session_key,
                SessionKeyMode::Client,
            ),
            sealing_key: seal_key(
                negotiate_flags,
                &exported_session_key,
                SessionKeyMode::Client,
            ),
            negotiate_flags,
        }
    }
}
