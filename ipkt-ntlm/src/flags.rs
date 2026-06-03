use bitflags::bitflags;

bitflags! {






    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[cfg_attr(feature = "serde", serde(transparent))]
    pub struct NegotiateFlags: u32 {

        const NEGOTIATE_56 = 0x8000_0000;

        const NEGOTIATE_KEY_EXCH = 0x4000_0000;

        const NEGOTIATE_128 = 0x2000_0000;

        const NEGOTIATE_VERSION = 0x0200_0000;

        const NEGOTIATE_TARGET_INFO = 0x0080_0000;

        const REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;

        const NEGOTIATE_IDENTIFY = 0x0010_0000;

        const NEGOTIATE_EXTENDED_SESSIONSECURITY = 0x0008_0000;

        const TARGET_TYPE_SERVER = 0x0002_0000;

        const TARGET_TYPE_DOMAIN = 0x0001_0000;

        const NEGOTIATE_ALWAYS_SIGN = 0x0000_8000;

        const NEGOTIATE_OEM_WORKSTATION_SUPPLIED = 0x0000_2000;

        const NEGOTIATE_OEM_DOMAIN_SUPPLIED = 0x0000_1000;

        const NEGOTIATE_ANONYMOUS = 0x0000_0800;

        const NEGOTIATE_NTLM = 0x0000_0200;

        const NEGOTIATE_LM_KEY = 0x0000_0080;

        const NEGOTIATE_DATAGRAM = 0x0000_0040;

        const NEGOTIATE_SEAL = 0x0000_0020;

        const NEGOTIATE_SIGN = 0x0000_0010;

        const REQUEST_TARGET = 0x0000_0004;

        const NEGOTIATE_OEM = 0x0000_0002;

        const NEGOTIATE_UNICODE = 0x0000_0001;
    }
}

impl NegotiateFlags {
    #[must_use]
    pub fn client_defaults() -> Self {
        Self::NEGOTIATE_UNICODE
            | Self::REQUEST_TARGET
            | Self::NEGOTIATE_NTLM
            | Self::NEGOTIATE_ALWAYS_SIGN
            | Self::NEGOTIATE_EXTENDED_SESSIONSECURITY
            | Self::NEGOTIATE_SIGN
            | Self::NEGOTIATE_SEAL
            | Self::NEGOTIATE_KEY_EXCH
            | Self::NEGOTIATE_128
            | Self::NEGOTIATE_56
    }

    #[must_use]
    pub const fn uses_unicode(self) -> bool {
        self.contains(Self::NEGOTIATE_UNICODE)
    }

    #[must_use]
    pub const fn uses_extended_session_security(self) -> bool {
        self.contains(Self::NEGOTIATE_EXTENDED_SESSIONSECURITY)
    }
}
