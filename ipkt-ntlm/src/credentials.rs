use crate::crypto::ntowf_v1;

#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Secret {
    Password(String),

    NtHash([u8; 16]),
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Password(_) => f.write_str("Secret::Password(***)"),
            Self::NtHash(_) => f.write_str("Secret::NtHash(***)"),
        }
    }
}

impl Secret {
    /// Returns the NT hash for this secret, computing it from the password
    /// when necessary.
    #[must_use]
    pub fn nt_hash(&self) -> [u8; 16] {
        match self {
            Self::Password(password) => ntowf_v1(password),
            Self::NtHash(hash) => *hash,
        }
    }
}

/// A complete set of credentials: domain, user, and a [`Secret`].
///
/// # Examples
///
/// ```
/// use ipkt_ntlm::Credentials;
///
/// let creds = Credentials::new("CONTOSO", "alice", "S3cr3t!");
/// assert_eq!(creds.user(), "alice");
///
/// // Pass-the-hash with a captured NT hash:
/// let pth = Credentials::with_nt_hash("CONTOSO", "alice", [0u8; 16]);
/// assert_eq!(pth.domain(), "CONTOSO");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Credentials {
    domain: String,
    user: String,
    secret: Secret,
}

impl Credentials {
    /// Creates credentials from a plaintext password.
    #[must_use]
    pub fn new(
        domain: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            domain: domain.into(),
            user: user.into(),
            secret: Secret::Password(password.into()),
        }
    }

    /// Anonymous credentials (empty domain, user, and secret).
    #[must_use]
    pub fn anonymous() -> Self {
        Self::new("", "", "")
    }

    /// Creates credentials from a captured NT hash (pass-the-hash).
    #[must_use]
    pub fn with_nt_hash(
        domain: impl Into<String>,
        user: impl Into<String>,
        nt_hash: [u8; 16],
    ) -> Self {
        Self {
            domain: domain.into(),
            user: user.into(),
            secret: Secret::NtHash(nt_hash),
        }
    }

    /// The authentication domain (may be empty).
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// The user name.
    #[must_use]
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The credential secret.
    #[must_use]
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    /// The NT hash for these credentials.
    #[must_use]
    pub fn nt_hash(&self) -> [u8; 16] {
        self.secret.nt_hash()
    }
}
