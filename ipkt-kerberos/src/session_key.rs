use crate::aes_cts::{decrypt_aes256, encrypt_aes256};
use crate::crypto::ETYPE_AES256_CTS_HMAC_SHA1_96;
use crate::des_crypto::{
    decrypt_des3_cbc_sha1, decrypt_des_cbc_crc, decrypt_des_cbc_md5, encrypt_des3_cbc_sha1,
    encrypt_des_cbc_crc, encrypt_des_cbc_md5, ETYPE_DES3_CBC_SHA1, ETYPE_DES_CBC_CRC,
    ETYPE_DES_CBC_MD5,
};
use crate::rc4_hmac::{decrypt_rc4_hmac, encrypt_rc4_hmac, ETYPE_RC4_HMAC};
use crate::Result;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosSessionKey {
    pub etype: i32,
    pub key: Vec<u8>,
}

impl KerberosSessionKey {
    
    pub fn aes256(key: [u8; 32]) -> Self {
        Self {
            etype: ETYPE_AES256_CTS_HMAC_SHA1_96,
            key: key.to_vec(),
        }
    }

    
    pub fn rc4(key: [u8; 16]) -> Self {
        Self {
            etype: ETYPE_RC4_HMAC,
            key: key.to_vec(),
        }
    }

    
    #[must_use]
    pub fn from_parts(etype: i32, key: Vec<u8>) -> Self {
        Self { etype, key }
    }

    
    pub fn encrypt(&self, key_usage: u32, plaintext: &[u8], confounder: &[u8]) -> Result<Vec<u8>> {
        match self.etype {
            ETYPE_AES256_CTS_HMAC_SHA1_96 => {
                let k: [u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad AES key len".into()))?;
                let c: [u8; 16] = confounder
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad confounder".into()))?;
                encrypt_aes256(&k, key_usage, plaintext, &c)
            }
            ETYPE_RC4_HMAC => encrypt_rc4_hmac(&self.key, key_usage, plaintext),
            ETYPE_DES_CBC_CRC => {
                let k: [u8; 8] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad DES key len".into()))?;
                encrypt_des_cbc_crc(&k, key_usage, plaintext)
            }
            ETYPE_DES_CBC_MD5 => {
                let k: [u8; 8] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad DES key len".into()))?;
                encrypt_des_cbc_md5(&k, key_usage, plaintext)
            }
            ETYPE_DES3_CBC_SHA1 => {
                let k: [u8; 24] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad 3DES key len".into()))?;
                encrypt_des3_cbc_sha1(&k, key_usage, plaintext)
            }
            _ => Err(crate::Error::Crypto(format!("unsupported etype {}", self.etype))),
        }
    }

    
    pub fn decrypt(&self, key_usage: u32, cipher: &[u8]) -> Result<Vec<u8>> {
        match self.etype {
            ETYPE_AES256_CTS_HMAC_SHA1_96 => {
                let k: [u8; 32] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad AES key len".into()))?;
                decrypt_aes256(&k, key_usage, cipher)
            }
            ETYPE_RC4_HMAC => decrypt_rc4_hmac(&self.key, key_usage, cipher),
            ETYPE_DES_CBC_CRC => {
                let k: [u8; 8] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad DES key len".into()))?;
                decrypt_des_cbc_crc(&k, key_usage, cipher)
            }
            ETYPE_DES_CBC_MD5 => {
                let k: [u8; 8] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad DES key len".into()))?;
                decrypt_des_cbc_md5(&k, key_usage, cipher)
            }
            ETYPE_DES3_CBC_SHA1 => {
                let k: [u8; 24] = self
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::Error::Crypto("bad 3DES key len".into()))?;
                decrypt_des3_cbc_sha1(&k, key_usage, cipher)
            }
            _ => Err(crate::Error::Crypto(format!("unsupported etype {}", self.etype))),
        }
    }
}


#[must_use]
pub fn default_enctype_list() -> Vec<i32> {
    vec![
        ETYPE_AES256_CTS_HMAC_SHA1_96,
        ETYPE_RC4_HMAC,
        ETYPE_DES3_CBC_SHA1,
        ETYPE_DES_CBC_MD5,
        ETYPE_DES_CBC_CRC,
    ]
}
