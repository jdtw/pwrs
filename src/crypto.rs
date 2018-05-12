//! ECDH P256, AES256 CBC, HMAC SHA256, NIST SP800 108 KDF
//!
//! Implements the ciphersuite needed for the password vault by wraping
//! [BCrypt][bcrypt] and [NCrypt][ncrypt] Win32 APIs.
//!
//! [bcrypt]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa833130(v=vs.85).aspx
//! [ncrypt]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa376208(v=vs.85).aspx
//!
//! All secrets (key agreement, AES key, MAC secret, etc.) are protected by the `seckey` crate,
//! which provides locked, protected memory allocations that are securely zeroed on `drop`.

use error::*;
use hex;
use seckey::SecKey;
use win32;
use win32::bcrypt;
use win32::bcrypt::SymAlg;
use win32::ncrypt;

/// An enum representing persisted key storage locations.
#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
pub enum KeyStorage {
    Software,
    SmartCard,
}

const MASTER_SECRET_LABEL: &str = "pwrs_master_secret";
const DERIVED_KEYS_LABEL: &str = "pwrs_derived_keys";

pub const P256_CURVE_SIZE: usize = 32;
pub const SHA2_DIGEST_SIZE: usize = 32;
pub const SHA1_DIGEST_SIZE: usize = 20;
pub const AES256_KEY_SIZE: usize = 32;

/// ECDH P256 public key, represented by `(x, y)`.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PubKey {
    pub x: [u8; P256_CURVE_SIZE],
    pub y: [u8; P256_CURVE_SIZE],
}

#[cfg(test)]
#[derive(Debug)]
pub struct PrivKey {
    pub d: SecKey<[u8; P256_CURVE_SIZE]>,
}

/// The result of ECDH secret agreement.
#[derive(Debug)]
pub struct AgreedSecret {
    pub s: SecKey<[u8; SHA2_DIGEST_SIZE]>,
}

impl AgreedSecret {
    /// Use the NIST SP800 108 CTR KDF (using HMAC SHA256) to derive an encryption key
    /// and a MAC secret.
    pub fn derive_keys(self) -> Result<(EncryptionKey, MacSecret), Error> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &*self.s.read())?;
        Ok(bcrypt::key_derivation(&secret, DERIVED_KEYS_LABEL)?)
    }
}

impl PubKey {
    /// Calculate the SHA1 hash of the public key as a string for display purposes.
    pub fn thumbprint(&self) -> Result<String, Error> {
        let hash = bcrypt::HashSha1::new()?
            .hash(&self.x)?
            .hash(&self.y)?
            .finish_hash()?;
        Ok(hex::encode(hash))
    }
}

/// Abstraction over ECDH keys
pub trait KeyPair {
    /// Get the public key
    fn pk(&self) -> Result<PubKey, Error>;
    /// Perform key agreement with the private key of `self` and the passed in public key
    fn agree(&self, pk: &PubKey) -> Result<AgreedSecret, Error>;
}

/// An ephemeral ECDH key pair
pub struct EcdhKeyPair {
    key: win32::Handle<bcrypt::Key>,
}

impl EcdhKeyPair {
    /// Generate a new, ephemeral ECDH key pair
    pub fn new() -> Result<Self, Error> {
        let key = bcrypt::generate_ecdh_p256_key_pair()?;
        Ok(EcdhKeyPair { key })
    }

    #[cfg(test)]
    pub fn import(sk: &PrivKey) -> Result<Self, Error> {
        let key = bcrypt::import_ecdh_p256_priv_key(sk)?;
        Ok(EcdhKeyPair { key })
    }

    #[cfg(test)]
    pub fn sk(&self) -> Result<PrivKey, Error> {
        Ok(bcrypt::export_ecdh_p256_priv_key(&self.key)?)
    }
}

impl KeyPair for EcdhKeyPair {
    /// Get the public key
    fn pk(&self) -> Result<PubKey, Error> {
        Ok(bcrypt::export_ecdh_p256_pub_key(&self.key)?)
    }

    /// Perform key agreement with the given public key and `self`'s private key.
    fn agree(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let pk = bcrypt::import_ecdh_p256_pub_key(pk)?;
        let secret = bcrypt::secret_agreement(&self.key, &pk)?;
        Ok(bcrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}

/// AES256-CBC key
#[derive(Debug)]
pub struct EncryptionKey(pub SecKey<[u8; AES256_KEY_SIZE]>);
/// HMAC SHA256 secret
#[derive(Debug)]
pub struct MacSecret(pub SecKey<[u8; SHA2_DIGEST_SIZE]>);
/// AES-encrypted bytes
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBytes(Vec<u8>);
/// HMAC SHA256
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mac([u8; SHA2_DIGEST_SIZE]);

impl EncryptionKey {
    /// Perform AES256 encryption of the passed in string. An all-zero IV is used (`[0u8; 16]`)
    /// because we use a new encryption key for every encrytion. To enforce this, `encrypt` consumes
    /// the encryption key.
    pub fn encrypt(self, string: &str) -> Result<EncryptedBytes, Error> {
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption.
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &*self.0.read())?;
        Ok(EncryptedBytes(bcrypt::encrypt_data(
            &k,
            &iv,
            string.as_bytes(),
        )?))
    }

    /// AES256 decryption with an all-zero IV.
    pub fn decrypt(&self, bytes: &EncryptedBytes) -> Result<String, Error> {
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &*self.0.read())?;
        let decrypted = bcrypt::decrypt_data(&k, &iv, &bytes.0)?;
        Ok(String::from_utf8(decrypted)?)
    }
}

impl MacSecret {
    /// Perform HMAC SHA256 of `site||username||data`.
    pub fn mac(&self, site: &str, username: &str, data: &EncryptedBytes) -> Result<Mac, Error> {
        let mac = bcrypt::HmacSha2::new(&*self.0.read())?
            .hash(site.as_bytes())?
            .hash(username.as_bytes())?
            .hash(&data.0)?
            .finish_hash()?;
        Ok(Mac(mac))
    }
}

/// A persisted ECDH key pair
///
/// # Examples
///
/// ```
/// use pwv::crypto::{KeyStorage, KspEcdhKeyPair, KeyPair};
///
/// let key = KspEcdhKeyPair::new(KeyStorage::Software, "keyname").unwrap();
/// let new_pk = key.pk().unwrap();
/// drop(key);
///
/// let key = KspEcdhKeyPair::open(KeyStorage::Software, "keyname").unwrap();
/// let opened_pk = key.pk().unwrap();
/// key.delete().unwrap();
///
/// assert_eq!(new_pk, opened_pk);
/// ```
pub struct KspEcdhKeyPair {
    prov: win32::Handle<ncrypt::Object>,
    key: win32::Handle<ncrypt::Object>,
}

impl KspEcdhKeyPair {
    /// Create a new persisted key
    pub fn new(ksp: KeyStorage, name: &str) -> Result<KspEcdhKeyPair, Error> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::create_persisted_ecdh_p256_key(&prov, Some(name))?;
        ncrypt::finalize_key(&key)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    /// Open an existing persisted key
    pub fn open(ksp: KeyStorage, name: &str) -> Result<KspEcdhKeyPair, Error> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::open_key(&prov, name)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    /// Delete the persisted key
    pub fn delete(self) -> Result<(), Error> {
        ncrypt::delete_key(self.key)?;
        Ok(())
    }
}

impl KeyPair for KspEcdhKeyPair {
    /// Export the public key
    fn pk(&self) -> Result<PubKey, Error> {
        Ok(ncrypt::export_ecdh_p256_pub_key(&self.key)?)
    }

    /// Perform secret agreement. For smart card keys, this will prompt for the
    /// smart card PIN.
    fn agree(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let pk = ncrypt::import_ecdh_p256_pub_key(&self.prov, pk)?;
        let secret = ncrypt::secret_agreement(&self.key, &pk)?;
        Ok(ncrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_close_open_key() {
        let key = KspEcdhKeyPair::new(KeyStorage::Software, "abcdefg").expect("Create key failed");
        key.pk().expect("Get pk failed");
        drop(key);
        let key = KspEcdhKeyPair::open(KeyStorage::Software, "abcdefg").expect("Open failed");
        key.delete().expect("Delete failed");
    }
}
