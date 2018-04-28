use error;
use win32;
use win32::bcrypt;
use win32::bcrypt::{Algorithm, Blob, SymAlg};
use win32::ncrypt;
pub use win32::ncrypt::Ksp;

// The ciphersuite we use is:
// - ECDH on P256 curve
// - NIST SP800 108 CTR KDF
// - AES256 CBC
// - HMAC SHA256

const MASTER_SECRET_LABEL: &'static str = "pwrs_master_secret";
const DERIVED_KEYS_LABEL: &'static str = "pwrs_derived_keys";

// Right now, the public key blob and private key blobs are just
// BCrypt public and private key structs. If we ever want to be
// cross-platform, or support other crypto libraries, we should
// really extract the actual curve points. Thankfully, if we ever
// want to upgrade, it should be fairly easy, since each of the
// BCrypt blobs begin with a magic value we can look for.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PubKey(Vec<u8>);
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PrivKey(Vec<u8>);
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct AgreedSecret(Vec<u8>);

pub trait KeyPair {
    fn pk(&self) -> error::Result<PubKey>;
    fn agree_and_derive(&self, pk: &PubKey) -> error::Result<AgreedSecret>;
}

pub struct EcdhKeyPair {
    key: win32::Handle<bcrypt::Key>,
}

impl EcdhKeyPair {
    pub fn new() -> error::Result<Self> {
        let key = bcrypt::generate_key_pair(Algorithm::EcdhP256)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn import(sk: &PrivKey) -> error::Result<Self> {
        let key = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &sk.0)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn sk(&self) -> error::Result<PrivKey> {
        Ok(PrivKey(bcrypt::export_key(&self.key, Blob::EccPrivate)?))
    }
}

impl KeyPair for EcdhKeyPair {
    fn pk(&self) -> error::Result<PubKey> {
        Ok(PubKey(bcrypt::export_key(&self.key, Blob::EccPublic)?))
    }

    fn agree_and_derive(&self, pk: &PubKey) -> error::Result<AgreedSecret> {
        let pk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, &pk.0)?;
        let secret = bcrypt::secret_agreement(&self.key, &pk)?;
        Ok(AgreedSecret(bcrypt::derive_key(
            &secret,
            MASTER_SECRET_LABEL,
        )?))
    }
}

// AES key 'k', HMAC secret 's'
struct EncryptionKey(Vec<u8>);
struct MacSecret(Vec<u8>);
pub struct DerivedKeys {
    k: EncryptionKey,
    s: MacSecret,
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBytes(Vec<u8>);
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mac(Vec<u8>);

impl DerivedKeys {
    pub fn new(secret: &AgreedSecret) -> error::Result<Self> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret.0)?;
        let keys = bcrypt::key_derivation(&secret, DERIVED_KEYS_LABEL, 64)?;
        let (k, s) = keys.split_at(32);
        Ok(DerivedKeys {
            k: EncryptionKey(k.to_vec()),
            s: MacSecret(s.to_vec()),
        })
    }

    pub fn encrypt(&self, string: &str) -> error::Result<EncryptedBytes> {
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption.
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k.0)?;
        Ok(EncryptedBytes(bcrypt::encrypt_data(
            &k,
            &iv,
            string.as_bytes(),
        )?))
    }

    pub fn decrypt(&self, bytes: &EncryptedBytes) -> error::Result<String> {
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k.0)?;
        let decrypted = bcrypt::decrypt_data(&k, &iv, &bytes.0)?;
        Ok(String::from_utf8(decrypted)?)
    }

    pub fn mac(&self, label: &str, data: &EncryptedBytes) -> error::Result<Mac> {
        Ok(Mac(bcrypt::hmac_sha256_with_label(
            &self.s.0,
            &label,
            &data.0,
        )?))
    }
}

pub struct KspEcdhKeyPair {
    prov: win32::Handle<ncrypt::Object>,
    key: win32::Handle<ncrypt::Object>,
}

impl KspEcdhKeyPair {
    pub fn new(ksp: Ksp, name: &str) -> error::Result<KspEcdhKeyPair> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::create_persisted_key(&prov, Algorithm::EcdhP256, Some(name))?;
        ncrypt::finalize_key(&key)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    pub fn open(ksp: Ksp, name: &str) -> error::Result<KspEcdhKeyPair> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::open_key(&prov, name)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    pub fn delete(self) -> error::Result<()> {
        Ok(ncrypt::delete_key(self.key)?)
    }
}

impl KeyPair for KspEcdhKeyPair {
    fn pk(&self) -> error::Result<PubKey> {
        Ok(PubKey(ncrypt::export_key(&self.key, Blob::EccPublic)?))
    }

    fn agree_and_derive(&self, pk: &PubKey) -> error::Result<AgreedSecret> {
        let pk = ncrypt::import_key(&self.prov, Blob::EccPublic, &pk.0)?;
        let secret = ncrypt::secret_agreement(&self.key, &pk)?;
        Ok(AgreedSecret(ncrypt::derive_key(
            &secret,
            MASTER_SECRET_LABEL,
        )?))
    }
}
