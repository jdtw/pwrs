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

pub trait KeyPair {
    fn pk(&self) -> error::Result<Vec<u8>>;
    fn agree_and_derive(&self, pk: &[u8]) -> error::Result<Vec<u8>>;
}

pub struct EcdhKeyPair {
    key: win32::Handle<bcrypt::Key>,
}

impl EcdhKeyPair {
    pub fn new() -> error::Result<Self> {
        let key = bcrypt::generate_key_pair(Algorithm::EcdhP256)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn import(sk: &[u8]) -> error::Result<Self> {
        let key = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, sk)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn sk(&self) -> error::Result<Vec<u8>> {
        Ok(bcrypt::export_key(&self.key, Blob::EccPrivate)?)
    }
}

impl KeyPair for EcdhKeyPair {
    fn pk(&self) -> error::Result<Vec<u8>> {
        Ok(bcrypt::export_key(&self.key, Blob::EccPublic)?)
    }

    fn agree_and_derive(&self, pk: &[u8]) -> error::Result<Vec<u8>> {
        let pk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, pk)?;
        let secret = bcrypt::secret_agreement(&self.key, &pk)?;
        Ok(bcrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}

// AES key 'k', HMAC secret 's'
pub struct DerivedKeys {
    k: Vec<u8>,
    s: Vec<u8>,
}

impl DerivedKeys {
    pub fn new(secret: &[u8]) -> error::Result<Self> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, secret)?;
        let keys = bcrypt::key_derivation(&secret, DERIVED_KEYS_LABEL, 64)?;
        let (k, s) = keys.split_at(32);
        Ok(DerivedKeys {
            k: k.to_vec(),
            s: s.to_vec(),
        })
    }

    pub fn encrypt(&self, string: &str) -> error::Result<Vec<u8>> {
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption.
        let iv: [u8; 32] = [0; 32];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k)?;
        Ok(bcrypt::encrypt_data(&k, &iv, string.as_bytes())?)
    }

    pub fn decrypt(&self, bytes: &[u8]) -> error::Result<String> {
        let iv: [u8; 32] = [0; 32];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k)?;
        let decrypted = bcrypt::decrypt_data(&k, &iv, bytes)?;
        Ok(String::from_utf8(decrypted)?)
    }

    pub fn mac(&self, label: &str, data: &[u8]) -> error::Result<Vec<u8>> {
        Ok(bcrypt::hmac_sha256_with_label(&self.s, &label, data)?)
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
    fn pk(&self) -> error::Result<Vec<u8>> {
        Ok(ncrypt::export_key(&self.key, Blob::EccPublic)?)
    }

    fn agree_and_derive(&self, pk: &[u8]) -> error::Result<Vec<u8>> {
        let pk = ncrypt::import_key(&self.prov, Blob::EccPublic, pk)?;
        let secret = ncrypt::secret_agreement(&self.key, &pk)?;
        Ok(ncrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}
