use error::*;
use utils::ToHex;
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

impl PubKey {
    pub fn thumbprint(&self) -> Result<String, Error> {
        let hash = bcrypt::hash_sha1(&self.0)?;
        Ok(hash.to_hex())
    }
}

pub trait KeyPair {
    fn pk(&self) -> Result<PubKey, Error>;
    fn agree_and_derive(&self, pk: &PubKey) -> Result<AgreedSecret, Error>;
}

pub struct EcdhKeyPair {
    key: win32::Handle<bcrypt::Key>,
}

impl EcdhKeyPair {
    pub fn new() -> Result<Self, Error> {
        let key = bcrypt::generate_key_pair(Algorithm::EcdhP256)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn import(sk: &PrivKey) -> Result<Self, Error> {
        let key = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &sk.0)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn sk(&self) -> Result<PrivKey, Error> {
        Ok(PrivKey(bcrypt::export_key(&self.key, Blob::EccPrivate)?))
    }
}

impl KeyPair for EcdhKeyPair {
    fn pk(&self) -> Result<PubKey, Error> {
        Ok(PubKey(bcrypt::export_key(&self.key, Blob::EccPublic)?))
    }

    fn agree_and_derive(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
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
    k: Option<EncryptionKey>,
    s: MacSecret,
}
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBytes(Vec<u8>);
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mac(Vec<u8>);

impl DerivedKeys {
    pub fn new(secret: &AgreedSecret) -> Result<Self, Error> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret.0)?;
        let keys = bcrypt::key_derivation(&secret, DERIVED_KEYS_LABEL, 64)?;
        let (k, s) = keys.split_at(32);
        Ok(DerivedKeys {
            k: Some(EncryptionKey(k.to_vec())),
            s: MacSecret(s.to_vec()),
        })
    }

    pub fn encrypt(&mut self, string: &str) -> Result<EncryptedBytes, Error> {
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption. (This is enforced by the fact that we `take` the
        // key material here.)
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(
            SymAlg::Aes256Cbc,
            &self.k
                .take()
                .expect("Cannot encrypt twice with the same key")
                .0,
        )?;
        Ok(EncryptedBytes(bcrypt::encrypt_data(
            &k,
            &iv,
            string.as_bytes(),
        )?))
    }

    pub fn decrypt(&self, bytes: &EncryptedBytes) -> Result<String, Error> {
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k.as_ref().unwrap().0)?;
        let decrypted = bcrypt::decrypt_data(&k, &iv, &bytes.0)?;
        Ok(String::from_utf8(decrypted)?)
    }

    pub fn mac(&self, site: &str, username: &str, data: &EncryptedBytes) -> Result<Mac, Error> {
        let hash = bcrypt::Hash::new(bcrypt::HashAlg::HmacSha256(&self.s.0))?;
        hash.hash_data(site.as_bytes())?;
        hash.hash_data(username.as_bytes())?;
        hash.hash_data(&data.0)?;
        let mac = hash.finish_hash()?;
        Ok(Mac(mac))
    }
}

pub struct KspEcdhKeyPair {
    prov: win32::Handle<ncrypt::Object>,
    key: win32::Handle<ncrypt::Object>,
}

impl KspEcdhKeyPair {
    pub fn new(ksp: Ksp, name: &str) -> Result<KspEcdhKeyPair, Error> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::create_persisted_key(&prov, Algorithm::EcdhP256, Some(name))?;
        ncrypt::finalize_key(&key)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    pub fn open(ksp: Ksp, name: &str) -> Result<KspEcdhKeyPair, Error> {
        let prov = ncrypt::open_storage_provider(ksp)?;
        let key = ncrypt::open_key(&prov, name)?;
        Ok(KspEcdhKeyPair { prov, key })
    }

    pub fn delete(self) -> Result<(), Error> {
        Ok(ncrypt::delete_key(self.key)?)
    }
}

impl KeyPair for KspEcdhKeyPair {
    fn pk(&self) -> Result<PubKey, Error> {
        Ok(PubKey(ncrypt::export_key(&self.key, Blob::EccPublic)?))
    }

    fn agree_and_derive(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let pk = ncrypt::import_key(&self.prov, Blob::EccPublic, &pk.0)?;
        let secret = ncrypt::secret_agreement(&self.key, &pk)?;
        Ok(AgreedSecret(ncrypt::derive_key(
            &secret,
            MASTER_SECRET_LABEL,
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn test_encrypt_twice_fails() {
        let secret = AgreedSecret(bcrypt::gen_random(32).unwrap());
        let mut keys = DerivedKeys::new(&secret).unwrap();
        keys.encrypt("foobar").unwrap();
        // We don't allow encryption twice (because we use an all-zero IV)
        keys.encrypt("fizzle").unwrap();
    }
}
