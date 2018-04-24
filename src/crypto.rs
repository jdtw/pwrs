use error;
use win32;
use win32::bcrypt;
use win32::bcrypt::{Algorithm, Blob, SymAlg};

// The ciphersuite we use is:
// - ECDH on P256 curve
// - NIST SP800 108 CTR KDF
// - AES256 CBC
// - HMAC SHA256

pub struct EcdhKeyPair {
    key: win32::Handle<bcrypt::Key>,
}

impl EcdhKeyPair {
    pub fn new() -> error::Result<Self> {
        let key = bcrypt::generate_key_pair(Algorithm::EcdhP256)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn pk(&self) -> error::Result<Vec<u8>> {
        let pk = bcrypt::export_key(&self.key, Blob::EccPublic)?;
        Ok(pk)
    }

    pub fn sk(&self) -> error::Result<Vec<u8>> {
        let sk = bcrypt::export_key(&self.key, Blob::EccPrivate)?;
        Ok(sk)
    }

    pub fn import(sk: &[u8]) -> error::Result<Self> {
        let key = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &sk)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn agree_and_derive(&self, pk: &[u8]) -> error::Result<Vec<u8>> {
        let pk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, &pk)?;
        let secret = bcrypt::secret_agreement(&self.key, &pk)?;
        let secret = bcrypt::derive_key(&secret, "pwrs_master_secret")?;
        Ok(secret)
    }
}

// AES key 'k', HMAC secret 's'
pub struct DerivedKeys {
    k: Vec<u8>,
    s: Vec<u8>,
}

impl DerivedKeys {
    pub fn new(secret: &[u8]) -> error::Result<Self> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret)?;
        let keys = bcrypt::key_derivation(&secret, "pwrs_application_keys", 64)?;
        let (k, s) = keys.split_at(32);
        Ok(DerivedKeys {
            k: k.to_vec(),
            s: s.to_vec(),
        })
    }

    pub fn encrypt(&self, string: &str) -> error::Result<Vec<u8>> {
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k)?;
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption.
        let iv: [u8; 32] = [0; 32];
        let encrypted = bcrypt::encrypt_data(&k, &iv, string.as_bytes())?;
        Ok(encrypted)
    }

    pub fn decrypt(&self, bytes: &[u8]) -> error::Result<String> {
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &self.k)?;
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption.
        let iv: [u8; 32] = [0; 32];
        let decrypted = bcrypt::decrypt_data(&k, &iv, bytes)?;
        let string = String::from_utf8(decrypted)?;
        Ok(string)
    }

    pub fn mac(&self, label: &str, data: &[u8]) -> error::Result<Vec<u8>> {
        let mac = bcrypt::hmac_sha256_with_label(&self.s, &label, &data)?;
        Ok(mac)
    }
}
