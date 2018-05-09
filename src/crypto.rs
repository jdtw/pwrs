use error::*;
use seckey::SecKey;
use utils::to_hex;
use win32;
use win32::bcrypt;
use win32::bcrypt::SymAlg;
use win32::ncrypt;
pub use win32::ncrypt::Ksp;

// The ciphersuite we use is:
// - ECDH on P256 curve
// - NIST SP800 108 CTR KDF
// - AES256 CBC
// - HMAC SHA256

const MASTER_SECRET_LABEL: &'static str = "pwrs_master_secret";
const DERIVED_KEYS_LABEL: &'static str = "pwrs_derived_keys";

pub const P256_CURVE_SIZE: usize = 32;
pub const SHA2_DIGEST_SIZE: usize = 32;
pub const SHA1_DIGEST_SIZE: usize = 20;
pub const AES256_KEY_SIZE: usize = 32;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct PubKey {
    pub x: [u8; P256_CURVE_SIZE],
    pub y: [u8; P256_CURVE_SIZE],
}

#[derive(Debug)]
pub struct PrivKey {
    pub d: SecKey<[u8; P256_CURVE_SIZE]>,
}
#[derive(Debug)]
pub struct AgreedSecret {
    pub s: SecKey<[u8; SHA2_DIGEST_SIZE]>,
}
impl AgreedSecret {
    pub fn derive_keys(self) -> Result<(EncryptionKey, MacSecret), Error> {
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &*self.s.read())?;
        Ok(bcrypt::key_derivation(&secret, DERIVED_KEYS_LABEL)?)
    }
}

impl PubKey {
    pub fn thumbprint(&self) -> Result<String, Error> {
        let hash = bcrypt::HashSha1::new()?
            .hash(&self.x)?
            .hash(&self.y)?
            .finish_hash()?;
        Ok(to_hex(&hash))
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
        let key = bcrypt::generate_ecdh_p256_key_pair()?;
        Ok(EcdhKeyPair { key })
    }

    pub fn import(sk: &PrivKey) -> Result<Self, Error> {
        let key = bcrypt::import_ecdh_p256_priv_key(sk)?;
        Ok(EcdhKeyPair { key })
    }

    pub fn sk(&self) -> Result<PrivKey, Error> {
        Ok(bcrypt::export_ecdh_p256_priv_key(&self.key)?)
    }
}

impl KeyPair for EcdhKeyPair {
    fn pk(&self) -> Result<PubKey, Error> {
        Ok(bcrypt::export_ecdh_p256_pub_key(&self.key)?)
    }

    fn agree_and_derive(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let pk = bcrypt::import_ecdh_p256_pub_key(pk)?;
        let secret = bcrypt::secret_agreement(&self.key, &pk)?;
        Ok(bcrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}

// AES key 'k', HMAC secret 's'
#[derive(Debug)]
pub struct EncryptionKey(pub SecKey<[u8; AES256_KEY_SIZE]>);
#[derive(Debug)]
pub struct MacSecret(pub SecKey<[u8; SHA2_DIGEST_SIZE]>);
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptedBytes(Vec<u8>);

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Mac([u8; SHA2_DIGEST_SIZE]);

impl EncryptionKey {
    pub fn encrypt(self, string: &str) -> Result<EncryptedBytes, Error> {
        // It's safe to encrypt with a zero IV because we generate new keys
        // for every encryption. (This is enforced by the fact that we `take` the
        // key material here.)
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &*self.0.read())?;
        Ok(EncryptedBytes(bcrypt::encrypt_data(
            &k,
            &iv,
            string.as_bytes(),
        )?))
    }

    pub fn decrypt(&self, bytes: &EncryptedBytes) -> Result<String, Error> {
        let iv: [u8; 16] = [0; 16];
        let k = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, &*self.0.read())?;
        let decrypted = bcrypt::decrypt_data(&k, &iv, &bytes.0)?;
        Ok(String::from_utf8(decrypted)?)
    }
}

impl MacSecret {
    pub fn mac(&self, site: &str, username: &str, data: &EncryptedBytes) -> Result<Mac, Error> {
        let mac = bcrypt::HmacSha2::new(&*self.0.read())?
            .hash(site.as_bytes())?
            .hash(username.as_bytes())?
            .hash(&data.0)?
            .finish_hash()?;
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
        let key = ncrypt::create_persisted_ecdh_p256_key(&prov, Some(name))?;
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
        Ok(ncrypt::export_ecdh_p256_pub_key(&self.key)?)
    }

    fn agree_and_derive(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let pk = ncrypt::import_ecdh_p256_pub_key(&self.prov, pk)?;
        let secret = ncrypt::secret_agreement(&self.key, &pk)?;
        Ok(ncrypt::derive_key(&secret, MASTER_SECRET_LABEL)?)
    }
}
