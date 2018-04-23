use error;
use entry;
use win32::ncrypt;
use win32::ncrypt::{Algorithm, Blob, Ksp};
use win32::bcrypt;
use win32::bcrypt::SymAlg;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Protector {
    #[cfg(test)]
    Test(Vec<u8>),
    Software(String),
    SmartCard(String),
}

impl entry::Decrypt for Protector {
    fn decrypt(&self, _entry: &entry::Entry) -> error::Result<String> {
        match self {
            #[cfg(test)]
            &Protector::Test(ref _pk) => (),
            &Protector::Software(ref _key_name) => (),
            &Protector::SmartCard(ref _key_name) => (),
        }
        panic!("notimpl");
    }
}

impl Protector {
    pub fn protect(pk: &[u8], username: &str, password: &str) -> error::Result<entry::Entry> {
        // 1. Generate ephemeral ecdh key pair (pk_e, sk_e)
        let prov = ncrypt::open_storage_provider(Ksp::Software)?;
        let ephemeral = ncrypt::create_persisted_key(&prov, Algorithm::EcdhP256, None)?;
        ncrypt::finalize_key(&ephemeral)?;
        let pk_e = ncrypt::export_key(&ephemeral, Blob::EccPublic)?;

        // 2. Do secret agreement with pk, sk_e
        let pk = ncrypt::import_key(&prov, Blob::EccPublic, pk)?;
        let secret = ncrypt::secret_agreement(&ephemeral, &pk)?;
        let secret = ncrypt::derive_key(&secret, "PWRS")?;

        // 3. Use KDF to get encryption key k and mac secret s
        let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret)?;
        let keys = bcrypt::key_derivation(&secret, "PWRSKEYS", 64)?;
        let keys = keys.chunks(32).collect::<Vec<&[u8]>>();

        // 4. Encrypt password (with zero IV) with k
        let encryption_key = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, keys[0])?;
        let iv: [u8; 32] = [0; 32];
        let encrypted = bcrypt::encrypt_data(&encryption_key, &iv, password.as_bytes())?;

        // 5. Mac user_name||encrypted_password with s
        let mac = bcrypt::hmac_sha256_with_label(keys[1], username, &encrypted)?;

        Ok(entry::Entry::new(pk_e, username, encrypted, mac))
    }
}
