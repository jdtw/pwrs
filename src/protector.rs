use error;
use entry::{Decrypt, Entry};
use win32::bcrypt;
use win32::bcrypt::{Algorithm, Blob, SymAlg};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Protector {
    #[cfg(test)]
    Test(Vec<u8>),
    Software(String),
    SmartCard(String),
}

impl Decrypt for Protector {
    fn decrypt(&self, entry: &Entry) -> error::Result<String> {
        match self {
            #[cfg(test)]
            &Protector::Test(ref sk) => Ok(test_protector_decrypt(sk, entry)),
            &Protector::Software(ref _key_name) => panic!("notimpl"),
            &Protector::SmartCard(ref _key_name) => panic!("notimpl"),
        }
    }
}

impl Protector {
    pub fn protect(pk: &[u8], username: &str, password: &str) -> error::Result<Entry> {
        // TODO: Move this into Entry struct. The purpose of the protector should be to provide
        // the master secret. After that, the entry can encrypt and decrypt itself.

        // 1. Generate ephemeral ecdh key pair (pk_e, sk_e)
        let ephemeral = bcrypt::generate_key_pair(Algorithm::EcdhP256)?;
        let pk_e = bcrypt::export_key(&ephemeral, Blob::EccPublic)?;

        // 2. Do secret agreement with pk, sk_e
        let pk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, pk)?;
        let secret = bcrypt::secret_agreement(&ephemeral, &pk)?;
        let secret = bcrypt::derive_key(&secret, "PWRS")?;

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

        Ok(Entry::new(pk_e, username, encrypted, mac))
    }
}

#[cfg(test)]
fn new_test_protector() -> (Vec<u8>, Protector) {
    let k = bcrypt::generate_key_pair(Algorithm::EcdhP256).unwrap();
    let pk = bcrypt::export_key(&k, Blob::EccPublic).unwrap();
    let sk = bcrypt::export_key(&k, Blob::EccPrivate).unwrap();
    (pk, Protector::Test(sk))
}

#[cfg(test)]
fn test_protector_decrypt(sk: &[u8], entry: &Entry) -> String {
    let pk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, &entry.pk()).unwrap();
    let sk = bcrypt::import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &sk).unwrap();

    let secret = bcrypt::secret_agreement(&sk, &pk).unwrap();
    let secret = bcrypt::derive_key(&secret, "PWRS").unwrap();

    // TODO: The stuff below here should move into the entry struct itself. The protector provides
    // the master secret, and the entry can encrypt/decrypt itself after that.

    let secret = bcrypt::generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
    let keys = bcrypt::key_derivation(&secret, "PWRSKEYS", 64).unwrap();
    let keys = keys.chunks(32).collect::<Vec<&[u8]>>();

    let mac =
        bcrypt::hmac_sha256_with_label(keys[1], &entry.username(), &entry.encrypted_password())
            .unwrap();
    if mac != entry.mac() {
        panic!("MAC verification failed!");
    }

    let decryption_key = bcrypt::generate_symmetric_key(SymAlg::Aes256Cbc, keys[0]).unwrap();
    let iv: [u8; 32] = [0; 32];
    let decrypted =
        bcrypt::decrypt_data(&decryption_key, &iv, &entry.encrypted_password()).unwrap();

    String::from_utf8(decrypted).unwrap()
}

#[cfg(test)]
mod tests {
    use entry::{Decrypt, Entry};
    use super::*;

    #[test]
    fn test_protect_unprotect() {
        let (pk, protector) = new_test_protector();
        let entry = Protector::protect(&pk, "john", "password").unwrap();
        assert_eq!("password", protector.decrypt(&entry).unwrap());
    }
}
