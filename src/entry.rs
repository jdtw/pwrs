use error;
use crypto::{DerivedKeys, EcdhKeyPair, KeyPair};
use authenticator::Authenticator;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pk: Vec<u8>, // ECDH P256
    username: String,
    encrypted_password: Vec<u8>, // AES-256 CBC
    mac: Vec<u8>,                // HMAC_SHA256(username||encrypted_password)
}

impl Entry {
    pub fn new(
        authenticator: &Authenticator,
        username: &str,
        password: &str,
    ) -> error::Result<Entry> {
        let ephemeral = EcdhKeyPair::new()?;
        let secret = ephemeral.agree_and_derive(authenticator.pk())?;
        let keys = DerivedKeys::new(&secret)?;
        let encrypted_password = keys.encrypt(password)?;
        let mac = keys.mac(username, &encrypted_password)?;

        Ok(Entry {
            pk: ephemeral.pk()?,
            username: String::from(username),
            encrypted_password,
            mac,
        })
    }

    pub fn decrypt(&self, authenticator: &Authenticator) -> error::Result<String> {
        let secret = authenticator.authenticator().authenticate(&self.pk)?;
        let keys = DerivedKeys::new(&secret)?;
        let mac = keys.mac(&self.username, &self.encrypted_password)?;
        if mac != self.mac {
            assert_eq!(mac, self.mac);
            panic!("MAC verification failed!");
        }
        keys.decrypt(&self.encrypted_password)
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
