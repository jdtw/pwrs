use authenticator::Authenticator;
use crypto::*;
use error::{Error, PwrsError};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pk: PubKey, // ECDH P256
    // TODO: Site needs to be part of the entry, and must be included in the MAC
    username: String,
    encrypted_password: EncryptedBytes, // AES-256 CBC
    mac: Mac,                           // HMAC_SHA256(username||encrypted_password)
}

impl Entry {
    pub fn new(
        authenticator: &Authenticator,
        username: String,
        password: &str,
    ) -> Result<Entry, Error> {
        let ephemeral = EcdhKeyPair::new()?;
        let secret = ephemeral.agree_and_derive(authenticator.pk())?;
        let keys = DerivedKeys::new(&secret)?;
        let encrypted_password = keys.encrypt(password)?;
        let mac = keys.mac(&username, &encrypted_password)?;

        Ok(Entry {
            pk: ephemeral.pk()?,
            username,
            encrypted_password,
            mac,
        })
    }

    pub fn decrypt_with(&self, authenticator: &Authenticator) -> Result<String, Error> {
        let secret = authenticator.authenticator().authenticate(&self.pk)?;
        let keys = DerivedKeys::new(&secret)?;
        let mac = keys.mac(&self.username, &self.encrypted_password)?;
        if mac != self.mac {
            bail!(PwrsError::MacVerificationFailed);
        }
        Ok(keys.decrypt(&self.encrypted_password)?)
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
