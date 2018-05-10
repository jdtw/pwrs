use authenticator::Authenticator;
use credentials::Password;
use crypto::*;
use error::{Error, PwrsError};

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pk: PubKey, // ECDH P256
    username: String,
    encrypted_password: EncryptedBytes, // AES-256 CBC
    mac: Mac,                           // HMAC_SHA256(site||username||encrypted_password)
}

impl Entry {
    pub fn new(
        authenticator: &Authenticator,
        site: &str,
        username: String,
        password: &str,
    ) -> Result<Entry, Error> {
        let ephemeral = EcdhKeyPair::new()?;
        let (k, s) = ephemeral
            .agree_and_derive(authenticator.pk())?
            .derive_keys()?;
        let encrypted_password = k.encrypt(password)?;
        let mac = s.mac(site, &username, &encrypted_password)?;

        Ok(Entry {
            pk: ephemeral.pk()?,
            username,
            encrypted_password,
            mac,
        })
    }

    pub fn decrypt_with(
        &self,
        site: &str,
        authenticator: &Authenticator,
    ) -> Result<Password, Error> {
        let (k, s) = authenticator
            .authenticator()
            .authenticate(&self.pk)?
            .derive_keys()?;
        let mac = s.mac(site, &self.username, &self.encrypted_password)?;
        if mac != self.mac {
            bail!(PwrsError::MacVerificationFailed);
        }
        Ok(Password::new(k.decrypt(&self.encrypted_password)?))
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
