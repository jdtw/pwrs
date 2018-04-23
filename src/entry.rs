use error;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pk: Vec<u8>, // ECDH P256
    username: String,
    encrypted_password: Vec<u8>, // AES-256 CBC
    mac: Vec<u8>,                // HMAC_SHA256(username||encrypted_password)
}

pub trait Decrypt {
    fn decrypt(&self, entry: &Entry) -> error::Result<String>;
}

impl Entry {
    pub fn new(pk: Vec<u8>, username: &str, encrypted_password: Vec<u8>, mac: Vec<u8>) -> Entry {
        Entry {
            pk,
            username: String::from(username),
            encrypted_password,
            mac,
        }
    }

    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn pk(&self) -> &[u8] {
        &self.pk
    }

    pub fn encrypted_password(&self) -> &[u8] {
        &self.encrypted_password
    }

    pub fn mac(&self) -> &[u8] {
        &self.mac
    }
}
