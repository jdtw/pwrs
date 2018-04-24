use error;
use win32::ncrypt;
#[cfg(test)]
use crypto::EcdhKeyPair;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Authenticator {
    #[cfg(test)]
    Test(Vec<u8>),
    Software(String),
    SmartCard(String),
}

pub trait Authenticate {
    // TODO: Should probably make the authenticator carry around its own
    // public key.
    fn authenticate(&self, pk: &[u8]) -> error::Result<Vec<u8>>;
}

impl Authenticate for Authenticator {
    // Authenticate takes in a public key and returns the result of
    // ECDH key agreement with that key, using the authenticator's private
    // key.
    fn authenticate(&self, pk: &[u8]) -> error::Result<Vec<u8>> {
        match self {
            #[cfg(test)]
            &Authenticator::Test(ref sk) => Ok(tests::authenticate(sk, pk)),
            &Authenticator::Software(ref _key_name) => panic!("notimpl"),
            &Authenticator::SmartCard(ref _key_name) => panic!("notimpl"),
        }
    }
}

#[cfg(test)]
pub fn new_test_authenticator() -> error::Result<(Vec<u8>, Authenticator)> {
    let key = EcdhKeyPair::new()?;
    Ok((key.pk().unwrap(), Authenticator::Test(key.sk().unwrap())))
}

pub fn new_software_authenticator() -> error::Result<(Vec<u8>, Authenticator)> {
    new_ksp_authenticator(ncrypt::Ksp::Software)
}

pub fn new_smart_card_authenticator() -> error::Result<(Vec<u8>, Authenticator)> {
    new_ksp_authenticator(ncrypt::Ksp::SmartCard)
}

fn new_ksp_authenticator(_ksp: ncrypt::Ksp) -> error::Result<(Vec<u8>, Authenticator)> {
    // TODO:
    // 1. Generate key name
    // 2. Create persisted key
    // 3. Export public key
    // return (pk, Authenticator::Type(key_name))
    panic!("notimpl");
}

#[cfg(test)]
mod tests {
    use super::*;
    use entry::Entry;

    pub fn authenticate(sk: &[u8], pk: &[u8]) -> Vec<u8> {
        let sk = EcdhKeyPair::import(sk).unwrap();
        sk.agree_and_derive(pk).unwrap()
    }

    #[test]
    fn test_protect_unprotect() {
        let (pk, authenticator) = new_test_authenticator().unwrap();
        let entry = Entry::new(&pk, "john", "password").unwrap();
        let decrypted = entry.decrypt(&authenticator).unwrap();
        assert_eq!("password", decrypted);
    }
}
