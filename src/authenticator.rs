use crypto::*;
use error::Error;
pub use win32::ncrypt::Ksp;

pub trait Authenticate {
    // In: entry public key, Out: secret
    fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error>;
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyStorageProvider {
    ksp: Ksp,
    key_name: String,
}

impl KeyStorageProvider {
    pub fn new(ksp: Ksp, key_name: String) -> Result<Authenticator, Error> {
        let key = KspEcdhKeyPair::new(ksp, &key_name)?;
        Ok(Authenticator {
            pk: key.pk()?,
            authenticator: AuthenticatorType::Ksp(KeyStorageProvider { ksp, key_name }),
        })
    }

    fn delete(self) -> Result<(), Error> {
        KspEcdhKeyPair::open(self.ksp, &self.key_name)?.delete()
    }
}

impl Authenticate for KeyStorageProvider {
    fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        KspEcdhKeyPair::open(self.ksp, &self.key_name)?.agree_and_derive(pk)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum AuthenticatorType {
    #[cfg(test)]
    Test(test::Test),
    Ksp(KeyStorageProvider),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Authenticator {
    pk: PubKey,
    authenticator: AuthenticatorType,
}

impl Authenticator {
    pub fn pk(&self) -> &PubKey {
        &self.pk
    }

    // Authenticate takes in a public key and returns the result of ECDH
    // key agreement with that key, using the authenticator's private key.
    pub fn authenticator(&self) -> &Authenticate {
        match &self.authenticator {
            #[cfg(test)]
            &AuthenticatorType::Test(ref test) => test,
            &AuthenticatorType::Ksp(ref ksp) => ksp,
        }
    }

    pub fn delete(self) -> Result<(), Error> {
        match self.authenticator {
            #[cfg(test)]
            AuthenticatorType::Test(_) => Ok(()),
            AuthenticatorType::Ksp(ksp) => ksp.delete(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crypto::EcdhKeyPair;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub struct Test(PrivKey);
    impl Test {
        pub fn new() -> Result<Authenticator, Error> {
            let key = EcdhKeyPair::new()?;
            Ok(Authenticator {
                pk: key.pk()?,
                authenticator: AuthenticatorType::Test(Test(key.sk()?)),
            })
        }
    }
    impl Authenticate for Test {
        fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
            let sk = EcdhKeyPair::import(&self.0)?;
            sk.agree_and_derive(pk)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use entry::Entry;

    #[test]
    fn test_test_protect_unprotect() {
        let authenticator = test::Test::new().unwrap();
        let entry = Entry::new(&authenticator, String::from("john"), "password🔐").unwrap();
        let decrypted = entry.decrypt_with(&authenticator).unwrap();
        assert_eq!("password🔐", decrypted);
    }

    #[test]
    fn test_ksp_protect_unprotect() {
        let authenticator =
            KeyStorageProvider::new(Ksp::Software, String::from("testkey1")).unwrap();
        let entry = Entry::new(&authenticator, String::from("john"), "password").unwrap();
        let decrypted = entry.decrypt_with(&authenticator).unwrap();
        authenticator.delete().unwrap();
        assert_eq!("password", decrypted);
    }
}
