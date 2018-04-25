use error;
use crypto::*;

pub trait Authenticate {
    // In: entry public key, Out: secret
    fn authenticate(&self, pk: &PubKey) -> error::Result<AgreedSecret>;
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyStorageProvider(Ksp, String);
impl KeyStorageProvider {
    pub fn new(ksp: Ksp, key_name: String) -> error::Result<Authenticator> {
        let key = KspEcdhKeyPair::new(ksp, &key_name)?;
        Ok(Authenticator {
            pk: key.pk()?,
            authenticator: AuthenticatorType::Ksp(KeyStorageProvider(ksp, key_name)),
        })
    }
}
impl Authenticate for KeyStorageProvider {
    fn authenticate(&self, pk: &PubKey) -> error::Result<AgreedSecret> {
        let key = KspEcdhKeyPair::open(self.0, &self.1)?;
        key.agree_and_derive(pk)
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
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crypto::EcdhKeyPair;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub struct Test(PrivKey);
    impl Test {
        pub fn new() -> error::Result<Authenticator> {
            let key = EcdhKeyPair::new()?;
            Ok(Authenticator {
                pk: key.pk()?,
                authenticator: AuthenticatorType::Test(Test(key.sk()?)),
            })
        }
    }
    impl Authenticate for Test {
        fn authenticate(&self, pk: &PubKey) -> error::Result<AgreedSecret> {
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
        let entry = Entry::new(&authenticator, String::from("john"), "password").unwrap();
        let decrypted = entry.decrypt_with(&authenticator).unwrap();
        assert_eq!("password", decrypted);
    }

    #[test]
    fn test_ksp_protect_unprotect() {
        let authenticator =
            KeyStorageProvider::new(Ksp::Software, String::from("testkey1")).unwrap();
        let entry = Entry::new(&authenticator, String::from("john"), "password").unwrap();
        let decrypted = entry.decrypt_with(&authenticator).unwrap();
        let key = KspEcdhKeyPair::open(Ksp::Software, "testkey1").unwrap();
        key.delete().unwrap();
        assert_eq!("password", decrypted);
    }
}
