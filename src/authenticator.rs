//! Each vault contains an `Authenticator` that provides an abstraction over
//! private key operations.

use crypto::*;
use error::Error;

/// The `Authenticate` trait provides an abstraction for the ECDH
/// private key operation.
pub trait Authenticate {
    /// Takes in a public key to perform key agreement with, and outputs
    /// the result of that key agreement.
    fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error>;
}

/// A key that will be stored in a [CNG key storage provider][cng]
///
/// [cng]: https://msdn.microsoft.com/en-us/library/windows/desktop/bb931355(v=vs.85).aspx
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Key {
    /// A key that will be stored in the software KSP.
    Software(String),
    /// A key that will be stored in the smart card KSP.
    SmartCard(String),
}

impl Key {
    /// Consumes the `Key` and creates an `Authenticator` from it.
    pub fn into_authenticator(self) -> Result<Authenticator, Error> {
        let key = {
            let (ksp, key_name) = match &self {
                Key::Software(key_name) => (KeyStorage::Software, key_name),
                Key::SmartCard(key_name) => (KeyStorage::SmartCard, key_name),
            };
            KspEcdhKeyPair::new(ksp, key_name)?
        };
        Ok(Authenticator {
            pk: key.pk()?,
            authenticator: AuthenticatorType::Ksp(self),
        })
    }

    fn delete(self) -> Result<(), Error> {
        let (ksp, key_name) = match self {
            Key::Software(key_name) => (KeyStorage::Software, key_name),
            Key::SmartCard(key_name) => (KeyStorage::SmartCard, key_name),
        };
        KspEcdhKeyPair::open(ksp, &key_name)?.delete()
    }
}

impl Authenticate for Key {
    fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
        let (ksp, key_name) = match self {
            Key::Software(key_name) => (KeyStorage::Software, key_name),
            Key::SmartCard(key_name) => (KeyStorage::SmartCard, key_name),
        };
        KspEcdhKeyPair::open(ksp, key_name)?.agree_and_derive(pk)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum AuthenticatorType {
    #[cfg(test)]
    Test(test::Test),
    Ksp(Key),
}

/// Manages the vault's ECDH key pair.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Authenticator {
    pk: PubKey,
    authenticator: AuthenticatorType,
}

impl Authenticator {
    /// The vault's public key.
    pub fn pk(&self) -> &PubKey {
        &self.pk
    }

    /// Return an `Authenticate` trait object.
    pub fn authenticator(&self) -> &Authenticate {
        match self.authenticator {
            #[cfg(test)]
            AuthenticatorType::Test(ref test) => test,
            AuthenticatorType::Ksp(ref ksp) => ksp,
        }
    }

    /// Delete the persisted key stored by the `Authenticator`.
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
    use seckey::SecKey;

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    pub struct Test([u8; P256_CURVE_SIZE]);
    impl Test {
        pub fn new() -> Result<Authenticator, Error> {
            let key = EcdhKeyPair::new()?;
            let sk = key.sk()?;
            let sk = *sk.d.read();
            Ok(Authenticator {
                pk: key.pk()?,
                authenticator: AuthenticatorType::Test(Test(sk)),
            })
        }
    }

    impl Authenticate for Test {
        fn authenticate(&self, pk: &PubKey) -> Result<AgreedSecret, Error> {
            let sk = EcdhKeyPair::import(&PrivKey {
                d: SecKey::new(self.0).unwrap(),
            })?;
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
        let entry = Entry::new(
            &authenticator,
            "example.com",
            String::from("john"),
            "password🔐",
        ).unwrap();
        let decrypted = entry.decrypt_with("example.com", &authenticator).unwrap();
        assert_eq!("password🔐", decrypted.str());
        assert!(
            entry
                .decrypt_with("someothersite.com", &authenticator)
                .is_err()
        );
    }

    #[test]
    fn test_ksp_protect_unprotect() {
        let authenticator = Key::Software(String::from("testkey1"))
            .into_authenticator()
            .unwrap();
        let entry = Entry::new(
            &authenticator,
            "facebook.com",
            String::from("john"),
            "password",
        ).unwrap();
        let decrypted = entry.decrypt_with("facebook.com", &authenticator).unwrap();
        authenticator.delete().unwrap();
        assert_eq!("password", decrypted.str());
    }
}
