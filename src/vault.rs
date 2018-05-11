//! A vault contains two things:
//! 1. An authenticator that knows how to encrypt/decrypt passwords.
//! 2. A set of `site -> (username, password)` entries.
//!
//! The `Vault` structure has methods for managing the vault entries,
//! as well as methods for serializing/deserializing to/from JSON (using `serde`).
//!
//! # Examples
//!
//! ```
//! use pwv::authenticator::Key;
//! use pwv::credentials::Credentials;
//! use pwv::vault::Vault;
//! use std::io::Write;
//!
//! let authenticator = Key::Software(String::from("example"))
//!     .into_authenticator()
//!     .unwrap();
//! let mut vault = Vault::new(authenticator);
//! let _pk = vault.thumbprint().unwrap();
//!
//! // Insert and encrypt the password
//! let creds = Credentials::new(
//!     String::from("user"),
//!     String::from("Pa$$w0rd!")
//! );
//! vault.insert(String::from("example.com"), creds).unwrap();
//!
//! // Retrieve and decrypt it
//! {
//!     let entry = vault.get("example.com").unwrap();
//!     assert_eq!(entry.site(), "example.com");
//!     assert_eq!(entry.username(), "user");
//!     assert_eq!(entry.decrypt_password().unwrap().str(), "Pa$$w0rd!");
//! }
//!
//! // Serialize and deserialize to/from buffer
//! let mut buffer = Vec::new();
//! vault.to_writer(buffer.by_ref()).unwrap();
//! let deserialized = Vault::from_reader(&buffer[..]).unwrap();
//! assert_eq!(deserialized, vault);
//!
//! let entry = deserialized.get("example.com").unwrap();
//! assert_eq!(entry.decrypt_password().unwrap().str(), "Pa$$w0rd!");
//!
//! // Delete the persistent "example" software key.
//! vault.delete().unwrap();
//!
//! // Note that the other copy of the vault, `deserialized`, will now
//! // fail to perform any decryptions because the private key shared by
//! // the two vaults is gone.
//! assert!(entry.decrypt_password().is_err());
//! ```
use authenticator::Authenticator;
use credentials::*;
use entry::Entry;
use error::*;
use serde_json;

use std::collections::hash_map;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::iter::Iterator;
use std::path::Path;

/// The password vault, containing `site -> (username, password)` entries.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    authenticator: Authenticator,
    entries: HashMap<String, Entry>,
}

/// A reference to a `site -> (username, password)` entry in
/// the vault, along with an interface for decrypting the password.
pub struct EntryRef<'a, 'b> {
    authenticator: &'a Authenticator,
    site: &'b str,
    entry: &'a Entry,
}

impl<'a, 'b> EntryRef<'a, 'b> {
    /// Retrieve the username associated with this entry
    pub fn username(&self) -> &str {
        self.entry.username()
    }

    /// Retrieve the site associated with this entry
    pub fn site(&self) -> &str {
        self.site
    }

    /// Uses the vault's [`Authenticator`] to decrypt the password.
    ///
    /// [`Authenticator`]: ../authenticator/index.html
    pub fn decrypt_password(&self) -> Result<Password, Error> {
        Ok(self.entry.decrypt_with(self.site, self.authenticator)?)
    }
}

/// An itertor over all vault entries, in arbitrary order.
pub struct VaultIter<'a> {
    authenticator: &'a Authenticator,
    entries: hash_map::Iter<'a, String, Entry>,
}

impl<'a> Iterator for VaultIter<'a> {
    type Item = EntryRef<'a, 'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|(site, entry)| EntryRef {
            authenticator: self.authenticator,
            site,
            entry,
        })
    }
}

impl Vault {
    /// Create a new, empty vault.
    pub fn new(authenticator: Authenticator) -> Vault {
        Vault {
            authenticator,
            entries: HashMap::new(),
        }
    }

    /// A SHA1 hash of the vault's public key. This should be displayed
    /// to the user after vault creation, and prior to encryption of a password.
    /// Since we blindly encrypt to whatever public key we find in the vault,
    /// and since there is no certificate associated with this key that we
    /// can validate, it is important to have *some* protection against an
    /// attacker placing their public key into the vault. Displaying the thumbprint
    /// is an easy way of doing this (assuming, of course, the user remembers what
    /// it should be).
    pub fn thumbprint(&self) -> Result<String, Error> {
        self.authenticator.pk().thumbprint()
    }

    /// Get an iterator over the vault entries, in no particular order.
    pub fn iter(&self) -> VaultIter {
        VaultIter {
            authenticator: &self.authenticator,
            entries: self.entries.iter(),
        }
    }

    /// Delete the key associated with the vault's authenticator. This does *not*
    /// delete the file from disk.
    pub fn delete(self) -> Result<(), Error> {
        self.authenticator.delete()
    }

    /// Serialize to a writer.
    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), Error> {
        serde_json::to_writer_pretty(writer, &self)?;
        Ok(())
    }

    /// Deserialize from a reader.
    pub fn from_reader<R: Read>(reader: R) -> Result<Vault, Error> {
        Ok(serde_json::from_reader(reader)?)
    }

    /// Deserialize from a file.
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Vault, Error> {
        let file = File::open(path.as_ref()).context(format!(
            "Open vault file '{}' failed",
            path.as_ref().display()
        ))?;
        Vault::from_reader(file)
    }

    /// Create a new vault file.
    pub fn write_new<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let vault_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path.as_ref())
            .context(format!(
                "Create new vault file failed: {}",
                path.as_ref().display()
            ))?;
        self.to_writer(vault_file)
    }

    /// Update the contents of the vault file (open existing file and truncate).
    pub fn write_update<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let vault_file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path.as_ref())
            .context(format!(
                "Open vault file for write failed: {}",
                path.as_ref().display()
            ))?;
        self.to_writer(vault_file)
    }

    /// Create a `site -> Credentials` entry in the vault. The password will
    /// be encrypted to the vault's public key. And since this is a public key
    /// operation, no authentication is required.
    pub fn insert(&mut self, site: String, creds: Credentials) -> Result<Option<Entry>, Error> {
        let (username, password) = creds.into_tuple();
        let entry = Entry::new(&self.authenticator, &site, username, password.str())?;
        Ok(self.entries.insert(site, entry))
    }

    /// Retrieve an entry from the vault. This does not cause the password to be decrypted.
    pub fn get<'a, 'b>(&'a self, site: &'b str) -> Option<EntryRef<'a, 'b>> {
        self.entries.get(site).map(|entry| EntryRef {
            authenticator: &self.authenticator,
            site,
            entry,
        })
    }

    /// Remove an entry from the vault.
    pub fn remove(&mut self, key: &str) -> Option<Entry> {
        self.entries.remove(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use authenticator::test;

    #[test]
    fn test_insert_get() {
        let authenticator = test::Test::new().unwrap();
        let mut vault = Vault::new(authenticator);
        vault
            .insert(
                String::from("key"),
                Credentials::new(String::from("username"), String::from("password")),
            )
            .unwrap();

        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username");
            let password = entry.decrypt_password().unwrap();
            assert_eq!(password.str(), "password");
        }
        // And make sure the entry didn't go anywhere
        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username");
            let password = entry.decrypt_password().unwrap();
            assert_eq!(password.str(), "password");
        }
        // Replace the entry
        vault
            .insert(
                String::from("key"),
                Credentials::new(String::from("username2"), String::from("password2")),
            )
            .unwrap();
        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username2");
            let password = entry.decrypt_password().unwrap();
            assert_eq!(password.str(), "password2");
        }
        // Now remove it
        let removed = vault.remove("key").unwrap();
        assert_eq!(removed.username(), "username2");
        assert!(vault.get("key").is_none());
    }

    #[test]
    fn serialize_deserialize_vault() {
        let authenticator = test::Test::new().unwrap();
        let mut vault = Vault::new(authenticator);
        vault
            .insert(
                String::from("foo.com"),
                Credentials::new(String::from("foo"), String::from("bar")),
            )
            .unwrap();
        vault
            .insert(
                String::from("example.com"),
                Credentials::new(String::from("user"), String::from("pass")),
            )
            .unwrap();

        let mut buffer = Vec::new();
        vault.to_writer(buffer.by_ref()).unwrap();
        let deserialized = Vault::from_reader(&buffer[..]).unwrap();
        assert_eq!(deserialized, vault);

        let entry = vault.get("foo.com").unwrap();
        let username = entry.username();
        assert_eq!(username, "foo");
        let password = entry.decrypt_password().unwrap();
        assert_eq!(password.str(), "bar");
    }
}
