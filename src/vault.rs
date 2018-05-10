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

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    authenticator: Authenticator,
    entries: HashMap<String, Entry>,
}

pub struct EntryRef<'a, 'b> {
    authenticator: &'a Authenticator,
    site: &'b str,
    entry: &'a Entry,
}

impl<'a, 'b> EntryRef<'a, 'b> {
    pub fn username(&self) -> &str {
        self.entry.username()
    }

    pub fn site(&self) -> &str {
        self.site
    }

    pub fn decrypt_password(&self) -> Result<Password, Error> {
        Ok(self.entry.decrypt_with(self.site, self.authenticator)?)
    }
}

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
    pub fn new(authenticator: Authenticator) -> Vault {
        Vault {
            authenticator,
            entries: HashMap::new(),
        }
    }

    pub fn thumbprint(&self) -> Result<String, Error> {
        self.authenticator.pk().thumbprint()
    }

    pub fn iter(&self) -> VaultIter {
        VaultIter {
            authenticator: &self.authenticator,
            entries: self.entries.iter(),
        }
    }

    pub fn delete(self) -> Result<(), Error> {
        self.authenticator.delete()
    }

    pub fn to_writer<W: Write>(&self, writer: W) -> Result<(), Error> {
        serde_json::to_writer_pretty(writer, &self)?;
        Ok(())
    }

    pub fn from_reader<R: Read>(reader: R) -> Result<Vault, Error> {
        Ok(serde_json::from_reader(reader)?)
    }

    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Vault, Error> {
        let file = File::open(path.as_ref()).context(format!(
            "Open vault file '{}' failed",
            path.as_ref().display()
        ))?;
        Vault::from_reader(file)
    }

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

    pub fn insert(&mut self, site: String, creds: Credentials) -> Result<Option<Entry>, Error> {
        let (username, password) = creds.into_tuple();
        let entry = Entry::new(&self.authenticator, &site, username, password.str())?;
        Ok(self.entries.insert(site, entry))
    }

    pub fn get<'a, 'b>(&'a self, site: &'b str) -> Option<EntryRef<'a, 'b>> {
        self.entries.get(site).map(|entry| EntryRef {
            authenticator: &self.authenticator,
            site,
            entry,
        })
    }

    pub fn remove(&mut self, key: &str) -> Option<Entry> {
        self.entries.remove(key)
    }

    pub fn authenticator(&self) -> &Authenticator {
        &self.authenticator
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
