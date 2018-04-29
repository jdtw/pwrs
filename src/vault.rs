use error::*;
use serde_json;
use entry::Entry;
use authenticator::Authenticator;

use std::collections::HashMap;
use std::io::prelude::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    authenticator: Authenticator,
    entries: HashMap<String, Entry>,
}

pub struct EntryRef<'a> {
    authenticator: &'a Authenticator,
    entry: &'a Entry,
}

impl<'a> EntryRef<'a> {
    pub fn username(&self) -> &str {
        self.entry.username()
    }

    pub fn password(&self) -> Result<String> {
        self.entry.decrypt_with(self.authenticator)
    }
}

impl Vault {
    pub fn new(authenticator: Authenticator) -> Vault {
        Vault {
            authenticator,
            entries: HashMap::new(),
        }
    }

    pub fn to_writer<W: Write>(&self, writer: W) -> Result<()> {
        Ok(serde_json::to_writer_pretty(writer, &self).chain_err(|| "Serialize to JSON failed")?)
    }

    pub fn from_reader<R: Read>(reader: R) -> Result<Vault> {
        Ok(serde_json::from_reader(reader).chain_err(|| "Deserialze from JSON failed")?)
    }

    pub fn insert(
        &mut self,
        key: String,
        username: String,
        password: &str,
    ) -> Result<Option<Entry>> {
        let entry = Entry::new(&self.authenticator, username, password)?;
        Ok(self.entries.insert(key, entry))
    }

    pub fn get(&self, key: &str) -> Option<EntryRef> {
        self.entries.get(key).map(|entry| EntryRef {
            authenticator: &self.authenticator,
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
            .insert(String::from("key"), String::from("username"), "password")
            .unwrap();

        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username");
            let password = entry.password().unwrap();
            assert_eq!(password, "password");
        }
        // And make sure the entry didn't go anywhere
        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username");
            let password = entry.password().unwrap();
            assert_eq!(password, "password");
        }
        // Replace the entry
        vault
            .insert(String::from("key"), String::from("username2"), "password2")
            .unwrap();
        {
            let entry = vault.get("key").unwrap();
            let username = entry.username();
            assert_eq!(username, "username2");
            let password = entry.password().unwrap();
            assert_eq!(password, "password2");
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
            .insert(String::from("foo.com"), String::from("foo"), "bar")
            .unwrap();
        vault
            .insert(String::from("example.com"), String::from("user"), "pass")
            .unwrap();

        let mut buffer = Vec::new();
        vault.to_writer(buffer.by_ref()).unwrap();
        let deserialized = Vault::from_reader(&buffer[..]).unwrap();
        assert_eq!(deserialized, vault);

        let entry = vault.get("foo.com").unwrap();
        let username = entry.username();
        assert_eq!(username, "foo");
        let password = entry.password().unwrap();
        assert_eq!(password, "bar");
    }
}
