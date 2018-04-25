use error;
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

impl Vault {
    pub fn new(authenticator: Authenticator) -> Vault {
        Vault {
            authenticator,
            entries: HashMap::new(),
        }
    }

    pub fn write<W: Write>(&self, writer: W) -> error::Result<()> {
        Ok(serde_json::to_writer(writer, &self)?)
    }

    pub fn read<R: Read>(reader: R) -> error::Result<Vault> {
        Ok(serde_json::from_reader(reader)?)
    }

    pub fn insert(
        &mut self,
        key: String,
        username: String,
        password: &str,
    ) -> error::Result<Option<Entry>> {
        let entry = Entry::new(&self.authenticator, username, password)?;
        Ok(self.entries.insert(key, entry))
    }

    pub fn get(&self, key: &str) -> error::Result<Option<(String, String)>> {
        match self.entries.get(key) {
            Some(entry) => {
                let password = entry.decrypt_with(&self.authenticator)?;
                Ok(Some((String::from(entry.username()), password)))
            }
            None => Ok(None),
        }
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
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
        let (username, password) = vault.get("key").unwrap().unwrap();
        assert_eq!(username, "username");
        assert_eq!(password, "password");
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
        let serialized = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, vault);
    }
}
