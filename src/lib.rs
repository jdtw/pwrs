extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

pub mod win32;
pub mod utils;
pub mod error;
pub mod protector;
pub mod entry;

use protector::Protector;
use entry::Entry;

use std::collections::HashMap;
use std::io::prelude::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    pk: Vec<u8>,
    protector: Protector,
    entries: HashMap<String, Entry>,
}

impl Vault {
    pub fn new(pk: Vec<u8>, protector: Protector) -> Vault {
        Vault {
            pk,
            protector,
            entries: HashMap::new(),
        }
    }

    pub fn new_entry(
        &mut self,
        key: &str,
        username: &str,
        password: &str,
    ) -> error::Result<&Entry> {
        let entry = Protector::protect(&self.pk, username, password)?;
        self.entries.insert(String::from(key), entry);
        Ok(&self.entries[key])
    }

    pub fn write<W: Write>(&self, writer: W) -> error::Result<()> {
        Ok(serde_json::to_writer(writer, &self)?)
    }

    pub fn read<R: Read>(reader: R) -> error::Result<Vault> {
        Ok(serde_json::from_reader(reader)?)
    }

    pub fn get(&self, key: &str) -> Option<&Entry> {
        self.entries.get(key)
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    //    #[test]
    //    fn new_entry() {
    //        let entry = Entry::new(&Vec::new(), "foo", "bar");
    //        assert!(entry.pk.is_empty());
    //        assert!(entry.encrypted_password.is_empty());
    //        assert_eq!(entry.username, "foo");
    //        assert!(entry.mac.is_empty());
    //    }
    //
    //    #[test]
    //    fn decrypt_entry() {
    //        let entry = Entry::new(&Vec::new(), "foo", "bar");
    //        let protector = TestProtector::new("foobar");
    //        let decrypted = protector.decrypt(&entry).unwrap();
    //        assert_eq!("foobar", decrypted);
    //    }
    //
    //    #[test]
    //    fn new_entry_from_vault() {
    //        let mut vault = Vault::new(vec![1, 2, 3]);
    //        assert_eq!(vec![1, 2, 3], vault.pk);
    //        let entry = vault.new_entry("example.com", "foo", "bar");
    //        assert_eq!(entry.username, "foo");
    //    }
    //
    //    #[test]
    //    fn serialize_deserialize_vault() {
    //        let mut vault = Vault::new(vec![1, 2, 3]);
    //        vault.new_entry("foo.com", "foo", "bar");
    //        vault.new_entry("example.com", "user", "pass");
    //        let serialized = serde_json::to_string(&vault).unwrap();
    //        let deserialized: Vault = serde_json::from_str(&serialized).unwrap();
    //        assert_eq!(deserialized, vault);
    //    }
}
