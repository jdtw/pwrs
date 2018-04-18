extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

use std::io;
use std::io::prelude::*;
use std::collections::HashMap;

extern crate winapi;

pub mod ncrypt {
    use winapi::shared::bcrypt::*;
    use winapi::shared::minwindef::ULONG;
    use winapi::um::winnt::LPCWSTR;
    use winapi::shared::basetsd::ULONG_PTR;
    use std::ffi::OsStr;
    use std::iter::once;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    type DWORD = ULONG;
    type SECURITY_STATUS = i32;

    const NCRYPT_SILENT_FLAG: ULONG = 0x00000040;
    const NCRYPT_IGNORE_DEVICE_STATE_FLAG: ULONG = 0x00001000;

    type NCRYPT_HANDLE = ULONG_PTR;
    type NCRYPT_PROV_HANDLE = ULONG_PTR;
    type NCRYPT_HASH_HANDLE = ULONG_PTR;
    type NCRYPT_KEY_HANDLE = ULONG_PTR;
    type NCRYPT_SECRET_HANDLE = ULONG_PTR;

    const MS_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Software Key Storage Provider";
    const MS_SMART_CARD_KEY_STORAGE_PROVIDER: &'static str =
        "Microsoft Smart Card Key Storage Provider";
    const MS_PLATFORM_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Platform Crypto Provider";
    const MS_NGC_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Passport Key Storage Provider";

    pub enum Ksp {
        Software,
        SmartCard,
        Tpm,
        Ngc,
    }

    #[link(name = "ncrypt")]
    extern "stdcall" {
        fn NCryptOpenStorageProvider(
            phProvider: *mut NCRYPT_PROV_HANDLE,
            pszProviderName: LPCWSTR,
            dwFlags: DWORD,
        ) -> SECURITY_STATUS;

        fn NCryptFreeObject(hObject: NCRYPT_HANDLE) -> SECURITY_STATUS;

        fn NCryptCreatePersistedKey(
            hProvider: NCRYPT_PROV_HANDLE,
            phKey: *mut NCRYPT_KEY_HANDLE,
            pszAlgId: LPCWSTR,
            pszKeyName: LPCWSTR,
            dwLegacyKeySpec: DWORD,
            dwFlags: DWORD,
        ) -> SECURITY_STATUS;

        fn NCryptFinalizeKey(hKey: NCRYPT_KEY_HANDLE, dwFlags: DWORD) -> SECURITY_STATUS;

        fn NCryptDeleteKey(hkey: NCRYPT_KEY_HANDLE, dwFlags: DWORD) -> SECURITY_STATUS;

        fn NCryptExportKey(
            hKey: NCRYPT_KEY_HANDLE,
            hExportKey: NCRYPT_KEY_HANDLE,
            pszBlobType: LPCWSTR,
            pParameterList: *mut BCryptBufferDesc,
            pOutput: *mut u8,
            cbOutput: DWORD,
            pcbResult: *mut DWORD,
            dwFlags: DWORD,
        ) -> SECURITY_STATUS;
    }

    pub struct NCryptHandle {
        handle: NCRYPT_HANDLE,
    }

    impl NCryptHandle {
        fn new() -> NCryptHandle {
            NCryptHandle { handle: 0 }
        }

        fn release_and_get_addressof(&mut self) -> *mut NCRYPT_HANDLE {
            self.reset();
            &mut self.handle
        }

        fn get(&self) -> NCRYPT_HANDLE {
            self.handle
        }

        fn reset(&mut self) {
            unsafe {
                if self.handle != 0 {
                    NCryptFreeObject(self.handle);
                    self.handle = 0;
                }
            }
        }

        fn release(&mut self) -> NCRYPT_HANDLE {
            let tmp = self.handle;
            self.handle = 0;
            tmp
        }
    }

    impl Drop for NCryptHandle {
        fn drop(&mut self) {
            self.reset();
        }
    }

    fn lpcwstr(string: &str) -> Vec<u16> {
        OsStr::new(string).encode_wide().chain(once(0)).collect()
    }

    pub fn open_storage_provider(ksp: Ksp) -> Result<NCryptHandle, SECURITY_STATUS> {
        let prov_name = match ksp {
            Ksp::Software => MS_KEY_STORAGE_PROVIDER,
            Ksp::SmartCard => MS_SMART_CARD_KEY_STORAGE_PROVIDER,
            Ksp::Tpm => MS_PLATFORM_CRYPTO_PROVIDER,
            Ksp::Ngc => MS_NGC_KEY_STORAGE_PROVIDER,
        };
        let mut prov = NCryptHandle::new();
        let status = unsafe {
            NCryptOpenStorageProvider(
                prov.release_and_get_addressof(),
                lpcwstr(prov_name).as_ptr(),
                0,
            )
        };
        if status != 0 {
            Err(status)
        } else {
            Ok(prov)
        }
    }

    pub enum Algorithm {
        EcdhP256,
    }

    pub fn create_persisted_key(
        provider: &NCryptHandle,
        algo: Algorithm,
        key_name: &str, // TODO: Option<&str> for ephemeral keys
    ) -> Result<NCryptHandle, SECURITY_STATUS> {
        let algorithm = match algo {
            Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
        };
        let mut key = NCryptHandle::new();
        let status = unsafe {
            NCryptCreatePersistedKey(
                provider.get(),
                key.release_and_get_addressof(),
                lpcwstr(algorithm).as_ptr(),
                lpcwstr(key_name).as_ptr(),
                0,
                0,
            )
        };
        if status != 0 {
            return Err(status);
        }
        Ok(key)
    }

    pub fn finalize_key(key: &NCryptHandle) -> Result<(), SECURITY_STATUS> {
        let status = unsafe { NCryptFinalizeKey(key.get(), 0) };
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }

    pub fn delete_key(mut key: NCryptHandle) -> Result<(), SECURITY_STATUS> {
        let status = unsafe { NCryptDeleteKey(key.release(), 0) };
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }

    pub fn export_key(key: &NCryptHandle) -> Result<Vec<u8>, SECURITY_STATUS> {
        unsafe {
            let mut byte_count: u32 = 0;
            let status = NCryptExportKey(
                key.get(),
                0,
                lpcwstr(BCRYPT_ECCPUBLIC_BLOB).as_ptr(),
                null_mut(),
                null_mut(),
                0,
                &mut byte_count,
                0,
            );
            if status != 0 {
                return Err(status);
            }

            let mut output = Vec::with_capacity(byte_count as usize);
            let status = NCryptExportKey(
                key.get(),
                0,
                // TODO: Create an enum
                lpcwstr(BCRYPT_ECCPUBLIC_BLOB).as_ptr(),
                null_mut(),
                output.as_mut_ptr(),
                byte_count,
                &mut byte_count,
                0,
            );
            if status != 0 {
                return Err(status);
            }

            output.set_len(byte_count as usize);
            Ok(output)
        }
    }
}

#[derive(Debug)]
pub enum PwrsError {
    JsonError(serde_json::Error),
    IoError(io::Error),
    FromUtf8Error(std::string::FromUtf8Error),
}

impl From<io::Error> for PwrsError {
    fn from(error: io::Error) -> Self {
        PwrsError::IoError(error)
    }
}

impl From<serde_json::Error> for PwrsError {
    fn from(error: serde_json::Error) -> Self {
        PwrsError::JsonError(error)
    }
}

impl From<std::string::FromUtf8Error> for PwrsError {
    fn from(error: std::string::FromUtf8Error) -> Self {
        PwrsError::FromUtf8Error(error)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pk: Vec<u8>, // ECDH P256
    user_name: String,
    encrypted_password: Vec<u8>, // AES-256 CBC
    mac: Vec<u8>,                // key||user_name||encrypted_password
}

pub trait Protector {
    fn decrypt(&self, entry: &Entry) -> Result<Vec<u8>, PwrsError>;
}

impl Entry {
    fn new(_pk: &[u8], user_name: &str, _password: &str) -> Entry {
        // TODO:
        // 1. Generate ephemeral ecdh key pair (pk_e, sk_e)
        // 2. Do secret agreement with pk, sk_e
        // 3. Use KDF to get encryption key k and mac secret s
        // 4. Encrypt password (with zero IV) with k
        // 5. Mac user_name||encrypted_password with s
        Entry {
            pk: Vec::new(),
            user_name: String::from(user_name),
            encrypted_password: Vec::new(),
            mac: Vec::new(),
        }
    }

    pub fn user_name(&self) -> &str {
        &self.user_name[..]
    }

    pub fn decrypt<T: Protector>(&self, protector: &T) -> Result<String, PwrsError> {
        let string = String::from_utf8(protector.decrypt(&self)?)?;
        Ok(string)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct Vault {
    pk: Vec<u8>,
    entries: HashMap<String, Entry>,
}

impl Vault {
    pub fn new(pk: Vec<u8>) -> Vault {
        Vault {
            pk,
            entries: HashMap::new(),
        }
    }

    pub fn new_entry(&mut self, key: &str, user_name: &str, password: &str) -> &Entry {
        self.entries
            .insert(String::from(key), Entry::new(&self.pk, user_name, password));
        &self.entries[key]
    }

    pub fn write<W: Write>(&self, writer: W) -> Result<(), PwrsError> {
        Ok(serde_json::to_writer(writer, &self)?)
    }

    pub fn read<R: Read>(reader: R) -> Result<Vault, PwrsError> {
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

    struct TestProtector(String);
    impl TestProtector {
        fn new(string: &str) -> TestProtector {
            TestProtector(String::from(string))
        }
    }
    impl Protector for TestProtector {
        fn decrypt(&self, _entry: &Entry) -> Result<Vec<u8>, PwrsError> {
            Ok(self.0.as_bytes().to_vec())
        }
    }

    #[test]
    fn new_entry() {
        let entry = Entry::new(&Vec::new(), "foo", "bar");
        assert!(entry.pk.is_empty());
        assert!(entry.encrypted_password.is_empty());
        assert_eq!(entry.user_name, "foo");
        assert!(entry.mac.is_empty());
    }

    #[test]
    fn decrypt_entry() {
        let entry = Entry::new(&Vec::new(), "foo", "bar");
        let protector = TestProtector::new("foobar");
        let decrypted = entry.decrypt(&protector).unwrap();
        assert_eq!("foobar", decrypted);
    }

    #[test]
    fn new_entry_from_vault() {
        let mut vault = Vault::new(vec![1, 2, 3]);
        assert_eq!(vec![1, 2, 3], vault.pk);
        let entry = vault.new_entry("example.com", "foo", "bar");
        assert_eq!(entry.user_name, "foo");
    }

    #[test]
    fn serialize_deserialize_vault() {
        let mut vault = Vault::new(vec![1, 2, 3]);
        vault.new_entry("foo.com", "foo", "bar");
        vault.new_entry("example.com", "user", "pass");
        let serialized = serde_json::to_string(&vault).unwrap();
        let deserialized: Vault = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, vault);
    }
}
