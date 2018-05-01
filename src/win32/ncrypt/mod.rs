mod ffi;

use self::ffi::*;
use error::*;
pub use win32::bcrypt::{Algorithm, Blob};
use win32::winapi::shared::bcrypt::*;
use win32::winapi::ctypes::c_void;
use win32::{CloseHandle, Handle, ToLpcwstr};

use std::ptr::{null, null_mut};
use std::string::ToString;

pub struct Object;
impl CloseHandle for Object {
    fn close(handle: &usize) {
        unsafe {
            NCryptFreeObject(*handle);
        }
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Copy, Clone)]
pub enum Ksp {
    Software,
    SmartCard,
    Tpm,
    Ngc,
}

impl ToString for Ksp {
    fn to_string(&self) -> String {
        String::from(match self {
            &Ksp::Software => MS_KEY_STORAGE_PROVIDER,
            &Ksp::SmartCard => MS_SMART_CARD_KEY_STORAGE_PROVIDER,
            &Ksp::Tpm => MS_PLATFORM_KEY_STORAGE_PROVIDER,
            &Ksp::Ngc => MS_NGC_KEY_STORAGE_PROVIDER,
        })
    }
}

pub fn open_storage_provider(ksp: Ksp) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let mut prov = Handle::new();
        let status =
            NCryptOpenStorageProvider(prov.put(), ksp.to_string().to_lpcwstr().as_ptr(), 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptOpenStorageProvider", status));
        }
        Ok(prov)
    }
}

pub fn open_key(prov: &Handle<Object>, key_name: &str) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let mut key = Handle::new();
        let status = NCryptOpenKey(prov.get(), key.put(), key_name.to_lpcwstr().as_ptr(), 0, 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptOpenKey", status));
        }
        Ok(key)
    }
}

pub fn create_persisted_key(
    provider: &Handle<Object>,
    algo: Algorithm,
    key_name: Option<&str>,
) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let mut key = Handle::new();
        let name_bytes = key_name.map(|n| n.to_lpcwstr());
        let name_ptr = match &name_bytes {
            &Some(ref bytes) => bytes.as_ptr(),
            &None => null(),
        };
        let status = NCryptCreatePersistedKey(
            provider.get(),
            key.put(),
            algo.to_string().to_lpcwstr().as_ptr(),
            name_ptr,
            0,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptCreatePersistedKey", status));
        }
        Ok(key)
    }
}

pub fn finalize_key(key: &Handle<Object>) -> Result<(), PwrsError> {
    unsafe {
        let status = NCryptFinalizeKey(key.get(), 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptFinalizeKey", status));
        }
        Ok(())
    }
}

pub fn delete_key(mut key: Handle<Object>) -> Result<(), PwrsError> {
    unsafe {
        let status = NCryptDeleteKey(key.release(), 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptDeleteKey", status));
        }
        Ok(())
    }
}

pub fn import_key(
    prov: &Handle<Object>,
    blob: Blob,
    bytes: &[u8],
) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let mut key = Handle::new();
        let status = NCryptImportKey(
            prov.get(),
            0,
            blob.to_string().to_lpcwstr().as_ptr(),
            null_mut(),
            key.put(),
            bytes.as_ptr(),
            bytes.len() as u32,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptImportKey", status));
        }
        Ok(key)
    }
}

pub fn export_key(key: &Handle<Object>, blob: Blob) -> Result<Vec<u8>, PwrsError> {
    unsafe {
        let blob_bytes = blob.to_string().to_lpcwstr();
        let mut byte_count: u32 = 0;
        let status = NCryptExportKey(
            key.get(),
            0,
            blob_bytes.as_ptr(),
            null_mut(),
            null_mut(),
            0,
            &mut byte_count,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptExportKey", status));
        }

        let mut output = Vec::with_capacity(byte_count as usize);
        let status = NCryptExportKey(
            key.get(),
            0,
            blob_bytes.as_ptr(),
            null_mut(),
            output.as_mut_ptr(),
            byte_count,
            &mut byte_count,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptExportKey", status));
        }

        output.set_len(byte_count as usize);
        Ok(output)
    }
}

pub fn secret_agreement(
    priv_key: &Handle<Object>,
    pub_key: &Handle<Object>,
) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let mut secret = Handle::new();
        let status = NCryptSecretAgreement(priv_key.get(), pub_key.get(), secret.put(), 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptSecretAgreement", status));
        }
        Ok(secret)
    }
}

pub fn derive_key(secret: &Handle<Object>, label: &str) -> Result<Vec<u8>, PwrsError> {
    unsafe {
        let mut sha2 = BCRYPT_SHA256_ALGORITHM.to_lpcwstr();
        let mut label = label.to_lpcwstr();
        let mut buffers: [BCryptBuffer; 2] = [
            BCryptBuffer {
                BufferType: KDF_HASH_ALGORITHM,
                cbBuffer: (sha2.len() * 2) as u32,
                pvBuffer: sha2.as_mut_ptr() as *mut c_void,
            },
            BCryptBuffer {
                BufferType: KDF_SECRET_PREPEND,
                cbBuffer: (label.len() * 2) as u32,
                pvBuffer: label.as_mut_ptr() as *mut c_void,
            },
        ];
        let mut parameters = BCryptBufferDesc {
            cBuffers: buffers.len() as u32,
            ulVersion: BCRYPTBUFFER_VERSION,
            pBuffers: buffers.as_mut_ptr(),
        };
        // SHA256 means 32 output bytes
        let mut output = Vec::with_capacity(32);
        let mut byte_count: u32 = 0;
        let status = NCryptDeriveKey(
            secret.get(),
            BCRYPT_KDF_HMAC.to_lpcwstr().as_ptr(),
            &mut parameters,
            output.as_mut_ptr(),
            32,
            &mut byte_count,
            KDF_USE_SECRET_AS_HMAC_KEY_FLAG,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptDeriveKey", status));
        }
        output.set_len(byte_count as usize);
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_delete_persisted_sw_key() {
        let prov = open_storage_provider(Ksp::Software).unwrap();
        let key = create_persisted_key(&prov, Algorithm::EcdhP256, Some("test-key-name")).unwrap();
        finalize_key(&key).unwrap();
        delete_key(key).unwrap();
    }

    #[test]
    fn test_open_key() {
        let prov = open_storage_provider(Ksp::Software).unwrap();
        {
            let key =
                create_persisted_key(&prov, Algorithm::EcdhP256, Some("test-key-name-2")).unwrap();
            finalize_key(&key).unwrap();
        }
        let key = open_key(&prov, "test-key-name-2").unwrap();
        delete_key(key).unwrap();
    }

    #[test]
    fn test_ephemeral_smart_card_key() {
        let prov = open_storage_provider(Ksp::SmartCard).unwrap();
        let key = create_persisted_key(&prov, Algorithm::EcdhP256, None).unwrap();
        finalize_key(&key).unwrap();
    }

    #[test]
    fn test_export() {
        let prov = open_storage_provider(Ksp::Software).unwrap();
        let key = create_persisted_key(&prov, Algorithm::EcdhP256, None).unwrap();
        finalize_key(&key).unwrap();

        let bytes = export_key(&key, Blob::EccPublic).unwrap();
        import_key(&prov, Blob::EccPublic, &bytes).unwrap();

        // Private key export is not supported
        assert!(export_key(&key, Blob::EccPrivate).is_err());
    }

    #[test]
    fn test_ecdh_key_agreement() {
        // Create and export Alice's key in software KSP
        let prov_alice = open_storage_provider(Ksp::Software).unwrap();
        let key_alice = create_persisted_key(&prov_alice, Algorithm::EcdhP256, None).unwrap();
        finalize_key(&key_alice).unwrap();
        let pubkey_alice = export_key(&key_alice, Blob::EccPublic).unwrap();

        // Create and export Bob's key in software KSP
        let prov_bob = open_storage_provider(Ksp::Software).unwrap();
        let key_bob = create_persisted_key(&prov_bob, Algorithm::EcdhP256, None).unwrap();
        finalize_key(&key_bob).unwrap();
        let pubkey_bob = export_key(&key_bob, Blob::EccPublic).unwrap();

        // Import Bob's pub key and derive secret for Alice
        let pubkey_bob = import_key(&prov_alice, Blob::EccPublic, &pubkey_bob).unwrap();
        let secret_alice = secret_agreement(&key_alice, &pubkey_bob).unwrap();
        let derived_alice = derive_key(&secret_alice, "alice+bob").unwrap();

        // Import Alice's pub key and derive secret for Bob
        let pubkey_alice = import_key(&prov_bob, Blob::EccPublic, &pubkey_alice).unwrap();
        let secret_bob = secret_agreement(&key_bob, &pubkey_alice).unwrap();
        let derived_bob = derive_key(&secret_bob, "alice+bob").unwrap();

        assert_eq!(derived_alice, derived_bob);
    }
}
