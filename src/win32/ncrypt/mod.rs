mod ffi;

use self::ffi::*;
use crypto::*;
use error::*;
use seckey::SecKey;
use std::mem;
use std::ptr::{null, null_mut};
use win32::bcrypt::BCryptEcdhP256KeyBlob;
use win32::{CloseHandle, Handle, ToLpcwstr};
use winapi::ctypes::c_void;
use winapi::shared::bcrypt::*;

const SCARD_W_CANCELLED_BY_USER: u32 = 0x8010_006e;
const NTE_EXISTS: u32 = 0x8009_000f;
const NTE_BAD_KEYSET: u32 = 0x8009_0016;

pub struct Object;
impl CloseHandle for Object {
    fn close(handle: &usize) {
        unsafe {
            NCryptFreeObject(*handle);
        }
    }
}

pub fn open_storage_provider(ksp: KeyStorage) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let ksp_name = match ksp {
            KeyStorage::Software => MS_KEY_STORAGE_PROVIDER,
            KeyStorage::SmartCard => MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        };
        let mut prov = Handle::new();
        let status = NCryptOpenStorageProvider(prov.put(), ksp_name.to_lpcwstr().as_ptr(), 0);
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
        if status == NTE_BAD_KEYSET as i32 {
            return Err(PwrsError::KeyNotFound(String::from(key_name)));
        }
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptOpenKey", status));
        }
        Ok(key)
    }
}

pub fn create_persisted_ecdh_p256_key(
    provider: &Handle<Object>,
    key_name: Option<&str>,
) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let algo = BCRYPT_ECDH_P256_ALGORITHM;
        let mut key = Handle::new();
        let name_bytes = key_name.map(|n| n.to_lpcwstr());
        let name_ptr = name_bytes
            .as_ref()
            .map_or_else(|| null(), |bytes| bytes.as_ptr());
        let status = NCryptCreatePersistedKey(
            provider.get(),
            key.put(),
            algo.to_lpcwstr().as_ptr(),
            name_ptr,
            0,
            0,
        );
        if status == NTE_EXISTS as i32 {
            return Err(PwrsError::KeyExists(String::from(key_name.unwrap_or(""))));
        }
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptCreatePersistedKey", status));
        }
        Ok(key)
    }
}

pub fn finalize_key(key: &Handle<Object>) -> Result<(), PwrsError> {
    unsafe {
        let status = NCryptFinalizeKey(key.get(), 0);
        if status == SCARD_W_CANCELLED_BY_USER as i32 {
            return Err(PwrsError::UserCancelled("NCryptFinalizeKey"));
        }
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

pub fn import_ecdh_p256_pub_key(
    prov: &Handle<Object>,
    pub_key: &PubKey,
) -> Result<Handle<Object>, PwrsError> {
    unsafe {
        let key_struct = BCryptEcdhP256KeyBlob::from_pub_key(pub_key);
        let blob = BCRYPT_ECCPUBLIC_BLOB;
        let mut key = Handle::new();
        let status = NCryptImportKey(
            prov.get(),
            0,
            blob.to_lpcwstr().as_ptr(),
            null_mut(),
            key.put(),
            &key_struct as *const BCryptEcdhP256KeyBlob as *const u8,
            mem::size_of::<BCryptEcdhP256KeyBlob>() as u32,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptImportKey", status));
        }
        Ok(key)
    }
}

pub fn export_ecdh_p256_pub_key(key: &Handle<Object>) -> Result<PubKey, PwrsError> {
    unsafe {
        let mut key_struct = BCryptEcdhP256KeyBlob::new();
        let blob = BCRYPT_ECCPUBLIC_BLOB;
        let mut byte_count: u32 = 0;
        let status = NCryptExportKey(
            key.get(),
            0,
            blob.to_lpcwstr().as_ptr(),
            null_mut(),
            &mut key_struct as *mut BCryptEcdhP256KeyBlob as *mut u8,
            mem::size_of::<BCryptEcdhP256KeyBlob>() as u32,
            &mut byte_count,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptExportKey", status));
        }

        Ok(PubKey {
            x: key_struct.x,
            y: key_struct.y,
        })
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

pub fn derive_key(secret: &Handle<Object>, label: &str) -> Result<AgreedSecret, PwrsError> {
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
        let mut output = AgreedSecret {
            s: SecKey::new([0u8; SHA2_DIGEST_SIZE]).unwrap(),
        };
        let mut byte_count: u32 = 0;
        let status = NCryptDeriveKey(
            secret.get(),
            BCRYPT_KDF_HMAC.to_lpcwstr().as_ptr(),
            &mut parameters,
            &mut *output.s.write() as *mut [u8; SHA2_DIGEST_SIZE] as *mut u8,
            32,
            &mut byte_count,
            KDF_USE_SECRET_AS_HMAC_KEY_FLAG,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("NCryptDeriveKey", status));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_delete_persisted_sw_key() {
        let prov = open_storage_provider(KeyStorage::Software).unwrap();
        let key = create_persisted_ecdh_p256_key(&prov, Some("test-key-name")).unwrap();
        finalize_key(&key).unwrap();
        delete_key(key).unwrap();
    }

    #[test]
    fn test_open_key() {
        let prov = open_storage_provider(KeyStorage::Software).unwrap();
        {
            let key = create_persisted_ecdh_p256_key(&prov, Some("test-key-name-2")).unwrap();
            finalize_key(&key).unwrap();
        }
        let key = open_key(&prov, "test-key-name-2").unwrap();
        delete_key(key).unwrap();
    }

    #[test]
    fn test_ephemeral_smart_card_key() {
        let prov = open_storage_provider(KeyStorage::SmartCard).unwrap();
        let key = create_persisted_ecdh_p256_key(&prov, None).unwrap();
        finalize_key(&key).unwrap();
    }

    #[test]
    fn test_export() {
        let prov = open_storage_provider(KeyStorage::Software).unwrap();
        let key = create_persisted_ecdh_p256_key(&prov, None).unwrap();
        finalize_key(&key).unwrap();

        let bytes = export_ecdh_p256_pub_key(&key).unwrap();
        import_ecdh_p256_pub_key(&prov, &bytes).unwrap();
    }

    #[test]
    fn test_ecdh_key_agreement() {
        // Create and export Alice's key in software KSP
        let prov_alice = open_storage_provider(KeyStorage::Software).unwrap();
        let key_alice = create_persisted_ecdh_p256_key(&prov_alice, None).unwrap();
        finalize_key(&key_alice).unwrap();
        let pubkey_alice = export_ecdh_p256_pub_key(&key_alice).unwrap();

        // Create and export Bob's key in software KSP
        let prov_bob = open_storage_provider(KeyStorage::Software).unwrap();
        let key_bob = create_persisted_ecdh_p256_key(&prov_bob, None).unwrap();
        finalize_key(&key_bob).unwrap();
        let pubkey_bob = export_ecdh_p256_pub_key(&key_bob).unwrap();

        // Import Bob's pub key and derive secret for Alice
        let pubkey_bob = import_ecdh_p256_pub_key(&prov_alice, &pubkey_bob).unwrap();
        let secret_alice = secret_agreement(&key_alice, &pubkey_bob).unwrap();
        let derived_alice = derive_key(&secret_alice, "alice+bob").unwrap();

        // Import Alice's pub key and derive secret for Bob
        let pubkey_alice = import_ecdh_p256_pub_key(&prov_bob, &pubkey_alice).unwrap();
        let secret_bob = secret_agreement(&key_bob, &pubkey_alice).unwrap();
        let derived_bob = derive_key(&secret_bob, "alice+bob").unwrap();

        assert_eq!(*derived_alice.s.read(), *derived_bob.s.read());
    }
}
