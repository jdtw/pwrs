mod ffi;

use self::ffi::*;
use win32;
use win32::handle;

use std::ptr::{null, null_mut};
use std::string::ToString;
use winapi::shared::bcrypt::*;
use winapi::ctypes::c_void;

impl handle::Handle for NCRYPT_HANDLE {
    fn invalid_value() -> NCRYPT_HANDLE {
        0
    }

    fn close(&self) {
        unsafe {
            NCryptFreeObject(*self);
        }
    }
}

pub type NCryptHandle = handle::Win32Handle<NCRYPT_HANDLE>;

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

pub fn open_storage_provider(ksp: Ksp) -> win32::Result<NCryptHandle> {
    unsafe {
        let mut prov = NCryptHandle::new();
        let status = NCryptOpenStorageProvider(
            prov.as_out_param(),
            ksp.to_string().to_lpcwstr().as_ptr(),
            0,
        );
        win32::Error::result("NCryptOpenStorageProvider", status, prov)
    }
}

pub fn open_key(prov: &NCryptHandle, key_name: &str) -> win32::Result<NCryptHandle> {
    unsafe {
        let mut key = NCryptHandle::new();
        let status = NCryptOpenKey(
            prov.get(),
            key.as_out_param(),
            to_lpcwstr(key_name).as_ptr(),
            0,
            0,
        );
        win32::Error::result("NCryptOpenKey", status, key)
    }
}

pub enum Algorithm {
    EcdhP256,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        String::from(match self {
            &Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
        })
    }
}

pub fn create_persisted_key(
    provider: &NCryptHandle,
    algo: Algorithm,
    key_name: Option<&str>,
) -> win32::Result<NCryptHandle> {
    unsafe {
        let mut key = NCryptHandle::new();
        let name_bytes = key_name.map(|n| to_lpcwstr(n));
        let status = NCryptCreatePersistedKey(
            provider.get(),
            key.as_out_param(),
            algo.to_string().to_lpcwstr().as_ptr(),
            match name_bytes {
                Some(ptr) => ptr.as_ptr(),
                None => null(),
            },
            0,
            0,
        );
        win32::Error::result("NCryptCreatePersistedKey", status, key)
    }
}

pub fn finalize_key(key: &NCryptHandle) -> win32::Result<()> {
    unsafe {
        let status = NCryptFinalizeKey(key.get(), 0);
        win32::Error::result("NCryptFinalizeKey", status, ())
    }
}

pub fn delete_key(mut key: NCryptHandle) -> win32::Result<()> {
    unsafe {
        let status = NCryptDeleteKey(key.release(), 0);
        win32::Error::result("NCryptFinalizeKey", status, ())
    }
}

pub enum Blob {
    EccPublic,
    EccPrivate,
}

impl ToString for Blob {
    fn to_string(&self) -> String {
        String::from(match self {
            &Blob::EccPublic => BCRYPT_ECCPUBLIC_BLOB,
            &Blob::EccPrivate => BCRYPT_ECCPRIVATE_BLOB,
        })
    }
}

pub fn import_key(prov: &NCryptHandle, blob: Blob, bytes: &[u8]) -> win32::Result<NCryptHandle> {
    unsafe {
        let mut key = NCryptHandle::new();
        let status = NCryptImportKey(
            prov.get(),
            0,
            blob.to_string().to_lpcwstr().as_ptr(),
            null_mut(),
            key.as_out_param(),
            bytes.as_ptr(),
            bytes.len() as u32,
            0,
        );
        win32::Error::result("NCryptImportKey", status, key)
    }
}

pub fn export_key(key: &NCryptHandle, blob: Blob) -> win32::Result<Vec<u8>> {
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
            return Err(win32::Error::new("NCryptExportKey", status));
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
            return Err(win32::Error::new("NCryptExportKey", status));
        }

        output.set_len(byte_count as usize);
        Ok(output)
    }
}

pub fn secret_agreement(
    priv_key: &NCryptHandle,
    pub_key: &NCryptHandle,
) -> win32::Result<NCryptHandle> {
    unsafe {
        let mut secret = NCryptHandle::new();
        let status = NCryptSecretAgreement(priv_key.get(), pub_key.get(), secret.as_out_param(), 0);
        win32::Error::result("NCryptSecretAgreement", status, secret)
    }
}

pub fn derive_key(secret: &NCryptHandle, label: Option<&str>) -> win32::Result<Vec<u8>> {
    unsafe {
        let mut sha2 = to_lpcwstr(BCRYPT_SHA256_ALGORITHM);

        let mut buffers = vec![
            BCryptBuffer {
                BufferType: KDF_HASH_ALGORITHM,
                cbBuffer: (sha2.len() * 2) as u32,
                pvBuffer: sha2.as_mut_ptr() as *mut c_void,
            },
        ];
        let mut label_bytes = label.map(|l| to_lpcwstr(l)).unwrap_or(Vec::new());
        if label_bytes.len() > 0 {
            buffers.push(BCryptBuffer {
                BufferType: KDF_SECRET_PREPEND,
                cbBuffer: (label_bytes.len() * 2) as u32,
                pvBuffer: label_bytes.as_mut_ptr() as *mut c_void,
            });
        }
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
            to_lpcwstr(BCRYPT_KDF_HMAC).as_ptr(),
            &mut parameters,
            output.as_mut_ptr(),
            32,
            &mut byte_count,
            KDF_USE_SECRET_AS_HMAC_KEY_FLAG,
        );
        if status != 0 {
            return Err(win32::Error::new("NCryptDeriveKey", status));
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
        let derived_alice = derive_key(&secret_alice, Some("alice+bob")).unwrap();

        // Import Alice's pub key and derive secret for Bob
        let pubkey_alice = import_key(&prov_bob, Blob::EccPublic, &pubkey_alice).unwrap();
        let secret_bob = secret_agreement(&key_bob, &pubkey_alice).unwrap();
        let derived_bob = derive_key(&secret_bob, Some("alice+bob")).unwrap();

        assert_eq!(derived_alice, derived_bob);
    }
}
