use std::ptr::{null, null_mut};
use std::string::ToString;
use winapi::shared::bcrypt::*;
use super::ffi::*;

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

pub fn open_storage_provider(ksp: Ksp) -> Result<NCryptHandle, SECURITY_STATUS> {
    unsafe {
        let mut prov = NCryptHandle::new();
        let status = NCryptOpenStorageProvider(
            prov.release_and_get_addressof(),
            ksp.to_string().to_lpcwstr().as_ptr(),
            0,
        );
        if status != 0 {
            return Err(status);
        }
        Ok(prov)
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
) -> Result<NCryptHandle, SECURITY_STATUS> {
    unsafe {
        let mut key = NCryptHandle::new();
        let name_bytes = key_name.map(|n| to_lpcwstr(n));
        let status = NCryptCreatePersistedKey(
            provider.get(),
            key.release_and_get_addressof(),
            algo.to_string().to_lpcwstr().as_ptr(),
            match name_bytes {
                Some(ptr) => ptr.as_ptr(),
                None => null(),
            },
            0,
            0,
        );
        if status != 0 {
            return Err(status);
        }
        Ok(key)
    }
}

pub fn finalize_key(key: &NCryptHandle) -> Result<(), SECURITY_STATUS> {
    unsafe {
        let status = NCryptFinalizeKey(key.get(), 0);
        if status != 0 {
            return Err(status);
        }
        Ok(())
    }
}

pub fn delete_key(mut key: NCryptHandle) -> Result<(), SECURITY_STATUS> {
    unsafe {
        let status = NCryptDeleteKey(key.release(), 0);
        if status != 0 {
            return Err(status);
        }
        Ok(())
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

pub fn export_key(key: &NCryptHandle, blob: Blob) -> Result<Vec<u8>, SECURITY_STATUS> {
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
            return Err(status);
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
            return Err(status);
        }

        output.set_len(byte_count as usize);
        Ok(output)
    }
}

pub fn secret_agreement(
    priv_key: &NCryptHandle,
    pub_key: &NCryptHandle,
) -> Result<NCryptHandle, SECURITY_STATUS> {
    unsafe {
        let mut secret = NCryptHandle::new();
        let status = NCryptSecretAgreement(
            priv_key.get(),
            pub_key.get(),
            secret.release_and_get_addressof(),
            0,
        );
        if status != 0 {
            return Err(status);
        }
        Ok(secret)
    }
}
