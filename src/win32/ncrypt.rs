#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::ptr::{null, null_mut};
use winapi::shared::bcrypt::*;

use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::ULONG;
use winapi::um::winnt::LPCWSTR;

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

pub enum Ksp {
    Software,
    SmartCard,
    Tpm,
    Ngc,
}

pub fn open_storage_provider(ksp: Ksp) -> Result<NCryptHandle, SECURITY_STATUS> {
    let prov_name = match ksp {
        Ksp::Software => MS_KEY_STORAGE_PROVIDER,
        Ksp::SmartCard => MS_SMART_CARD_KEY_STORAGE_PROVIDER,
        Ksp::Tpm => MS_PLATFORM_KEY_STORAGE_PROVIDER,
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
        return Err(status);
    }
    Ok(prov)
}

pub enum Algorithm {
    EcdhP256,
}

pub fn create_persisted_key(
    provider: &NCryptHandle,
    algo: Algorithm,
    key_name: Option<&str>,
) -> Result<NCryptHandle, SECURITY_STATUS> {
    let algorithm = match algo {
        Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
    };
    let mut key = NCryptHandle::new();
    let name_bytes = key_name.map(|n| lpcwstr(n));
    let status = unsafe {
        NCryptCreatePersistedKey(
            provider.get(),
            key.release_and_get_addressof(),
            lpcwstr(algorithm).as_ptr(),
            match name_bytes { Some(ptr) => ptr.as_ptr(), None => null() },
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
