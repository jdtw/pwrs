#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use winapi::shared::basetsd::ULONG_PTR;
use winapi::shared::minwindef::ULONG;
use winapi::um::winnt::LPCWSTR;
use winapi::shared::bcrypt::*;

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

type DWORD = ULONG;
pub type SECURITY_STATUS = i32;

pub type NCRYPT_HANDLE = ULONG_PTR;
type NCRYPT_PROV_HANDLE = ULONG_PTR;
type NCRYPT_KEY_HANDLE = ULONG_PTR;
type NCRYPT_SECRET_HANDLE = ULONG_PTR;

pub const MS_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Software Key Storage Provider";
pub const MS_SMART_CARD_KEY_STORAGE_PROVIDER: &'static str =
    "Microsoft Smart Card Key Storage Provider";
pub const MS_PLATFORM_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Platform Crypto Provider";
pub const MS_NGC_KEY_STORAGE_PROVIDER: &'static str = "Microsoft Passport Key Storage Provider";

#[link(name = "ncrypt")]
extern "stdcall" {
    pub fn NCryptOpenStorageProvider(
        phProvider: *mut NCRYPT_PROV_HANDLE,
        pszProviderName: LPCWSTR,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;

    pub fn NCryptFreeObject(hObject: NCRYPT_HANDLE) -> SECURITY_STATUS;

    pub fn NCryptCreatePersistedKey(
        hProvider: NCRYPT_PROV_HANDLE,
        phKey: *mut NCRYPT_KEY_HANDLE,
        pszAlgId: LPCWSTR,
        pszKeyName: LPCWSTR,
        dwLegacyKeySpec: DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;

    pub fn NCryptFinalizeKey(hKey: NCRYPT_KEY_HANDLE, dwFlags: DWORD) -> SECURITY_STATUS;

    pub fn NCryptDeleteKey(hkey: NCRYPT_KEY_HANDLE, dwFlags: DWORD) -> SECURITY_STATUS;

    pub fn NCryptExportKey(
        hKey: NCRYPT_KEY_HANDLE,
        hExportKey: NCRYPT_KEY_HANDLE,
        pszBlobType: LPCWSTR,
        pParameterList: *mut BCryptBufferDesc,
        pOutput: *mut u8,
        cbOutput: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;

    pub fn NCryptSecretAgreement(
        hPrivKey: NCRYPT_KEY_HANDLE,
        hPubKey: NCRYPT_KEY_HANDLE,
        phAgreedSecret: *mut NCRYPT_SECRET_HANDLE,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;

    pub fn NCryptDeriveKey(
        hSharedSecret: NCRYPT_SECRET_HANDLE,
        pwszKDF: LPCWSTR,
        pParameterList: *mut BCryptBufferDesc,
        pbDerivedKey: *mut u8,
        cbDerivedKey: DWORD,
        pcbResult: *mut DWORD,
        dwFlags: DWORD,
    ) -> SECURITY_STATUS;
}

pub trait ToLpcwstr {
    fn to_lpcwstr(&self) -> Vec<u16>;
}

pub fn to_lpcwstr(string: &str) -> Vec<u16> {
    OsStr::new(string).encode_wide().chain(once(0)).collect()
}

impl ToLpcwstr for String {
    fn to_lpcwstr(&self) -> Vec<u16> {
        to_lpcwstr(self)
    }
}