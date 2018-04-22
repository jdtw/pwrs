pub mod error;
pub use self::error::{Error, Result};

pub mod handle;
pub use self::handle::{CloseHandle, Handle};

pub mod ncrypt;
pub mod bcrypt;

use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

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
