use std::ffi::OsStr;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;

pub trait ToLpcwstr {
    fn to_lpcwstr(&self) -> Vec<u16>;
}

fn to_lpcwstr<T: AsRef<str>>(string: T) -> Vec<u16> {
    OsStr::new(string.as_ref())
        .encode_wide()
        .chain(once(0))
        .collect()
}

impl ToLpcwstr for String {
    fn to_lpcwstr(&self) -> Vec<u16> {
        to_lpcwstr(self)
    }
}

impl<'a> ToLpcwstr for &'a str {
    fn to_lpcwstr(&self) -> Vec<u16> {
        to_lpcwstr(self)
    }
}
