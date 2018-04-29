extern crate winapi;

pub mod handle;
pub use self::handle::{CloseHandle, Handle};

pub mod lpcwstr;
pub use self::lpcwstr::ToLpcwstr;

pub mod ncrypt;
pub mod bcrypt;

pub mod credui;
