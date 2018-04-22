extern crate winapi;

pub mod error;
pub use self::error::{Error, Result};

pub mod handle;
pub use self::handle::{CloseHandle, Handle};

pub mod lpcwstr;
pub use self::lpcwstr::ToLpcwstr;

pub mod ncrypt;
pub mod bcrypt;
