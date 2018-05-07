#![cfg(windows)]

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate failure;

pub mod authenticator;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod prompt;
pub mod utils;
pub mod vault;
pub mod win32;
