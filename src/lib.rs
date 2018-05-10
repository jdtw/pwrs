#![cfg(windows)]

extern crate winapi;

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate failure;

extern crate memsec;
extern crate seckey;

pub mod authenticator;
pub mod credentials;
mod crypto;
mod entry;
pub mod error;
pub mod prompt;
mod utils;
pub mod vault;
mod win32;
