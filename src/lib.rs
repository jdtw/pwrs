#![recursion_limit = "1024"]

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate error_chain;

pub mod win32;
pub mod utils;
pub mod error;
pub mod authenticator;
pub mod entry;
pub mod crypto;
pub mod vault;
pub mod prompt;
