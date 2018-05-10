#![cfg(windows)]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[macro_use]
extern crate failure;
extern crate hex;
extern crate memsec;
extern crate seckey;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate winapi;

pub mod authenticator;
pub mod credentials;
mod crypto;
mod entry;
pub mod error;
pub mod prompt;
pub mod vault;
mod win32;
