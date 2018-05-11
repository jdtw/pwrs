//! `pwv` (*p*ass*w*ord *v*ault) is a Windows command-line password manager.
//!
//! Passwords are stored encrypted in a vault file, encrypted to the vault's public key.
//! The private key can either be kept in a smart card that supports ECDH on the P256
//! curve (such as the YubiKey 4), or in software. Key access happens through the
//! Microsoft [CNG APIs][cng].
//!
//! # Layout
//!
//! * The [`vault`] module deals with managing the `site -> (username, password)` entries
//!   and serialization to/from JSON.
//! * Each vault has an [`authenticator`] that manages storage of the vault's ECDH key pair,
//!   and provides an [`authenticate`] abstraction for decrypting a passwords.
//! * Usernames and passwords are handled by the [`credentials`] module.
//! * The [`prompt`] module gathers credentials from the user.
//!
//! [cng]: https://msdn.microsoft.com/en-us/library/windows/desktop/bb931355(v=vs.85).aspx
//! [`vault`]: vault/index.html
//! [`authenticator`]: authenticator/index.html
//! [`authenticate`]: authenticator/trait.Authenticate.html
//! [`credentials`]: credentials/index.html
//! [`prompt`]: prompt/index.html
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
