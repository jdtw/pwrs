//! `pwv` (**p**ass**w**ord **v**ault) is a Windows command-line password manager.
//!
//! Passwords are stored encrypted in a vault file, encrypted to the vault's public key.
//! The private key can either be kept in a smart card that supports ECDH on the P256
//! curve (such as the YubiKey 4), or in software. Key access happens through the
//! Microsoft [CNG APIs][cng].
//!
//! The ciphersuite used in the vault:
//! * ECDH on P256 curve
//! * AES256 CBC
//! * HMAC SHA256
//! * NIST SP800 108 CTR HMAC KDF
//! See the [`crypto`] module for more details.
//!
//! [cng]: https://msdn.microsoft.com/en-us/library/windows/desktop/bb931355(v=vs.85).aspx
//! [`crypto`]: crypto/index.html
//!
//! # Examples
//!
//! ```
//! use pwv::authenticator::Key;
//! use pwv::prompt::Prompt;
//! use pwv::vault::Vault;
//! use std::io::Write;
//!
//! let authenticator = Key::Software(String::from("example"))
//!     .into_authenticator()
//!     .unwrap();
//! let mut vault = Vault::new(authenticator);
//!
//! // The thumbprint (hash of the vault's public key) should be shown
//! // to the user after vault creation (where they should be told to
//! // remember it), and then during each subsequent vault insertion (where
//! // they should be told to check and see if it matches the one they
//! // were shown during creation).
//! let _pk = vault.thumbprint().unwrap();
//!
//! // Insert and encrypt the password
//! let creds = ("user", "Pa$$w0rd!");
//! vault.insert(String::from("example.com"), &creds).unwrap();
//!
//! // Retrieve and decrypt it
//! {
//!     let entry = vault.get("example.com").unwrap();
//!     assert_eq!(entry.site(), "example.com");
//!     assert_eq!(entry.username(), "user");
//!     assert_eq!(entry.decrypt_password().unwrap().str(), "Pa$$w0rd!");
//! }
//!
//! // Serialize and deserialize to/from buffer
//! let mut buffer = Vec::new();
//! vault.to_writer(buffer.by_ref()).unwrap();
//! let deserialized = Vault::from_reader(&buffer[..]).unwrap();
//! assert_eq!(deserialized, vault);
//!
//! let entry = deserialized.get("example.com").unwrap();
//! assert_eq!(entry.decrypt_password().unwrap().str(), "Pa$$w0rd!");
//!
//! // Delete the persistent "example" software key.
//! vault.delete().unwrap();
//!
//! // Note that the other copy of the vault, `deserialized`, will now
//! // fail to perform any decryptions because the private key shared by
//! // the two vaults is gone.
//! assert!(entry.decrypt_password().is_err());
//! ```
#![cfg(windows)]

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
pub mod crypto;
mod entry;
pub mod error;
pub mod prompt;
pub mod vault;
mod win32;
