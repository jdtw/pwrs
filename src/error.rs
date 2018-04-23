use win32;
use std::io;
use serde_json;
use std::string;
use std::result;
use std::fmt;
use std::error;

#[derive(Debug)]
pub enum Error {
    JsonError(serde_json::Error),
    IoError(io::Error),
    FromUtf8Error(string::FromUtf8Error),
    Win32Error(win32::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Error::JsonError(ref e) => e.fmt(f),
            &Error::IoError(ref e) => e.fmt(f),
            &Error::FromUtf8Error(ref e) => e.fmt(f),
            &Error::Win32Error(ref e) => e.fmt(f),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            &Error::JsonError(ref e) => e.description(),
            &Error::IoError(ref e) => e.description(),
            &Error::FromUtf8Error(ref e) => e.description(),
            &Error::Win32Error(ref e) => e.description(),
        }
    }
}

pub type Result<T> = result::Result<T, Error>;

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::IoError(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Error::JsonError(error)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(error: string::FromUtf8Error) -> Self {
        Error::FromUtf8Error(error)
    }
}

impl From<win32::Error> for Error {
    fn from(error: win32::Error) -> Self {
        Error::Win32Error(error)
    }
}
