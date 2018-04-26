use std::error;
use std::fmt;
use std::result;

#[derive(Debug)]
pub struct Error {
    api: &'static str,
    error: i32,
}

pub type Result<T> = result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} failed with {}", self.api, self.error)
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        "Win32 API error"
    }
}

impl Error {
    pub fn new(api: &'static str, error: i32) -> Error {
        Error { api, error }
    }

    pub fn result<T>(api: &'static str, error: i32, result: T) -> Result<T> {
        if error != 0 {
            Err(Error::new(api, error))
        } else {
            Ok(result)
        }
    }
}
