//! Structures for passing around usernames and passwords
use memsec;

#[derive(Debug, PartialEq)]
/// A container for plaintext passwords that will be securely zeroed on `drop`.
pub struct Password {
    password: String,
}

impl Password {
    pub fn new(password: String) -> Self {
        Password { password }
    }
    /// Return a reference to the plaintext pasword. Callers should be careful
    /// of copying the password out of the `Password` structure, as any plain
    /// `String`s will potentially leave the password in memory after the password
    /// has been `drop`ped.
    pub fn str(&self) -> &str {
        &self.password
    }
}

/// The plaintext `Password` is securely zeroed out when dropped, so it does
/// not remain in memory longer than needed.
impl Drop for Password {
    fn drop(&mut self) {
        unsafe {
            let bytes = self.password.as_mut_vec();
            memsec::memzero(bytes.as_mut_ptr(), bytes.len());
        }
    }
}

#[derive(Debug, PartialEq)]
/// A wrapper around a username and password. The password is securely
/// zeroed on `drop`.
pub struct Credentials {
    username: String,
    password: Password,
}

impl From<(String, String)> for Credentials {
    fn from(tuple: (String, String)) -> Self {
        Credentials::new(tuple.0, tuple.1)
    }
}

impl From<Credentials> for (String, Password) {
    fn from(creds: Credentials) -> Self {
        (creds.username, creds.password)
    }
}

impl Credentials {
    pub fn new(username: String, password: String) -> Self {
        Credentials {
            username,
            password: Password::new(password),
        }
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        self.password.str()
    }
}
