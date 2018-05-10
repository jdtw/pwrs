use memsec;

#[derive(Debug, PartialEq)]
pub struct Password {
    password: String,
}

impl Password {
    pub fn new(password: String) -> Self {
        Password { password }
    }
    pub fn str(&self) -> &str {
        &self.password
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        unsafe {
            let bytes = self.password.as_mut_vec();
            memsec::memzero(bytes.as_mut_ptr(), bytes.len());
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Credentials {
    username: String,
    password: Password,
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
    pub fn into_tuple(self) -> (String, Password) {
        (self.username, self.password)
    }
}
