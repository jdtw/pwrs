use error::*;
use win32::credui;
pub use win32::credui::Credentials;

pub trait Prompt {
    fn prompt(&self) -> Result<Credentials, PwrsError>;
}

pub struct StaticPrompt {
    username: String,
    password: String,
}

impl StaticPrompt {
    pub fn new(username: String, password: String) -> StaticPrompt {
        StaticPrompt { username, password }
    }
}

impl Prompt for StaticPrompt {
    fn prompt(&self) -> Result<Credentials, PwrsError> {
        Ok(Credentials::new(
            self.username.clone(),
            self.password.clone(),
        ))
    }
}

pub struct UIPrompt<'a> {
    caption: &'a str,
    message: &'a str,
}

impl<'a> UIPrompt<'a> {
    pub fn new(caption: &'a str, message: &'a str) -> UIPrompt<'a> {
        UIPrompt { caption, message }
    }
}

impl<'a> Prompt for UIPrompt<'a> {
    fn prompt(&self) -> Result<Credentials, PwrsError> {
        let auth_buffer = credui::prompt_for_windows_credentials(self.caption, self.message)?;
        let credentials = credui::unpack_authentication_buffer(auth_buffer)?;
        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_ui_prompt() {
        let prompt = UIPrompt::new("test_ui_prompt", "Blah blah blah blah");
        prompt.prompt().unwrap();
    }
}