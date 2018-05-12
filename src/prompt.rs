use credentials::*;
use error::*;
use win32::credui;

pub trait Prompt {
    fn prompt(&self) -> Result<Credentials, PwrsError>;
}

/// A wrapper around [`CredUIPromptForWindowsCredentials`][credui] that will
/// gather a username and password from the user.
///
/// [credui]: https://msdn.microsoft.com/en-us/library/windows/desktop/aa375178(v=vs.85).aspx
pub struct UIPrompt {
    caption: String,
    message: String,
}

impl UIPrompt {
    pub fn new(caption: String, message: String) -> UIPrompt {
        UIPrompt { caption, message }
    }
}

impl Prompt for UIPrompt {
    fn prompt(&self) -> Result<Credentials, PwrsError> {
        let auth_buffer = credui::prompt_for_windows_credentials(&self.caption, &self.message)?;
        let credentials = credui::unpack_authentication_buffer(auth_buffer)?;
        Ok(credentials)
    }
}

impl<'a> Prompt for (&'a str, &'a str) {
    fn prompt(&self) -> Result<Credentials, PwrsError> {
        Ok(Credentials::new(String::from(self.0), String::from(self.1)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_ui_prompt() {
        let prompt = UIPrompt::new(
            String::from("test_ui_prompt"),
            String::from("Blah blah blah blah"),
        );
        prompt.prompt().unwrap();
    }
}
