//! Retrieves credentials from the user.
//!
//! Currently, there are two ways to do this, via UI, or via a tuple of `(username, password)`.
//! In the future, I would like to also add a command-line prompt for credentials.

use credentials::*;
use error::*;
use win32::credui;

/// Abstraction over credential gathering from the user
pub trait Prompt {
    // Gather a username and password from the user
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
    /// Show the Windows credential collection dialog to collect the username and password.
    ///
    /// # Examples
    ///
    /// ```
    /// use pwv::prompt::{Prompt, UIPrompt};
    ///
    /// let caption = String::from("Enter credentials for example.com");
    /// let message = String::from("And be sure nobody is looking over your shoulder!");
    /// let ui_prompt = UIPrompt::new(caption, message);
    /// // Uncomment the line below to show UI.
    /// // let creds = ui_prompt.prompt().unwrap();
    /// ```
    fn prompt(&self) -> Result<Credentials, PwrsError> {
        let auth_buffer = credui::prompt_for_windows_credentials(&self.caption, &self.message)?;
        let credentials = credui::unpack_authentication_buffer(auth_buffer)?;
        Ok(credentials)
    }
}

impl<'a> Prompt for (&'a str, &'a str) {
    /// Return credentials from the `(username, password)` tuple. Note that this is
    /// less secure than UI credential collection because we can not zero out the password
    /// since we don't have ownership of it. This `impl` is mostly used for testing, or
    /// for collecting a password from the command-line.
    ///
    /// # Examples
    ///
    /// ```
    /// use pwv::prompt::Prompt;
    ///
    /// let _credentials = ("username", "password").prompt().unwrap();
    /// ```
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
