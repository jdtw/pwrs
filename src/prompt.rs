use error;
use win32::credui;
pub use win32::credui::Credentials;

pub trait Prompt {
    fn prompt(&self) -> error::Result<Credentials>;
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
    fn prompt(&self) -> error::Result<Credentials> {
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
    fn prompt(&self) -> error::Result<Credentials> {
        let auth_buffer = credui::prompt_for_windows_credentials(self.caption, self.message)?;
        match auth_buffer {
            Some(auth_buffer) => Ok(credui::unpack_authentication_buffer(auth_buffer)?),
            None => Err(error::Error::UserCancelled),
        }
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

    #[test]
    #[ignore]
    fn test_cancel_prompt() {
        let prompt = UIPrompt::new("test_cancel_prompt", "Cancel this one, too.");
        match prompt.prompt() {
            Err(error::Error::UserCancelled) => (),
            Err(e) => panic!("Unexpected error {}", e),
            _ => panic!("Cancel the prompt!"),
        }
    }
}
