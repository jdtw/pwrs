use win32;
use win32::ToLpcwstr;
use win32::winapi::um::wincred::*;
use win32::winapi::um::combaseapi::CoTaskMemFree;
use win32::winapi::um::errhandlingapi::GetLastError;
use win32::winapi::shared::winerror::{ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER};
use win32::winapi::ctypes::c_void;
use std::mem;
use std::ptr;
use std::ptr::null_mut;
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;

#[derive(Debug, PartialEq)]
pub struct Credentials {
    username: String,
    password: String,
}

impl Credentials {
    pub fn new(username: String, password: String) -> Self {
        Credentials { username, password }
    }
    pub fn username(&self) -> &str {
        &self.username
    }
    pub fn password(&self) -> &str {
        &self.password
    }
}

pub struct AuthBuffer(Vec<u8>);
impl AuthBuffer {
    fn new(ptr: *const c_void, count: usize) -> Self {
        unsafe {
            let mut buffer: Vec<u8> = Vec::with_capacity(count);
            ptr::copy_nonoverlapping(ptr as *const u8, buffer.as_mut_ptr(), count);
            buffer.set_len(count);
            AuthBuffer(buffer)
        }
    }
}
// TODO: impl Drop for AuthBuffer and secure zero it

pub fn prompt_for_windows_credentials(
    caption: &str,
    message: &str,
) -> win32::Result<Option<AuthBuffer>> {
    unsafe {
        let message = message.to_lpcwstr();
        let caption = caption.to_lpcwstr();
        let mut info = CREDUI_INFOW {
            cbSize: mem::size_of::<CREDUI_INFOW>() as u32,
            hwndParent: null_mut(),
            pszMessageText: message.as_ptr(),
            pszCaptionText: caption.as_ptr(),
            hbmBanner: null_mut(),
        };
        let mut auth_package = 0;
        let mut auth_buffer = null_mut();
        let mut auth_buffer_byte_count = 0;
        let error = CredUIPromptForWindowsCredentialsW(
            &mut info,
            0,
            &mut auth_package,
            null_mut(),
            0,
            &mut auth_buffer,
            &mut auth_buffer_byte_count,
            null_mut(),
            CREDUIWIN_GENERIC,
        );
        if error == ERROR_CANCELLED {
            return Ok(None);
        }
        if error != 0 {
            return Err(win32::Error::new(
                "CredUIPromptForWindowsCredentialsW",
                error as i32,
            ));
        }
        let copy = AuthBuffer::new(auth_buffer, auth_buffer_byte_count as usize);
        // TODO: Secure zero!
        CoTaskMemFree(auth_buffer);
        Ok(Some(copy))
    }
}

pub fn unpack_authentication_buffer(mut buffer: AuthBuffer) -> win32::Result<Credentials> {
    unsafe {
        let mut username_len = 0;
        let mut password_len = 0;
        let success = CredUnPackAuthenticationBufferW(
            0,
            buffer.0.as_mut_ptr() as *mut c_void,
            buffer.0.len() as u32,
            null_mut(),
            &mut username_len,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut password_len,
        );
        if success == 0 {
            let error = GetLastError();
            if error != ERROR_INSUFFICIENT_BUFFER {
                return Err(win32::Error::new(
                    "CredUnPackAuthenticationBufferW",
                    error as i32,
                ));
            }
        }
        let mut username_buffer = Vec::with_capacity(username_len as usize);
        let mut password_buffer = Vec::with_capacity(password_len as usize);
        let success = CredUnPackAuthenticationBufferW(
            0,
            buffer.0.as_mut_ptr() as *mut c_void,
            buffer.0.len() as u32,
            username_buffer.as_mut_ptr(),
            &mut username_len,
            null_mut(),
            null_mut(),
            password_buffer.as_mut_ptr(),
            &mut password_len,
        );
        if success == 0 {
            return Err(win32::Error::new(
                "CredUnPackAuthenticationBufferW",
                GetLastError() as i32,
            ));
        }
        // Strip off the null terminators before converting to rust strings.
        username_buffer.set_len(username_len as usize - 1);
        password_buffer.set_len(password_len as usize - 1);
        let username = OsString::from_wide(&username_buffer).into_string().unwrap();
        let password = OsString::from_wide(&password_buffer).into_string().unwrap();
        Ok(Credentials { username, password })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    // Run this with `cargo test -- --test-threads=1 --ignored`.
    // For the UI tests, it will only work on a single thread.
    fn test_credui_prompt() {
        let buffy = prompt_for_windows_credentials(
            "test_credui_prompt",
            "Enter \"username\" and \"password\" in the prompts.",
        ).unwrap()
            .unwrap();
        let creds = unpack_authentication_buffer(buffy).unwrap();
        assert_eq!(creds.username(), "username");
        assert_eq!(creds.password(), "password");
    }

    #[test]
    #[ignore]
    fn test_cancel_prompt() {
        let buffy =
            prompt_for_windows_credentials("test_cancel_prompt", "Cancel this prompt!").unwrap();
        assert!(buffy.is_none());
    }
}
