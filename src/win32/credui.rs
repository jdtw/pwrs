use credentials::Credentials;
use error::*;
use memsec;
use std::ffi::OsString;
use std::mem;
use std::os::windows::ffi::OsStringExt;
use std::ptr::null_mut;
use win32::ToLpcwstr;
use winapi::ctypes::c_void;
use winapi::shared::winerror::{ERROR_CANCELLED, ERROR_INSUFFICIENT_BUFFER};
use winapi::um::combaseapi::CoTaskMemFree;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::wincred::*;

pub struct AuthBuffer {
    ptr: *mut c_void,
    len: usize,
}
impl AuthBuffer {
    fn new(ptr: *mut c_void, len: usize) -> Self {
        AuthBuffer { ptr, len }
    }
    fn as_mut_ptr(&mut self) -> *mut c_void {
        self.ptr
    }
    fn len(&self) -> usize {
        self.len
    }
}
impl Drop for AuthBuffer {
    fn drop(&mut self) {
        unsafe {
            memsec::memzero(self.ptr as *mut u8, self.len);
            CoTaskMemFree(self.ptr);
        }
    }
}

pub fn prompt_for_windows_credentials(
    caption: &str,
    message: &str,
) -> Result<AuthBuffer, PwrsError> {
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
            return Err(PwrsError::UserCancelled(
                "CredUIPromptForWindowsCredentialsW",
            ));
        }
        if error != 0 {
            return Err(PwrsError::Win32Error(
                "CredUIPromptForWindowsCredentialsW",
                error as i32,
            ));
        }
        let auth_buffer = AuthBuffer::new(auth_buffer, auth_buffer_byte_count as usize);
        Ok(auth_buffer)
    }
}

pub fn unpack_authentication_buffer(mut buffer: AuthBuffer) -> Result<Credentials, PwrsError> {
    unsafe {
        let mut username_len = 0;
        let mut password_len = 0;
        let success = CredUnPackAuthenticationBufferW(
            0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
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
                return Err(PwrsError::Win32Error(
                    "CredUnPackAuthenticationBuffer",
                    error as i32,
                ));
            }
        }
        let mut username_buffer = Vec::with_capacity(username_len as usize);
        let mut password_buffer = Vec::with_capacity(password_len as usize);
        let success = CredUnPackAuthenticationBufferW(
            0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            username_buffer.as_mut_ptr(),
            &mut username_len,
            null_mut(),
            null_mut(),
            password_buffer.as_mut_ptr(),
            &mut password_len,
        );
        if success == 0 {
            return Err(PwrsError::Win32Error(
                "CredUnPackAuthenticationBuffer",
                GetLastError() as i32,
            ));
        }
        // Strip off the null terminators before converting to rust strings.
        username_buffer.set_len(username_len as usize - 1);
        password_buffer.set_len(password_len as usize - 1);
        let username = OsString::from_wide(&username_buffer).into_string();
        let password = OsString::from_wide(&password_buffer).into_string();
        memsec::memzero(
            password_buffer.as_mut_ptr() as *mut u8,
            password_buffer.len(),
        );
        Ok(Credentials::new(username.unwrap(), password.unwrap()))
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
        ).unwrap();
        let creds = unpack_authentication_buffer(buffy).unwrap();
        assert_eq!(creds.username(), "username");
        assert_eq!(creds.password(), "password");
    }

    #[test]
    #[ignore]
    fn test_cancel_prompt() {
        let result = prompt_for_windows_credentials("test_cancel_prompt", "Cancel this prompt!");
        match result {
            Err(PwrsError::UserCancelled(_)) => (),
            Err(e) => panic!("Unexpected error {}", e),
            _ => panic!("Cancel the prompt!"),
        }
    }
}
