pub use failure::Error;

#[derive(Debug, Fail)]
pub enum PwrsError {
    #[fail(display = "{} failed with error {}", _0, _1)]
    Win32Error(&'static str, i32),
    #[fail(display = "User canceled")]
    UserCancelled,
    #[fail(display = "MAC verification failed")]
    MacVerificationFailed,
    #[fail(display = "Buffer too small. Expected {}, got {}", _0, _1)]
    BufferTooSmall(usize, usize),
}
