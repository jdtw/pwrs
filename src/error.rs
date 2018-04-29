error_chain!{
    errors {
        Win32(err: i32) {
            description("Win32 error")
            display("Win32 error: '{}'", err)
        }
        UserCancelled {
            description("User cancelled")
            display("User cancelled")
        }
        MacVerificationFailed {
            description("MAC verification failed")
            display("MAC verification failed")
        }
    }
}
