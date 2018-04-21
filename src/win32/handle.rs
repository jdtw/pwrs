pub trait Handle {
    fn invalid_value() -> Self;
    fn close(&self);
}

pub struct Win32Handle<T: Handle + Copy + PartialEq>(T);

impl<T: Handle + Copy + PartialEq> Win32Handle<T> {
    pub fn new() -> Win32Handle<T> {
        Win32Handle(T::invalid_value())
    }

    pub fn as_out_param(&mut self) -> *mut T {
        self.reset();
        &mut self.0
    }

    pub fn get(&self) -> T {
        self.0
    }

    pub fn reset(&mut self) {
        if self.0 != T::invalid_value() {
            self.0.close();
            self.0 = T::invalid_value();
        }
    }

    pub fn release(&mut self) -> T {
        let handle = self.0;
        self.0 = T::invalid_value();
        handle
    }
}

impl<T: Handle + Copy + PartialEq> Drop for Win32Handle<T> {
    fn drop(&mut self) {
        self.reset();
    }
}
