pub struct Handle {
    handle: usize,
    close: Box<Fn(&mut usize)>,
}

impl Handle {
    pub fn new(close: Box<Fn(&mut usize)>) -> Handle {
        Handle { handle: 0, close }
    }

    pub fn as_out_param(&mut self) -> &mut usize {
        self.reset();
        &mut self.handle
    }

    pub fn get(&self) -> usize {
        self.handle
    }

    pub fn reset(&mut self) {
        if self.handle != 0 {
            (self.close)(&mut self.handle);
            self.handle = 0;
        }
    }

    pub fn release(&mut self) -> usize {
        let handle = self.handle;
        self.handle = 0;
        handle
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.reset();
    }
}
