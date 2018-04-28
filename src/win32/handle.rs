use std::marker::PhantomData;

pub trait CloseHandle {
    fn close(&usize);
}

pub struct Handle<T: CloseHandle> {
    handle: usize,
    phantom: PhantomData<T>,
}

impl<T: CloseHandle> Handle<T> {
    pub fn new() -> Handle<T> {
        Handle {
            handle: 0,
            phantom: PhantomData,
        }
    }

    pub fn put(&mut self) -> &mut usize {
        self.reset();
        &mut self.handle
    }

    pub fn get(&self) -> usize {
        self.handle
    }

    pub fn reset(&mut self) {
        if self.handle != 0 {
            T::close(&self.handle);
            self.handle = 0;
        }
    }

    pub fn release(&mut self) -> usize {
        let handle = self.handle;
        self.handle = 0;
        handle
    }
}

impl<T: CloseHandle> Drop for Handle<T> {
    fn drop(&mut self) {
        self.reset();
    }
}
