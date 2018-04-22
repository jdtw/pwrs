use winapi::shared::bcrypt::*;
use win32;
use win32::{CloseHandle, Handle};
use std::ptr::{null, null_mut};

// The BCrypt functions don't take const input
// parameters (even though they're SAL annotated
// as read-only). The safe interface takes const
// references and transmutes them to mutable ones
// to pass into the BCrypt FFI layer.
use std::mem::transmute;

pub enum HandleType {
    Hash,
    SymmetricKey,
}

pub struct HashHandle;
impl CloseHandle for HashHandle {
    fn close(handle: &usize) {
        unsafe {
            BCryptDestroyHash(*handle as BCRYPT_HASH_HANDLE);
        }
    }
}

pub struct Key;
impl CloseHandle for Key {
    fn close(handle: &usize) {
        unsafe {
            BCryptDestroyKey(*handle as BCRYPT_HASH_HANDLE);
        }
    }
}

pub fn gen_random(size: usize) -> win32::Result<Vec<u8>> {
    unsafe {
        let mut random = Vec::with_capacity(size);
        let status = BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            size as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        if status != 0 {
            return Err(win32::Error::new("BCryptGenRandom", status));
        }
        random.set_len(size);
        Ok(random)
    }
}

pub enum HashAlg<'a> {
    Sha1,
    Sha256,
    HmacSha256(&'a [u8]),
}

pub struct Hash<'a> {
    handle: Handle<HashHandle>,
    alg: HashAlg<'a>,
}

impl<'a> Hash<'a> {
    pub fn new(alg: HashAlg) -> win32::Result<Hash> {
        unsafe {
            let mut hash = Hash {
                handle: Handle::new(),
                alg,
            };
            let (alg_handle, secret, secret_len) = match &hash.alg {
                &HashAlg::Sha1 => (BCRYPT_SHA1_ALG_HANDLE, null(), 0),
                &HashAlg::Sha256 => (BCRYPT_SHA256_ALG_HANDLE, null(), 0),
                &HashAlg::HmacSha256(ref secret) => {
                    (BCRYPT_HMAC_SHA256_ALG_HANDLE, secret.as_ptr(), secret.len())
                }
            };
            let status = BCryptCreateHash(
                alg_handle,
                hash.handle.as_out_param() as *mut usize as *mut BCRYPT_HANDLE,
                null_mut(),
                0,
                transmute::<*const u8, *mut u8>(secret),
                secret_len as u32,
                0,
            );
            win32::Error::result("BCryptCreateHash", status, hash)
        }
    }

    pub fn hash_data(&self, data: &[u8]) -> win32::Result<()> {
        unsafe {
            let status = BCryptHashData(
                self.handle.get() as BCRYPT_HANDLE,
                transmute::<*const u8, *mut u8>(data.as_ptr()),
                data.len() as u32,
                0,
            );
            win32::Error::result("BCryptHashData", status, ())
        }
    }

    pub fn finish_hash(self) -> win32::Result<Vec<u8>> {
        unsafe {
            let output_len = match &self.alg {
                &HashAlg::Sha1 => 20,
                &HashAlg::Sha256 => 32,
                &HashAlg::HmacSha256(_) => 32,
            };
            let mut output = Vec::with_capacity(output_len);
            let status = BCryptFinishHash(
                self.handle.get() as BCRYPT_HANDLE,
                output.as_mut_ptr(),
                output_len as u32,
                0,
            );
            if status != 0 {
                return Err(win32::Error::new("BCryptFinishHash", status));
            }
            output.set_len(output_len);
            Ok(output)
        }
    }
}

pub fn hash_data(alg: HashAlg, data: &[u8]) -> win32::Result<Vec<u8>> {
    let hash = Hash::new(alg)?;
    hash.hash_data(&data)?;
    hash.finish_hash()
}

pub fn hash_sha1(data: &[u8]) -> win32::Result<Vec<u8>> {
    hash_data(HashAlg::Sha1, &data)
}

pub fn hash_sha256(data: &[u8]) -> win32::Result<Vec<u8>> {
    hash_data(HashAlg::Sha256, &data)
}

pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> win32::Result<Vec<u8>> {
    hash_data(HashAlg::HmacSha256(&secret), &data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_random() {
        assert!(gen_random(0).unwrap().len() == 0);
        assert!(gen_random(13).unwrap().len() == 13);
        assert!(gen_random(32).unwrap() != gen_random(32).unwrap());
    }

    #[test]
    fn test_hash_data_sha1() {
        let input: [u8; 5] = [1, 2, 3, 4, 5];

        let hash = Hash::new(HashAlg::Sha1).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output1 = hash.finish_hash().unwrap();

        let output2 = hash_sha1(&input
            .iter()
            .cloned()
            .chain(input.iter().cloned())
            .collect::<Vec<u8>>())
            .unwrap();

        assert_eq!(output1, output2);
        assert!(output1.len() == 20);
    }

    #[test]
    fn test_hash_data_sha2() {
        let input: [u8; 5] = [1, 2, 3, 4, 5];

        let hash = Hash::new(HashAlg::Sha256).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output1 = hash.finish_hash().unwrap();

        let output2 = hash_sha256(&input
            .iter()
            .cloned()
            .chain(input.iter().cloned())
            .collect::<Vec<u8>>())
            .unwrap();

        assert_eq!(output1, output2);
        assert!(output1.len() == 32);
    }

    #[test]
    fn test_hmac_data_sha2() {
        let input: [u8; 5] = [1, 2, 3, 4, 5];
        let secret: [u8; 32] = [0; 32];

        let hash = Hash::new(HashAlg::HmacSha256(&secret)).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output1 = hash.finish_hash().unwrap();

        let output2 = hmac_sha256(
            &secret,
            &input
                .iter()
                .cloned()
                .chain(input.iter().cloned())
                .collect::<Vec<u8>>(),
        ).unwrap();

        assert_eq!(output1, output2);
        assert!(output1.len() == 32);
    }
}
