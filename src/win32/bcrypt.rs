use error::*;
use win32::winapi::shared::bcrypt::*;
use win32::winapi::ctypes::c_void;
use win32::{CloseHandle, Handle, ToLpcwstr};
use std::ptr::{null, null_mut};
use std::string::ToString;

pub enum HandleType {
    Hash,
    SymmetricKey,
}

pub struct HashHandle;
impl CloseHandle for HashHandle {
    fn close(handle: &usize) {
        unsafe {
            BCryptDestroyHash(*handle as BCRYPT_HANDLE);
        }
    }
}

pub struct Key;
impl CloseHandle for Key {
    fn close(handle: &usize) {
        unsafe {
            BCryptDestroyKey(*handle as BCRYPT_HANDLE);
        }
    }
}

pub struct Secret;
impl CloseHandle for Secret {
    fn close(handle: &usize) {
        unsafe {
            BCryptDestroySecret(*handle as BCRYPT_HANDLE);
        }
    }
}

pub enum Algorithm {
    EcdhP256,
}

impl ToString for Algorithm {
    fn to_string(&self) -> String {
        String::from(match self {
            &Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALGORITHM,
        })
    }
}

pub fn generate_key_pair(alg: Algorithm) -> Result<Handle<Key>> {
    unsafe {
        let alg = match alg {
            Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALG_HANDLE,
        };
        let mut key = Handle::new();
        let status =
            BCryptGenerateKeyPair(alg, key.put() as *mut usize as *mut BCRYPT_HANDLE, 0, 0);
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        let status = BCryptFinalizeKeyPair(key.get() as BCRYPT_HANDLE, 0);
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        Ok(key)
    }
}

pub enum Blob {
    EccPublic,
    EccPrivate,
}

impl ToString for Blob {
    fn to_string(&self) -> String {
        String::from(match self {
            &Blob::EccPublic => BCRYPT_ECCPUBLIC_BLOB,
            &Blob::EccPrivate => BCRYPT_ECCPRIVATE_BLOB,
        })
    }
}

pub fn import_key_pair(alg: Algorithm, blob: Blob, bytes: &[u8]) -> Result<Handle<Key>> {
    unsafe {
        let alg = match alg {
            Algorithm::EcdhP256 => BCRYPT_ECDH_P256_ALG_HANDLE,
        };
        let mut key = Handle::new();
        let status = BCryptImportKeyPair(
            alg,
            null_mut(),
            blob.to_string().to_lpcwstr().as_ptr(),
            key.put() as *mut usize as *mut BCRYPT_HANDLE,
            bytes.as_ptr() as *const u8 as *mut u8,
            bytes.len() as u32,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        Ok(key)
    }
}

pub fn export_key(key: &Handle<Key>, blob: Blob) -> Result<Vec<u8>> {
    unsafe {
        let blob_bytes = blob.to_string().to_lpcwstr();
        let mut byte_count: u32 = 0;
        let status = BCryptExportKey(
            key.get() as BCRYPT_HANDLE,
            null_mut(),
            blob_bytes.as_ptr(),
            null_mut(),
            0,
            &mut byte_count,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        let mut output = Vec::with_capacity(byte_count as usize);
        let status = BCryptExportKey(
            key.get() as BCRYPT_HANDLE,
            null_mut(),
            blob_bytes.as_ptr(),
            output.as_mut_ptr(),
            byte_count,
            &mut byte_count,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        output.set_len(byte_count as usize);
        Ok(output)
    }
}

pub fn secret_agreement(sk: &Handle<Key>, pk: &Handle<Key>) -> Result<Handle<Secret>> {
    unsafe {
        let mut secret = Handle::new();
        let status = BCryptSecretAgreement(
            sk.get() as BCRYPT_HANDLE,
            pk.get() as BCRYPT_HANDLE,
            secret.put() as *mut usize as *mut BCRYPT_HANDLE,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        Ok(secret)
    }
}

pub fn derive_key(secret: &Handle<Secret>, label: &str) -> Result<Vec<u8>> {
    unsafe {
        let mut sha2 = BCRYPT_SHA256_ALGORITHM.to_lpcwstr();
        let mut label = label.to_lpcwstr();
        let mut buffers: [BCryptBuffer; 2] = [
            BCryptBuffer {
                BufferType: KDF_HASH_ALGORITHM,
                cbBuffer: (sha2.len() * 2) as u32,
                pvBuffer: sha2.as_mut_ptr() as *mut c_void,
            },
            BCryptBuffer {
                BufferType: KDF_SECRET_PREPEND,
                cbBuffer: (label.len() * 2) as u32,
                pvBuffer: label.as_mut_ptr() as *mut c_void,
            },
        ];
        let mut parameters = BCryptBufferDesc {
            cBuffers: buffers.len() as u32,
            ulVersion: BCRYPTBUFFER_VERSION,
            pBuffers: buffers.as_mut_ptr(),
        };
        // SHA256 means 32 output bytes
        let mut output = Vec::with_capacity(32);
        let mut byte_count: u32 = 0;
        let status = BCryptDeriveKey(
            secret.get() as BCRYPT_HANDLE,
            BCRYPT_KDF_HMAC.to_lpcwstr().as_ptr(),
            &mut parameters,
            output.as_mut_ptr(),
            32,
            &mut byte_count,
            KDF_USE_SECRET_AS_HMAC_KEY_FLAG,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        output.set_len(byte_count as usize);
        Ok(output)
    }
}

pub enum SymAlg {
    Sp800108CtrHmacKdf,
    Aes256Cbc,
}

pub fn generate_symmetric_key(alg: SymAlg, secret: &[u8]) -> Result<Handle<Key>> {
    let (alg_handle, expected_len) = match alg {
        SymAlg::Sp800108CtrHmacKdf => (BCRYPT_SP800108_CTR_HMAC_ALG_HANDLE, 32),
        SymAlg::Aes256Cbc => (BCRYPT_AES_CBC_ALG_HANDLE, 32),
    };
    if secret.len() != expected_len {
        bail!("Unexpected secret length")
    }
    unsafe {
        let mut key = Handle::new();
        let status = BCryptGenerateSymmetricKey(
            alg_handle,
            key.put() as *mut usize as *mut BCRYPT_HANDLE,
            null_mut(),
            0,
            secret.as_ptr() as *const u8 as *mut u8,
            secret.len() as u32,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        Ok(key)
    }
}

pub fn key_derivation(key: &Handle<Key>, label: &str, output_len: usize) -> Result<Vec<u8>> {
    let label_bytes = label.to_lpcwstr();
    let mut buffer = BCryptBuffer {
        BufferType: KDF_LABEL,
        cbBuffer: (label_bytes.len() * 2) as u32,
        pvBuffer: label_bytes.as_ptr() as *mut c_void,
    };

    let mut parameters = BCryptBufferDesc {
        cBuffers: 1,
        ulVersion: BCRYPTBUFFER_VERSION,
        pBuffers: &mut buffer,
    };

    unsafe {
        let mut output = Vec::with_capacity(output_len);
        let mut result_byte_count = 0;
        let status = BCryptKeyDerivation(
            key.get() as BCRYPT_HANDLE,
            &mut parameters,
            output.as_mut_ptr(),
            output_len as u32,
            &mut result_byte_count,
            0,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        output.set_len(result_byte_count as usize);
        Ok(output)
    }
}

pub fn gen_random(size: usize) -> Result<Vec<u8>> {
    unsafe {
        let mut random = Vec::with_capacity(size);
        let status = BCryptGenRandom(
            null_mut(),
            random.as_mut_ptr(),
            size as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }
        random.set_len(size);
        Ok(random)
    }
}

pub fn encrypt_data(key: &Handle<Key>, iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut iv = iv.to_vec();
        let mut result_byte_count = 0;

        let status = BCryptEncrypt(
            key.get() as BCRYPT_HANDLE,
            data.as_ptr() as *const u8 as *mut u8,
            data.len() as u32,
            null_mut(),
            iv.as_mut_ptr(),
            iv.len() as u32,
            null_mut(),
            0,
            &mut result_byte_count,
            BCRYPT_BLOCK_PADDING,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        let mut output = Vec::with_capacity(result_byte_count as usize);
        let status = BCryptEncrypt(
            key.get() as BCRYPT_HANDLE,
            data.as_ptr() as *const u8 as *mut u8,
            data.len() as u32,
            null_mut(),
            iv.as_mut_ptr(),
            iv.len() as u32,
            output.as_mut_ptr(),
            result_byte_count,
            &mut result_byte_count,
            BCRYPT_BLOCK_PADDING,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        output.set_len(result_byte_count as usize);
        Ok(output)
    }
}

pub fn decrypt_data(key: &Handle<Key>, iv: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    unsafe {
        let mut iv: Vec<u8> = iv.iter().cloned().collect();
        let mut result_byte_count = 0;

        let status = BCryptDecrypt(
            key.get() as BCRYPT_HANDLE,
            data.as_ptr() as *const u8 as *mut u8,
            data.len() as u32,
            null_mut(),
            iv.as_mut_ptr(),
            iv.len() as u32,
            null_mut(),
            0,
            &mut result_byte_count,
            BCRYPT_BLOCK_PADDING,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        let mut output = Vec::with_capacity(result_byte_count as usize);
        let status = BCryptDecrypt(
            key.get() as BCRYPT_HANDLE,
            data.as_ptr() as *const u8 as *mut u8,
            data.len() as u32,
            null_mut(),
            iv.as_mut_ptr(),
            iv.len() as u32,
            output.as_mut_ptr(),
            result_byte_count,
            &mut result_byte_count,
            BCRYPT_BLOCK_PADDING,
        );
        if status != 0 {
            bail!(ErrorKind::Win32(status));
        }

        output.set_len(result_byte_count as usize);
        Ok(output)
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
    pub fn new(alg: HashAlg) -> Result<Hash> {
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
                hash.handle.put() as *mut usize as *mut BCRYPT_HANDLE,
                null_mut(),
                0,
                secret as *const u8 as *mut u8,
                secret_len as u32,
                0,
            );
            if status != 0 {
                bail!(ErrorKind::Win32(status));
            }
            Ok(hash)
        }
    }

    pub fn hash_data(&self, data: &[u8]) -> Result<()> {
        unsafe {
            let status = BCryptHashData(
                self.handle.get() as BCRYPT_HANDLE,
                data.as_ptr() as *const u8 as *mut u8,
                data.len() as u32,
                0,
            );
            if status != 0 {
                bail!(ErrorKind::Win32(status));
            }
            Ok(())
        }
    }

    pub fn finish_hash(self) -> Result<Vec<u8>> {
        unsafe {
            let output_len = match self.alg {
                HashAlg::Sha1 => 20,
                HashAlg::Sha256 => 32,
                HashAlg::HmacSha256(_) => 32,
            };
            let mut output = Vec::with_capacity(output_len);
            let status = BCryptFinishHash(
                self.handle.get() as BCRYPT_HANDLE,
                output.as_mut_ptr(),
                output_len as u32,
                0,
            );
            if status != 0 {
                bail!(ErrorKind::Win32(status));
            }
            output.set_len(output_len);
            Ok(output)
        }
    }
}

pub fn hash_data(alg: HashAlg, data: &[u8]) -> Result<Vec<u8>> {
    let hash = Hash::new(alg)?;
    hash.hash_data(&data)?;
    hash.finish_hash()
}

pub fn hash_sha1(data: &[u8]) -> Result<Vec<u8>> {
    hash_data(HashAlg::Sha1, &data)
}

pub fn hash_sha256(data: &[u8]) -> Result<Vec<u8>> {
    hash_data(HashAlg::Sha256, &data)
}

pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    hash_data(HashAlg::HmacSha256(&secret), &data)
}

pub fn hmac_sha256_with_label(secret: &[u8], label: &str, data: &[u8]) -> Result<Vec<u8>> {
    hmac_sha256(
        secret,
        &label
            .as_bytes()
            .iter()
            .cloned()
            .chain(data.iter().cloned())
            .collect::<Vec<u8>>(),
    )
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
    fn test_generate_symmetric_key() {
        let secret = gen_random(32).unwrap();
        generate_symmetric_key(SymAlg::Aes256Cbc, &secret).unwrap();
        generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "SuperSecretP@ssw0rd!";
        let secret = gen_random(32).unwrap();
        let iv: [u8; 32] = [0; 32];

        let key = generate_symmetric_key(SymAlg::Aes256Cbc, &secret).unwrap();
        let encrypted = encrypt_data(&key, &iv, plaintext.as_bytes()).unwrap();
        let decrypted = decrypt_data(&key, &iv, &encrypted).unwrap();
        assert_eq!(plaintext, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_kdf() {
        let secret = gen_random(32).unwrap();
        let key = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let kdf_bytes1 = key_derivation(&key, "test_kdf", 128).unwrap();
        assert_eq!(kdf_bytes1.len(), 128);

        // Re-derive and ensure the bytes are the same
        let key = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let kdf_bytes2 = key_derivation(&key, "test_kdf", 128).unwrap();
        assert_eq!(kdf_bytes1, kdf_bytes2);
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
        let label = "foobar";
        let label_bytes = label.as_bytes();
        let input: [u8; 5] = [1, 2, 3, 4, 5];
        let secret: [u8; 32] = [0; 32];

        let hash = Hash::new(HashAlg::HmacSha256(&secret)).unwrap();
        hash.hash_data(&label_bytes).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output1 = hash.finish_hash().unwrap();
        assert!(output1.len() == 32);

        let output2 = hmac_sha256(
            &secret,
            &label_bytes
                .iter()
                .cloned()
                .chain(input.iter().cloned().chain(input.iter().cloned()))
                .collect::<Vec<u8>>(),
        ).unwrap();
        assert_eq!(output1, output2);

        let output3 = hmac_sha256_with_label(
            &secret,
            label,
            &input
                .iter()
                .cloned()
                .chain(input.iter().cloned())
                .collect::<Vec<u8>>(),
        ).unwrap();
        assert_eq!(output2, output3);
    }

    #[test]
    fn test_encrypt_then_mac() {
        let username = "username";
        let password = "P@ssw0rd!";
        let iv: [u8; 32] = [0; 32];

        let secret = gen_random(32).unwrap();
        let secret = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let keys = key_derivation(&secret, "encrypt+mac", 64).unwrap();
        let keys = keys.chunks(32).collect::<Vec<&[u8]>>();
        let key = generate_symmetric_key(SymAlg::Aes256Cbc, keys[0]).unwrap();
        let encrypted = encrypt_data(&key, &iv, password.as_bytes()).unwrap();
        let mac = hmac_sha256_with_label(keys[1], username, &encrypted).unwrap();
        // At this point, we would store the (username, mac, encrypted) tuple.
        // Now test that this is all reproducable.
        let keys = key_derivation(&secret, "encrypt+mac", 64).unwrap();
        let keys = keys.chunks(32).collect::<Vec<&[u8]>>();
        let verification = hmac_sha256_with_label(keys[1], username, &encrypted).unwrap();
        assert_eq!(mac, verification);
        let key = generate_symmetric_key(SymAlg::Aes256Cbc, keys[0]).unwrap();
        let decrypted = decrypt_data(&key, &iv, &encrypted).unwrap();
        assert_eq!(password, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_ecdh_key_agreement() {
        let key_alice = generate_key_pair(Algorithm::EcdhP256).unwrap();
        let pubkey_alice = export_key(&key_alice, Blob::EccPublic).unwrap();
        let privkey_alice = export_key(&key_alice, Blob::EccPrivate).unwrap();
        let key_alice =
            import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &privkey_alice).unwrap();

        let key_bob = generate_key_pair(Algorithm::EcdhP256).unwrap();
        let pubkey_bob = export_key(&key_bob, Blob::EccPublic).unwrap();
        let privkey_bob = export_key(&key_bob, Blob::EccPrivate).unwrap();
        let key_bob = import_key_pair(Algorithm::EcdhP256, Blob::EccPrivate, &privkey_bob).unwrap();

        // Import Bob's pub key and derive secret for Alice
        let pubkey_bob =
            import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, &pubkey_bob).unwrap();
        let secret_alice = secret_agreement(&key_alice, &pubkey_bob).unwrap();
        let derived_alice = derive_key(&secret_alice, "alice+bob").unwrap();

        // Import Alice's pub key and derive secret for Bob
        let pubkey_alice =
            import_key_pair(Algorithm::EcdhP256, Blob::EccPublic, &pubkey_alice).unwrap();
        let secret_bob = secret_agreement(&key_bob, &pubkey_alice).unwrap();
        let derived_bob = derive_key(&secret_bob, "alice+bob").unwrap();

        assert_eq!(derived_alice, derived_bob);
    }
}
