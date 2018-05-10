use crypto::*;
use error::*;
use seckey::{SecKey, TempKey, ZeroSafe};
use std::mem;
use std::ptr;
use std::ptr::{null, null_mut};
use std::string::ToString;
use win32::{CloseHandle, Handle, ToLpcwstr};
use winapi::ctypes::c_void;
use winapi::shared::bcrypt::*;

#[repr(C)]
pub struct BCryptEcdhP256KeyBlob {
    pub header: BCRYPT_ECCKEY_BLOB,
    pub x: [u8; P256_CURVE_SIZE],
    pub y: [u8; P256_CURVE_SIZE],
    pub d: [u8; P256_CURVE_SIZE],
}

unsafe impl ZeroSafe for BCryptEcdhP256KeyBlob {}

impl BCryptEcdhP256KeyBlob {
    pub fn new() -> Self {
        BCryptEcdhP256KeyBlob {
            header: BCRYPT_ECCKEY_BLOB {
                dwMagic: 0,
                cbKey: 0,
            },
            x: [0; P256_CURVE_SIZE],
            y: [0; P256_CURVE_SIZE],
            d: [0; P256_CURVE_SIZE],
        }
    }

    pub fn from_pub_key(pub_key: &PubKey) -> Self {
        unsafe {
            let mut key_struct = BCryptEcdhP256KeyBlob::new();
            key_struct.header = BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PUBLIC_P256_MAGIC,
                cbKey: P256_CURVE_SIZE as u32,
            };
            ptr::copy_nonoverlapping(
                pub_key.x.as_ptr(),
                key_struct.x.as_mut_ptr(),
                P256_CURVE_SIZE,
            );
            ptr::copy_nonoverlapping(
                pub_key.y.as_ptr(),
                key_struct.y.as_mut_ptr(),
                P256_CURVE_SIZE,
            );
            key_struct
        }
    }

    #[cfg(test)]
    pub fn from_priv_key(priv_key: &PrivKey) -> Self {
        unsafe {
            let mut key_struct = BCryptEcdhP256KeyBlob::new();
            key_struct.header = BCRYPT_ECCKEY_BLOB {
                dwMagic: BCRYPT_ECDH_PRIVATE_P256_MAGIC,
                cbKey: P256_CURVE_SIZE as u32,
            };
            ptr::copy_nonoverlapping(
                &*priv_key.d.read() as *const [u8; P256_CURVE_SIZE] as *const u8,
                key_struct.d.as_mut_ptr(),
                P256_CURVE_SIZE,
            );
            key_struct
        }
    }

    pub fn validate_header(&self, magic: u32) {
        assert_eq!(self.header.dwMagic, magic);
        assert_eq!(self.header.cbKey, P256_CURVE_SIZE as u32);
    }
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

pub fn generate_ecdh_p256_key_pair() -> Result<Handle<Key>, PwrsError> {
    unsafe {
        let alg = BCRYPT_ECDH_P256_ALG_HANDLE;
        let mut key = Handle::new();
        let status =
            BCryptGenerateKeyPair(alg, key.put() as *mut usize as *mut BCRYPT_HANDLE, 0, 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptGenerateKeyPair", status));
        }
        let status = BCryptFinalizeKeyPair(key.get() as BCRYPT_HANDLE, 0);
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptFinalizeKeyPair", status));
        }
        Ok(key)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum Blob {
    EccPublic,
    #[cfg(test)]
    EccPrivate,
}

impl ToString for Blob {
    fn to_string(&self) -> String {
        String::from(match self {
            Blob::EccPublic => BCRYPT_ECCPUBLIC_BLOB,
            #[cfg(test)]
            Blob::EccPrivate => BCRYPT_ECCPRIVATE_BLOB,
        })
    }
}

pub fn import_ecdh_p256_pub_key(pub_key: &PubKey) -> Result<Handle<Key>, PwrsError> {
    let key_struct = BCryptEcdhP256KeyBlob::from_pub_key(pub_key);
    import_ecdh_p256_key(Blob::EccPublic, key_struct)
}

#[cfg(test)]
pub fn import_ecdh_p256_priv_key(priv_key: &PrivKey) -> Result<Handle<Key>, PwrsError> {
    let key_struct = BCryptEcdhP256KeyBlob::from_priv_key(priv_key);
    import_ecdh_p256_key(Blob::EccPrivate, key_struct)
}

fn import_ecdh_p256_key(
    blob: Blob,
    mut key_struct: BCryptEcdhP256KeyBlob,
) -> Result<Handle<Key>, PwrsError> {
    unsafe {
        let mut key_struct = TempKey::from(&mut key_struct);
        let alg = BCRYPT_ECDH_P256_ALG_HANDLE;
        let mut key = Handle::new();
        let status = BCryptImportKeyPair(
            alg,
            null_mut(),
            blob.to_string().to_lpcwstr().as_ptr(),
            key.put() as *mut usize as *mut BCRYPT_HANDLE,
            &mut *key_struct as *mut BCryptEcdhP256KeyBlob as *mut u8,
            mem::size_of::<BCryptEcdhP256KeyBlob>() as u32,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptImportKeyPair", status));
        }
        Ok(key)
    }
}

fn export_ecdh_p256_key(key: &Handle<Key>, blob: Blob) -> Result<BCryptEcdhP256KeyBlob, PwrsError> {
    unsafe {
        let mut key_struct = BCryptEcdhP256KeyBlob::new();
        let blob_bytes = blob.to_string().to_lpcwstr();
        let mut byte_count: u32 = 0;
        let status = BCryptExportKey(
            key.get() as BCRYPT_HANDLE,
            null_mut(),
            blob_bytes.as_ptr(),
            &mut key_struct as *mut BCryptEcdhP256KeyBlob as *mut u8,
            mem::size_of::<BCryptEcdhP256KeyBlob>() as u32,
            &mut byte_count,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptExportKey", status));
        }

        Ok(key_struct)
    }
}

pub fn export_ecdh_p256_pub_key(key: &Handle<Key>) -> Result<PubKey, PwrsError> {
    let key = export_ecdh_p256_key(key, Blob::EccPublic)?;
    key.validate_header(BCRYPT_ECDH_PUBLIC_P256_MAGIC);
    Ok(PubKey { x: key.x, y: key.y })
}

#[cfg(test)]
pub fn export_ecdh_p256_priv_key(key: &Handle<Key>) -> Result<PrivKey, PwrsError> {
    let mut key = export_ecdh_p256_key(key, Blob::EccPrivate)?;
    let key = TempKey::from(&mut key);
    key.validate_header(BCRYPT_ECDH_PRIVATE_P256_MAGIC);
    Ok(PrivKey {
        d: SecKey::new(key.d).unwrap(),
    })
}

pub fn secret_agreement(sk: &Handle<Key>, pk: &Handle<Key>) -> Result<Handle<Secret>, PwrsError> {
    unsafe {
        let mut secret = Handle::new();
        let status = BCryptSecretAgreement(
            sk.get() as BCRYPT_HANDLE,
            pk.get() as BCRYPT_HANDLE,
            secret.put() as *mut usize as *mut BCRYPT_HANDLE,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptSecretAgreement", status));
        }
        Ok(secret)
    }
}

pub fn derive_key(secret: &Handle<Secret>, label: &str) -> Result<AgreedSecret, PwrsError> {
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
        let mut output = AgreedSecret {
            s: SecKey::new([0; SHA2_DIGEST_SIZE]).unwrap(),
        };
        let mut byte_count: u32 = 0;
        let status = BCryptDeriveKey(
            secret.get() as BCRYPT_HANDLE,
            BCRYPT_KDF_HMAC.to_lpcwstr().as_ptr(),
            &mut parameters,
            &mut *output.s.write() as *mut [u8; SHA2_DIGEST_SIZE] as *mut u8,
            32,
            &mut byte_count,
            KDF_USE_SECRET_AS_HMAC_KEY_FLAG,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptDeriveKey", status));
        }
        Ok(output)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum SymAlg {
    Sp800108CtrHmacKdf,
    Aes256Cbc,
}

pub fn generate_symmetric_key(alg: SymAlg, secret: &[u8]) -> Result<Handle<Key>, PwrsError> {
    let (alg_handle, expected_len) = match alg {
        SymAlg::Sp800108CtrHmacKdf => (BCRYPT_SP800108_CTR_HMAC_ALG_HANDLE, SHA2_DIGEST_SIZE),
        SymAlg::Aes256Cbc => (BCRYPT_AES_CBC_ALG_HANDLE, AES256_KEY_SIZE),
    };
    if secret.len() != expected_len {
        return Err(PwrsError::BufferTooSmall(expected_len, secret.len()));
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
            return Err(PwrsError::Win32Error("BCryptGenerateSymmetricKey", status));
        }
        Ok(key)
    }
}

#[repr(C)]
struct BCryptKeyMaterial {
    k: [u8; AES256_KEY_SIZE],
    s: [u8; SHA2_DIGEST_SIZE],
}

unsafe impl ZeroSafe for BCryptKeyMaterial {}

pub fn key_derivation(
    key: &Handle<Key>,
    label: &str,
) -> Result<(EncryptionKey, MacSecret), PwrsError> {
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
        let mut output = BCryptKeyMaterial {
            k: [0; AES256_KEY_SIZE],
            s: [0; SHA2_DIGEST_SIZE],
        };
        let mut output = TempKey::from(&mut output);
        let mut result_byte_count = 0;
        let status = BCryptKeyDerivation(
            key.get() as BCRYPT_HANDLE,
            &mut parameters,
            &mut *output as *mut BCryptKeyMaterial as *mut u8,
            mem::size_of::<BCryptKeyMaterial>() as u32,
            &mut result_byte_count,
            0,
        );
        if status != 0 {
            return Err(PwrsError::Win32Error("BCryptKeyDerivation", status));
        }

        Ok((
            EncryptionKey(SecKey::new(output.k).unwrap()),
            MacSecret(SecKey::new(output.s).unwrap()),
        ))
    }
}

pub fn encrypt_data(key: &Handle<Key>, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, PwrsError> {
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
            return Err(PwrsError::Win32Error("BCryptEncrypt", status));
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
            return Err(PwrsError::Win32Error("BCryptEncrypt", status));
        }

        output.set_len(result_byte_count as usize);
        Ok(output)
    }
}

pub fn decrypt_data(key: &Handle<Key>, iv: &[u8], data: &[u8]) -> Result<Vec<u8>, PwrsError> {
    unsafe {
        let mut iv = iv.to_vec();
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
            return Err(PwrsError::Win32Error("BCryptDecrypt", status));
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
            return Err(PwrsError::Win32Error("BCryptDecrypt", status));
        }

        output.set_len(result_byte_count as usize);
        Ok(output)
    }
}

enum HashAlg<'a> {
    Sha1,
    HmacSha256(&'a [u8]),
}

struct Hash<'a> {
    handle: Handle<HashHandle>,
    alg: HashAlg<'a>,
}

impl<'a> Hash<'a> {
    fn new(alg: HashAlg) -> Result<Hash, PwrsError> {
        unsafe {
            let mut hash = Hash {
                handle: Handle::new(),
                alg,
            };
            let (alg_handle, secret, secret_len) = match hash.alg {
                HashAlg::Sha1 => (BCRYPT_SHA1_ALG_HANDLE, null(), 0),
                HashAlg::HmacSha256(secret) => {
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
                return Err(PwrsError::Win32Error("BCryptCreateHash", status));
            }
            Ok(hash)
        }
    }

    fn hash_data(&self, data: &[u8]) -> Result<(), PwrsError> {
        unsafe {
            let status = BCryptHashData(
                self.handle.get() as BCRYPT_HANDLE,
                data.as_ptr() as *const u8 as *mut u8,
                data.len() as u32,
                0,
            );
            if status != 0 {
                return Err(PwrsError::Win32Error("BCryptHashData", status));
            }
            Ok(())
        }
    }

    fn finish_hash_sha2(self) -> Result<[u8; SHA2_DIGEST_SIZE], PwrsError> {
        unsafe {
            let mut output = [0u8; SHA2_DIGEST_SIZE];
            let status = BCryptFinishHash(
                self.handle.get() as BCRYPT_HANDLE,
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            );
            if status != 0 {
                return Err(PwrsError::Win32Error("BCryptFinishHash", status));
            }
            Ok(output)
        }
    }

    fn finish_hash_sha1(self) -> Result<[u8; SHA1_DIGEST_SIZE], PwrsError> {
        unsafe {
            let mut output = [0u8; SHA1_DIGEST_SIZE];
            let status = BCryptFinishHash(
                self.handle.get() as BCRYPT_HANDLE,
                output.as_mut_ptr(),
                output.len() as u32,
                0,
            );
            if status != 0 {
                return Err(PwrsError::Win32Error("BCryptFinishHash", status));
            }
            Ok(output)
        }
    }
}

pub struct HashSha1<'a> {
    hasher: Hash<'a>,
}

impl<'a> HashSha1<'a> {
    pub fn new() -> Result<Self, PwrsError> {
        Ok(HashSha1 {
            hasher: Hash::new(HashAlg::Sha1)?,
        })
    }

    pub fn hash(self, bytes: &[u8]) -> Result<Self, PwrsError> {
        self.hasher.hash_data(bytes)?;
        Ok(self)
    }

    pub fn finish_hash(self) -> Result<[u8; SHA1_DIGEST_SIZE], PwrsError> {
        self.hasher.finish_hash_sha1()
    }
}

pub struct HmacSha2<'a> {
    hasher: Hash<'a>,
}

impl<'a> HmacSha2<'a> {
    pub fn new(secret: &'a [u8]) -> Result<Self, PwrsError> {
        Ok(HmacSha2 {
            hasher: Hash::new(HashAlg::HmacSha256(secret))?,
        })
    }

    pub fn hash(self, bytes: &[u8]) -> Result<Self, PwrsError> {
        self.hasher.hash_data(bytes)?;
        Ok(self)
    }

    pub fn finish_hash(self) -> Result<[u8; SHA2_DIGEST_SIZE], PwrsError> {
        self.hasher.finish_hash_sha2()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_symmetric_key() {
        let secret = [0u8; 32];
        generate_symmetric_key(SymAlg::Aes256Cbc, &secret).unwrap();
        generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "SuperSecretP@ssw0rd!";
        let secret = [1u8; 32];
        let iv = [0u8; 16];

        let key = generate_symmetric_key(SymAlg::Aes256Cbc, &secret).unwrap();
        let encrypted = encrypt_data(&key, &iv, plaintext.as_bytes()).unwrap();
        let decrypted = decrypt_data(&key, &iv, &encrypted).unwrap();
        assert_eq!(plaintext, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_kdf() {
        let secret = [2u8; 32];
        let key = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let (k1, s1) = key_derivation(&key, "test_kdf").unwrap();

        // Re-derive and ensure the bytes are the same
        let key = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let (k2, s2) = key_derivation(&key, "test_kdf").unwrap();
        assert_eq!(*k1.0.read(), *k2.0.read());
        assert_eq!(*s1.0.read(), *s2.0.read());
    }

    #[test]
    fn test_hash_data_sha1() {
        let input: [u8; 5] = [1, 2, 3, 4, 5];

        let hash = Hash::new(HashAlg::Sha1).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output1 = hash.finish_hash_sha1().unwrap();

        let hash = Hash::new(HashAlg::Sha1).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output2 = hash.finish_hash_sha1().unwrap();

        assert_eq!(output1, output2);
        assert!(output1.len() == 20);
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
        let output1 = hash.finish_hash_sha2().unwrap();

        let hash = Hash::new(HashAlg::HmacSha256(&secret)).unwrap();
        hash.hash_data(&label_bytes).unwrap();
        hash.hash_data(&input).unwrap();
        hash.hash_data(&input).unwrap();
        let output2 = hash.finish_hash_sha2().unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_encrypt_then_mac() {
        let username = "username";
        let password = "P@ssw0rd!";
        let iv: [u8; 32] = [0; 32];

        let secret = [255u8; 32];
        let secret = generate_symmetric_key(SymAlg::Sp800108CtrHmacKdf, &secret).unwrap();
        let (k, s) = key_derivation(&secret, "encrypt+mac").unwrap();
        let key = generate_symmetric_key(SymAlg::Aes256Cbc, &*k.0.read()).unwrap();
        let encrypted = encrypt_data(&key, &iv, password.as_bytes()).unwrap();
        let s_read = s.0.read();
        let hash = Hash::new(HashAlg::HmacSha256(&*s_read)).unwrap();
        hash.hash_data(username.as_bytes()).unwrap();
        hash.hash_data(&encrypted).unwrap();
        let mac = hash.finish_hash_sha2().unwrap();
        // At this point, we would store the (username, mac, encrypted) tuple.
        // Now test that this is all reproducable.
        let (k, s) = key_derivation(&secret, "encrypt+mac").unwrap();
        let s_read = s.0.read();
        let hash = Hash::new(HashAlg::HmacSha256(&*s_read)).unwrap();
        hash.hash_data(username.as_bytes()).unwrap();
        hash.hash_data(&encrypted).unwrap();
        let verification = hash.finish_hash_sha2().unwrap();
        assert_eq!(mac, verification);
        let key = generate_symmetric_key(SymAlg::Aes256Cbc, &*k.0.read()).unwrap();
        let decrypted = decrypt_data(&key, &iv, &encrypted).unwrap();
        assert_eq!(password, String::from_utf8(decrypted).unwrap());
    }

    #[test]
    fn test_ecdh_key_agreement() {
        let key_alice = generate_ecdh_p256_key_pair().unwrap();
        let pubkey_alice = export_ecdh_p256_pub_key(&key_alice).unwrap();
        let privkey_alice = export_ecdh_p256_priv_key(&key_alice).unwrap();
        let key_alice = import_ecdh_p256_priv_key(&privkey_alice).unwrap();

        let key_bob = generate_ecdh_p256_key_pair().unwrap();
        let pubkey_bob = export_ecdh_p256_pub_key(&key_bob).unwrap();
        let privkey_bob = export_ecdh_p256_priv_key(&key_bob).unwrap();
        let key_bob = import_ecdh_p256_priv_key(&privkey_bob).unwrap();

        // Import Bob's pub key and derive secret for Alice
        let pubkey_bob = import_ecdh_p256_pub_key(&pubkey_bob).unwrap();
        let secret_alice = secret_agreement(&key_alice, &pubkey_bob).unwrap();
        let derived_alice = derive_key(&secret_alice, "alice+bob").unwrap();

        // Import Alice's pub key and derive secret for Bob
        let pubkey_alice = import_ecdh_p256_pub_key(&pubkey_alice).unwrap();
        let secret_bob = secret_agreement(&key_bob, &pubkey_alice).unwrap();
        let derived_bob = derive_key(&secret_bob, "alice+bob").unwrap();

        assert_eq!(*derived_alice.s.read(), *derived_bob.s.read());
    }
}
