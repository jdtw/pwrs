extern crate pwrs;

use pwrs::win32::ncrypt;
use pwrs::win32::ncrypt::{Algorithm, Blob, Ksp};

fn main() {
    let prov = ncrypt::open_storage_provider(Ksp::Software).unwrap();
    let key = ncrypt::create_persisted_key(&prov, Algorithm::EcdhP256, None).unwrap();
    ncrypt::finalize_key(&key).unwrap();
    let pubkey = ncrypt::export_key(&key, Blob::EccPublic).unwrap();
    println!("pub: {} {:?}", pubkey.len(), pubkey);
    //ncrypt::delete_key(key).unwrap();
}
