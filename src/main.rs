extern crate pwrs;

use pwrs::win32::ncrypt;
use pwrs::win32::ncrypt::{Algorithm, Ksp};

fn main() {
    let prov = ncrypt::open_storage_provider(Ksp::Software).unwrap();
    let key = ncrypt::create_persisted_key(&prov, Algorithm::EcdhP256, "foobarbazquux").unwrap();
    ncrypt::finalize_key(&key).unwrap();
    let pubkey = ncrypt::export_key(&key).unwrap();
    println!("pub: {} {:?}", pubkey.len(), pubkey);
    ncrypt::delete_key(key).unwrap();
}
