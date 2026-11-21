//! KDF limits on local `.kdbx` files (`ov_kdbx::check_kdf_limits`): a file from elsewhere picks its
//! own key derivation, and one over the limits is refused with `too_large` before it runs (a huge
//! Argon2 memory used to abort the process). Impls only; the facade docs say so.

use ov_core::api::*;
use ov_core::OvErrorCode;

fn creds() -> KdbxCredentials {
    KdbxCredentials { password: Some(b"pw".to_vec()), ..Default::default() }
}

fn nc() -> CancelToken {
    CancelToken::new()
}

/// `kdbx` with its Argon2 memory (`M` in the header's KDF parameters) set to `memory`, and the
/// header hash fixed up, as a file written by another app would carry it.
fn with_argon2_memory(mut kdbx: Vec<u8>, memory: u64) -> Vec<u8> {
    let key = [0x05, 1, 0, 0, 0, b'M', 8, 0, 0, 0];
    let at = kdbx.windows(key.len()).position(|w| w == key).expect("an Argon2 memory parameter") + key.len();
    kdbx[at..at + 8].copy_from_slice(&memory.to_le_bytes());
    // The outer header: 12 bytes, then fields (id, u32 length, data) up to id 0
    let mut end = 12;
    loop {
        let id = kdbx[end];
        let len = u32::from_le_bytes(kdbx[end + 1..end + 5].try_into().unwrap()) as usize;
        end += 5 + len;
        if id == 0 {
            break;
        }
    }
    let hash = ov_crypto::primitives::sha256(&kdbx[..end]);
    kdbx[end..end + 32].copy_from_slice(&hash);
    kdbx
}

#[tokio::test]
async fn files_over_the_kdf_limits_are_refused_before_they_run() {
    let v = Vault::create_local("Home".into(), creds(), nc()).await.unwrap();
    v.set_kdf(KdbxKdf::Argon2id { memory: 1 << 20, iterations: 2, parallelism: 1 }).unwrap();
    let bytes = v.save_local(nc()).await.unwrap();
    assert!(Vault::open_local(with_argon2_memory(bytes.clone(), 1 << 20), creds(), nc()).await.is_ok());

    // 4 TiB, as KeePassXC's own range allows: refused at once, with what and how much
    let huge = with_argon2_memory(bytes, u64::from(u32::MAX) * 1024);
    let started = std::time::Instant::now();
    let e = Vault::open_local(huge, creds(), nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::TooLarge, "{e}");
    assert!(e.details.unwrap().contains("\"kdf_param\":\"memory\""));
    assert!(started.elapsed().as_secs() < 2);
}

#[tokio::test]
async fn kdf_choices_over_the_limits_are_refused() {
    let v = Vault::create_local("Home".into(), creds(), nc()).await.unwrap();
    let e = v.set_kdf(KdbxKdf::Argon2id { memory: 2 << 30, iterations: 1, parallelism: 1 }).unwrap_err();
    assert_eq!(e.code, OvErrorCode::TooLarge);
    let e = v.set_kdf(KdbxKdf::AesKdf { rounds: 2_000_000_000 }).unwrap_err();
    assert_eq!(e.code, OvErrorCode::TooLarge);
    v.set_kdf(KdbxKdf::AesKdf { rounds: 1000 }).unwrap();
}
