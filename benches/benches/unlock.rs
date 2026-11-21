//! Unlock costs with the KDF parameters the clients use:
//! - account unlock (SPEC §3): Argon2id m = 64 MiB, t = 3, p = 1 (`KDF_DEFAULTS`), HKDF with the
//!   Secret Key, then the keyset unwrap (what `Account::unlock_offline` and sign-in run);
//! - an account vault (SPEC §7): KDBX 4 with the vault KDF, Argon2id 1 MiB, t = 2, p = 1;
//! - a local database with KeePassXC's default KDF: Argon2d 64 MiB, t = 10, p = 2.

use criterion::{criterion_group, criterion_main, Criterion};
use ov_benches::T0;
use ov_crypto::auk::{derive_auk, new_kdf_params, DeriveAukOptions};
use ov_crypto::keyset::{generate_keyset, unwrap_keyset, wrap_keyset};
use ov_crypto::secret_key::generate_secret_key;
use ov_kdbx::vault::{create_kdbx, create_vault_kdbx, database_default_kdf, password_credentials, set_kdf};

fn unlock(c: &mut Criterion) {
    let mut g = c.benchmark_group("unlock");
    g.sample_size(10);

    let kdf = new_kdf_params().expect("kdf");
    let sk = generate_secret_key().expect("secret key");
    let password = "correct horse battery staple";
    let auk = derive_auk(password, &kdf, &sk, DeriveAukOptions::default()).expect("auk");
    let wrapped = wrap_keyset(&auk, &generate_keyset().expect("keyset")).expect("wrap");
    g.bench_function("account/argon2id-64MiB-t3-p1", |b| {
        b.iter(|| {
            let auk = derive_auk(password, &kdf, &sk, DeriveAukOptions::default()).expect("auk");
            unwrap_keyset(&auk, &wrapped).expect("unwrap")
        })
    });

    let (vault, vault_key) = create_vault_kdbx("Vault", &[7; 32], T0).expect("vault");
    let vault_bytes = ov_kdbx::write(&vault, &vault_key).expect("write vault");
    g.bench_function("vault/argon2id-1MiB-t2-p1", |b| {
        b.iter(|| ov_kdbx::read(&vault_bytes, &vault_key).expect("open vault"))
    });

    let mut local = create_kdbx("Local", T0).expect("db");
    set_kdf(&mut local, database_default_kdf().expect("kdf"));
    let local_key = password_credentials(Some(password), None);
    let local_bytes = ov_kdbx::write(&local, &local_key).expect("write local");
    g.bench_function("local_db/argon2d-64MiB-t10-p2", |b| {
        b.iter(|| ov_kdbx::read(&local_bytes, &local_key).expect("open local"))
    });
    g.finish();
}

criterion_group!(benches, unlock);
criterion_main!(benches);
