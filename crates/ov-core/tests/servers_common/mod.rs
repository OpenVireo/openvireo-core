//! Helpers for the tests against W2-E's in-memory servers (`ov_testkit::servers`). Only compiled
//! with `--cfg ov_test_servers` until W2-E merges.

#![allow(dead_code)]

use std::sync::Arc;

use ov_core::api::*;
use ov_testkit::servers::TestServers;
use ov_testkit::ManualClock;

/// The SDK tests' cheap KDF (`m=19456, t=2`).
pub const KDF: KdfOverrides = KdfOverrides { m: Some(19456), t: Some(2), p: Some(1) };

pub fn servers() -> TestServers {
    TestServers::new(Arc::new(ManualClock::new(1_794_700_800_000)))
}

pub fn config(offline: bool) -> ClientConfig {
    ClientConfig {
        device: DeviceInfo { id: None, name: "test".into(), platform: Platform::Web },
        offline,
        server: None,
    }
}

/// A new device (its own SecureStore and BlobCache) on the test servers.
pub fn device(s: &TestServers, offline: bool) -> OvClient {
    OvClient::new(config(offline), s.host())
}

pub async fn connect(c: &OvClient, s: &TestServers) -> Account {
    c.connect(s.issuer(), CancelToken::new()).await.unwrap()
}

pub fn nc() -> CancelToken {
    CancelToken::new()
}

pub async fn register(a: &Account, email: &str, password: &str) -> NewAccount {
    a.register(
        RegisterInput {
            email: email.into(),
            password: password.as_bytes().to_vec(),
            kdf: Some(KDF),
            trust_device: true,
        },
        nc(),
    )
    .await
    .unwrap()
}

pub fn login_input(email: &str, password: &str, secret_key: Option<&[u8]>) -> LoginInput {
    LoginInput {
        email: email.into(),
        password: password.as_bytes().to_vec(),
        secret_key: secret_key.map(<[u8]>::to_vec),
        totp: None,
        trust_device: true,
    }
}

pub async fn login(a: &Account, email: &str, password: &str, secret_key: Option<&[u8]>) -> Unlocked {
    match a.login(login_input(email, password, secret_key), nc()).await.unwrap() {
        LoginStep::Unlocked(u) => u,
        LoginStep::NeedsTotp(_) => panic!("unexpected TOTP challenge"),
    }
}

pub fn field<'a>(e: &'a EntryRecord, name: &str) -> &'a [u8] {
    e.fields.iter().find(|f| f.name == name).map(|f| f.value.as_slice()).unwrap_or_default()
}

/// Adds an entry `title` with a password to the vault's root.
pub fn add_entry(v: &Vault, title: &str, password: &str) -> String {
    v.add_entry(
        v.root_group_id(),
        EntryInput {
            fields: vec![
                FieldInput { name: "Title".into(), value: title.as_bytes().to_vec(), protected: None },
                FieldInput { name: "Password".into(), value: password.as_bytes().to_vec(), protected: None },
            ],
            ..Default::default()
        },
    )
    .unwrap()
}

pub fn find_title(v: &Vault, title: &str) -> EntryRecord {
    let id = v.entries(false).into_iter().find(|e| e.title == title).expect("entry").id;
    v.entry(id).unwrap()
}
