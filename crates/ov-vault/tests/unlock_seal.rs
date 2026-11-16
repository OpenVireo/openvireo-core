//! Ports of the SDK's `test/unlock-seal.test.ts` that are core logic. The AES-GCM seal itself (a
//! non-extractable WebCrypto key, format `s1.<iv>.<data>`) stays in the TS wrapper; the core supplies
//! the 64 secret bytes, the AAD that binds them to issuer + user, and the check that what comes
//! back is this account's keyset. `passwordHash` / `passwordHashCredentials` are ov-kdbx's
//! (`password_hash`, `password_hash_credentials`) and tested there.

mod common;

use common::*;
use ov_error::OvErrorCode;
use ov_protocol::types::VaultRole;
use ov_vault::keys::wire_public;
use ov_vault::unlock::{keyset_secret, resume_keyset, unlock_seal_aad, UNLOCK_SEAL_VERSION};
use ov_vault::{new_vault, parse_reference, read_field, Keyring};

#[test]
fn resumes_from_the_sealed_secret_and_the_vaults_open() {
    let mut server = Server::default();
    let alice = User::new("alice");
    server.register(&alice);
    let nv = new_vault("Personal", &alice.principal(), &alice.keyset, None).unwrap();
    server.create_vault(&alice.principal(), &nv.request).unwrap();
    server.blobs.insert(nv.id.clone(), vault_blob("Personal", &nv.key, &[("GitHub", "", "s3cret")]));

    let secret = keyset_secret(&alice.keyset);
    assert_eq!(secret.len(), 64);
    // after a reload: the unsealed bytes and the account's public keys from GET /me
    let resumed = resume_keyset(&secret, &server.publics[&alice.principal()]).unwrap();
    assert_eq!(resumed.public, alice.keyset.public);
    assert_eq!(resumed.public.fingerprint(), alice.keyset.public.fingerprint());
    let mut keyring = Keyring::new();
    keyring.ingest_list(&server.list_vaults(&alice.principal()), &resumed);
    let v = keyring.get(&nv.id).unwrap();
    assert_eq!((v.info.name.as_str(), v.info.role.clone()), ("Personal", VaultRole::Manage));
    let db = open(&server, v).unwrap();
    assert_eq!(&*read_field(&db, &parse_reference("ov://Personal/GitHub/password").unwrap()).unwrap(), "s3cret");

    // lock: the keyring wipes its keys
    keyring.clear();
    assert!(keyring.is_empty());
}

#[test]
fn rejects_a_plaintext_of_the_wrong_length() {
    let alice = User::new("alice");
    let public = wire_public(&alice.keyset.public);
    let secret = keyset_secret(&alice.keyset);
    for bad in [&secret[..63], &[][..], &[0u8; 65][..]] {
        assert!(resume_keyset(bad, &public).unwrap_err().is(OvErrorCode::DecryptionFailed));
    }
}

#[test]
fn is_bound_to_the_user_and_issuer() {
    let a = unlock_seal_aad("https://accounts.example/", "alice-id");
    assert_eq!(a, "ov-unlock-seal-v1|https://accounts.example|alice-id");
    assert_eq!(unlock_seal_aad("https://accounts.example//", "alice-id"), a);
    assert_ne!(unlock_seal_aad("https://accounts.example", "bob-id"), a);
    assert_ne!(unlock_seal_aad("https://other.example", "alice-id"), a);
    assert_eq!(UNLOCK_SEAL_VERSION, "s1");
}

#[test]
fn another_accounts_keyset_is_refused() {
    let (alice, bob) = (User::new("alice"), User::new("bob"));
    let e = resume_keyset(&keyset_secret(&alice.keyset), &wire_public(&bob.keyset.public)).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidPublicKeys));
}

#[test]
fn fails_when_the_accounts_keys_changed_after_a_reset() {
    // the server now holds another keyset for alice
    let (alice, reset) = (User::new("alice"), User::new("alice"));
    let e = resume_keyset(&keyset_secret(&alice.keyset), &wire_public(&reset.keyset.public)).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidPublicKeys));
    // and public keys whose signature doesn't verify are refused too
    let mut forged = wire_public(&alice.keyset.public);
    forged.sig = wire_public(&reset.keyset.public).sig;
    assert!(resume_keyset(&keyset_secret(&alice.keyset), &forged).unwrap_err().is(OvErrorCode::InvalidPublicKeys));
}
