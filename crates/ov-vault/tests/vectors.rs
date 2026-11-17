//! The contract vectors that cross ov-vault's paths: a listed vault built from the `seal` and
//! `vault_name` vectors unseals to the vector's key and name, and the `service_account` vector's
//! token, wrapped master and master sealed to the admin open through the SA functions.

use ov_crypto::encoding::to_hex;
use ov_crypto::keyset::keyset_from_secrets;
use ov_crypto::tokens::parse_sa_token;
use ov_protocol::types::{ServiceAccount, ServiceAccountExchange, Vault, VaultKey, VaultRole, WrappedKeyset};
use ov_testkit::hex_array;
use ov_testkit::test_vectors::TestVectors;
use ov_vault::service_account::{exchange_request, unlock_service_account, unseal_master};
use ov_vault::VaultKeys;

fn vectors() -> TestVectors {
    ov_testkit::load_json("test-vectors.json")
}

#[test]
fn seal_and_vault_name_vectors_ingest() {
    let tv = vectors();
    let s = &tv.seal[0];
    let vault_id = s.aad.strip_prefix("ov-vault-key|").unwrap();
    assert_eq!(vault_id, tv.vault_name.vault_id);
    let ks = keyset_from_secrets(&hex_array::<32>(&s.recipient_enc_sk_hex), &[7u8; 32]);
    let listed = Vault {
        id: vault_id.to_owned(),
        org_id: None,
        owner_id: None,
        encrypted_name: tv.vault_name.encrypted_name.clone(),
        role: VaultRole::Read,
        current_key_version: 3,
        pending_key_version: None,
        rotation_required: None,
        keys: vec![
            VaultKey { key_version: 2, sealed_key: "not-a-sealed-key".into() },
            VaultKey { key_version: 3, sealed_key: s.sealed.clone() },
        ],
        created_at: None,
    };
    let v = VaultKeys::from_vault(&listed, &ks);
    assert_eq!(v.info.name, tv.vault_name.name);
    assert_eq!(v.keys().len(), 1);
    assert_eq!(to_hex(&v.current_key().unwrap().key), s.plaintext_hex);
    assert_eq!(s.plaintext_hex, tv.vault_name.vault_key_hex);

    // sealed for another vault id: the AAD doesn't match, so nothing opens
    let mut other = listed.clone();
    other.id = "00000000-0000-4000-8000-000000000000".into();
    let v = VaultKeys::from_vault(&other, &ks);
    assert!(v.keys().is_empty());
    assert_eq!(v.info.name, "");
}

#[test]
fn service_account_vector_unlocks() {
    let tv = vectors();
    let sa = &tv.service_account;
    let t = parse_sa_token(&sa.token).unwrap();
    assert_eq!(exchange_request(&t).secret, ov_crypto::encoding::b64u(&*t.secret));
    let ex = ServiceAccountExchange {
        access_token: "jwt".into(),
        expires_in: 900,
        wrapped_master: sa.wrapped_master.clone(),
        keyset: WrappedKeyset {
            enc_pk: sa.public.enc_pk.clone(),
            sign_pk: sa.public.sign_pk.clone(),
            sig: sa.public.sig.clone(),
            wrapped: sa.wrapped_keyset.clone(),
        },
    };
    let ks = unlock_service_account(&t, &ex).unwrap();
    assert_eq!(to_hex(&*ks.enc_sk), sa.keyset_enc_sk_hex);
    assert_eq!(to_hex(&*ks.sign_seed), sa.keyset_sign_seed_hex);
    assert_eq!(ks.public.fingerprint(), sa.public.fingerprint);

    // the admin (the `keyset` vector's principal) unseals the master key
    assert_eq!(sa.master_sealed_to_admin.admin, tv.keyset.principal);
    let admin =
        keyset_from_secrets(&hex_array::<32>(&tv.keyset.enc_sk_hex), &hex_array::<32>(&tv.keyset.sign_seed_hex));
    let listed = ServiceAccount {
        id: sa.sa_id.clone(),
        org_id: "org".into(),
        name: "ci".into(),
        public: None,
        keyset: None,
        master_key: Some(sa.master_sealed_to_admin.sealed.clone()),
        created_by: None,
        created_at: None,
        expires_at: None,
        disabled: None,
    };
    assert_eq!(to_hex(&*unseal_master(&admin, &listed).unwrap()), sa.master_key_hex);
}
