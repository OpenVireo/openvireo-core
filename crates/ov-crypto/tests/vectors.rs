//! `vectors/test-vectors.json` sections owned by ov-crypto. Each test is named after its vector
//! section and case (array cases without a `case` name use their index).

use std::sync::OnceLock;

use ov_crypto::auk::{derive_auk, password_bytes, stretch_password, DeriveAukOptions, KdfParams};
use ov_crypto::encoding::{b64u, from_b64u, to_hex};
use ov_crypto::envelope::{
    aad, seal_derived_key, seal_sa_master_with, seal_with, unseal, unseal_sa_master, unseal_vault_key, unwrap,
    SealOptions,
};
use ov_crypto::jwt::{decode_jwt, verify_jwt, verify_jwt_refetching, Jwks, VerifyOptions, DEFAULT_SKEW_SECS};
use ov_crypto::keyset::{
    fingerprint, keyset_from_secrets, trusted_public_keys, unwrap_keyset, verify_public_keys, wrap_keyset_with_nonce,
    Keyset, PublicKeysJson, WrappedKeysetJson,
};
use ov_crypto::restore::{
    check_restore_proof, reseal_vault_key, reseal_vault_key_with, restore_proof, restore_proof_message,
    verify_restore_proof,
};
use ov_crypto::secret_key::{format_secret_key, parse_secret_key};
use ov_crypto::tokens::{
    build_sa_token, parse_sa_token, refresh_token_hash, sa_secret_hash, sa_secret_prefix, unwrap_sa_master,
    wrap_sa_master_with_nonce,
};
use ov_crypto::vault_name::{decrypt_vault_name, encrypt_vault_name_with_nonce, vault_name_key};
use ov_crypto::Zeroizing;
use ov_error::OvErrorCode;
use ov_testkit::test_vectors::{self as tv, TestVectors};
use ov_testkit::{hex_array, hex_bytes};

fn v() -> &'static TestVectors {
    static V: OnceLock<TestVectors> = OnceLock::new();
    V.get_or_init(ov_testkit::test_vectors)
}

fn z32(hex: &str) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(hex_array::<32>(hex))
}

fn kdf(k: &tv::Kdf) -> KdfParams {
    KdfParams { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p }
}

fn pk_json(p: &tv::PublicKeyset) -> PublicKeysJson {
    PublicKeysJson { enc_pk: p.enc_pk.clone(), sign_pk: p.sign_pk.clone(), sig: p.sig.clone() }
}

fn wrapped(p: &tv::PublicKeyset, w: &str) -> WrappedKeysetJson {
    WrappedKeysetJson {
        enc_pk: p.enc_pk.clone(),
        sign_pk: p.sign_pk.clone(),
        sig: p.sig.clone(),
        wrapped: w.to_owned(),
    }
}

fn seal_opts(esk_hex: &str, nonce_hex: &str) -> SealOptions {
    SealOptions { ephemeral_secret_key: Some(z32(esk_hex)), nonce: Some(hex_array::<24>(nonce_hex)) }
}

// ---- secret_key (SPEC §2)

fn secret_key_case(i: usize) {
    let c = &v().secret_key[i];
    let raw = hex_array::<16>(&c.raw_hex);
    assert_eq!(format_secret_key(&raw).as_str(), c.display);
    assert_eq!(*parse_secret_key(&c.display).unwrap(), raw);
}

#[test]
fn secret_key_0() {
    secret_key_case(0);
}

#[test]
fn secret_key_1_all_zero() {
    secret_key_case(1);
}

#[test]
fn secret_key_2_all_ones() {
    secret_key_case(2);
}

#[test]
fn secret_key_count() {
    assert_eq!(v().secret_key.len(), 3);
}

#[test]
fn secret_key_0_sloppy_input() {
    let c = &v().secret_key[0];
    let sloppy = format!(" k1 {}", c.display[3..].to_lowercase().replace('-', " ").replace('0', "o").replace('1', "l"));
    assert_eq!(*parse_secret_key(&sloppy).unwrap(), hex_array::<16>(&c.raw_hex));
}

// ---- auk (SPEC §3)

fn auk_case(i: usize) {
    let c = &v().auk[i];
    let k = kdf(&c.kdf);
    let sk = hex_array::<16>(&c.secret_key_hex);
    let weak_ok = DeriveAukOptions { allow_weak: true, ..Default::default() };
    assert_eq!(to_hex(&password_bytes(&c.password)), c.password_nfkc_hex);
    assert_eq!(to_hex(stretch_password(&c.password, &k, weak_ok).unwrap().as_ref()), c.argon2id_hex);
    assert_eq!(to_hex(derive_auk(&c.password, &k, &sk, weak_ok).unwrap().as_ref()), c.auk_hex);
    // Server-provided parameters go through the floor: the vectors' m = 1024 is refused.
    let checked = derive_auk(&c.password, &k, &sk, DeriveAukOptions::default());
    if c.kdf.m < 19456 {
        assert!(checked.unwrap_err().is(OvErrorCode::WeakKdf));
    } else {
        assert_eq!(to_hex(checked.unwrap().as_ref()), c.auk_hex);
    }
}

#[test]
fn auk_0_ascii_password() {
    auk_case(0);
}

#[test]
fn auk_1_nfkc_password() {
    assert!(!v().auk[1].password.is_ascii());
    auk_case(1);
}

#[test]
fn auk_2_production_kdf() {
    auk_case(2);
}

#[test]
fn auk_count() {
    assert_eq!(v().auk.len(), 3);
}

// ---- keyset (SPEC §4, §5)

#[test]
fn keyset_public_keys_signature_and_fingerprint() {
    let k = &v().keyset;
    let ks = keyset_from_secrets(&z32(&k.enc_sk_hex), &z32(&k.sign_seed_hex));
    assert_eq!(ks.public.to_json(), pk_json(&k.public));
    assert_eq!(ks.public.fingerprint(), k.public.fingerprint);
    assert!(verify_public_keys(&ks.public));
    assert_eq!(k.aad, aad::KEYSET);
}

#[test]
fn keyset_wraps_byte_for_byte_and_unwraps() {
    let k = &v().keyset;
    let auk = z32(&k.auk_hex);
    let ks = keyset_from_secrets(&z32(&k.enc_sk_hex), &z32(&k.sign_seed_hex));
    let w = wrap_keyset_with_nonce(&auk, &ks, &hex_array::<24>(&k.nonce_hex));
    assert_eq!(w.wrapped, k.wrapped);
    let plain = unwrap(&auk, &from_b64u(&k.wrapped).unwrap(), &k.aad).unwrap();
    assert_eq!(to_hex(&plain), format!("{}{}", k.enc_sk_hex, k.sign_seed_hex));
    let back = unwrap_keyset(&auk, &wrapped(&k.public, &k.wrapped)).unwrap();
    assert_eq!(to_hex(back.enc_sk.as_ref()), k.enc_sk_hex);
    assert_eq!(to_hex(back.sign_seed.as_ref()), k.sign_seed_hex);
}

#[test]
fn keyset_rejects_swapped_public_keys() {
    let k = &v().keyset;
    let bob = &v().public_keys[0];
    let w = WrappedKeysetJson {
        enc_pk: bob.enc_pk.clone(),
        sign_pk: bob.sign_pk.clone(),
        sig: bob.sig.clone(),
        wrapped: k.wrapped.clone(),
    };
    let e = unwrap_keyset(&z32(&k.auk_hex), &w).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidPublicKeys) && e.message.contains("don't match"));
}

#[test]
fn keyset_rejects_wrong_auk_and_unknown_version() {
    let k = &v().keyset;
    let mut wrong = z32(&k.auk_hex);
    wrong[0] ^= 1;
    let blob = from_b64u(&k.wrapped).unwrap();
    assert!(unwrap(&wrong, &blob, &k.aad).unwrap_err().is(OvErrorCode::DecryptionFailed));
    assert!(unwrap_keyset(&wrong, &wrapped(&k.public, &k.wrapped)).unwrap_err().is(OvErrorCode::DecryptionFailed));
    let mut v2 = blob;
    v2[0] = 2;
    assert!(unwrap(&z32(&k.auk_hex), &v2, &k.aad).unwrap_err().is(OvErrorCode::UnsupportedVersion));
}

// ---- public_keys (SPEC §5)

#[test]
fn public_keys_user_bob() {
    let p = v().public_keys.iter().find(|p| p.principal == "user:bob").expect("user:bob case");
    let ks = keyset_from_secrets(&z32(&p.enc_sk_hex), &z32(&p.sign_seed_hex));
    let json = PublicKeysJson { enc_pk: p.enc_pk.clone(), sign_pk: p.sign_pk.clone(), sig: p.sig.clone() };
    assert_eq!(ks.public.to_json(), json);
    assert_eq!(fingerprint(&ks.public.enc_pk, &ks.public.sign_pk), p.fingerprint);
    assert_eq!(trusted_public_keys(&json).unwrap(), ks.public);
    let forged = PublicKeysJson { sig: v().keyset.public.sig.clone(), ..json };
    let e = trusted_public_keys(&forged).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidPublicKeys) && e.message.contains("signature"));
}

#[test]
fn public_keys_count() {
    assert_eq!(v().public_keys.len(), 1);
}

// ---- seal (SPEC §6)

fn seal_case(i: usize) {
    let s = &v().seal[i];
    let opts = seal_opts(&s.ephemeral_sk_hex, &s.nonce_hex);
    let sealed =
        seal_with(&from_b64u(&s.recipient_enc_pk).unwrap(), &hex_bytes(&s.plaintext_hex), &s.aad, &opts).unwrap();
    assert_eq!(b64u(&sealed), s.sealed);
    assert_eq!(to_hex(&sealed[1..33]), s.ephemeral_pk_hex);
    let sk = z32(&s.recipient_enc_sk_hex);
    assert_eq!(to_hex(seal_derived_key(&sk, &sealed).unwrap().as_ref()), s.derived_key_hex);
    let blob = from_b64u(&s.sealed).unwrap();
    assert_eq!(to_hex(&unseal(&sk, &blob, &s.aad).unwrap()), s.plaintext_hex);
    let vault_id = s.aad.strip_prefix("ov-vault-key|").expect("vault-key AAD");
    assert_eq!(aad::vault_key(vault_id), s.aad);
    assert_eq!(to_hex(unseal_vault_key(&sk, vault_id, &blob).unwrap().as_ref()), s.plaintext_hex);
}

#[test]
fn seal_0() {
    seal_case(0);
}

#[test]
fn seal_1() {
    seal_case(1);
}

#[test]
fn seal_count() {
    assert_eq!(v().seal.len(), 2);
}

#[test]
fn seal_rejects_all_zero_shared_secret() {
    let e = seal_with(&[0u8; 32], &[0u8; 32], "x", &SealOptions::default()).unwrap_err();
    assert!(e.is(OvErrorCode::LowOrderPoint));
}

// ---- seal_negative

fn seal_negative_case(name: &str, code: OvErrorCode) {
    let n = v().seal_negative.iter().find(|n| n.case == name).unwrap_or_else(|| panic!("missing case {name:?}"));
    let expected =
        if n.expect == "unsupported version" { OvErrorCode::UnsupportedVersion } else { OvErrorCode::DecryptionFailed };
    assert_eq!(expected, code, "{name}: {}", n.expect);
    let e = unseal(&z32(&n.recipient_enc_sk_hex), &from_b64u(&n.sealed).unwrap(), &n.aad).unwrap_err();
    assert!(e.is(code), "{name}: got {e:?}");
}

#[test]
fn seal_negative_wrong_aad_other_vault() {
    seal_negative_case("wrong aad (other vault)", OvErrorCode::DecryptionFailed);
}

#[test]
fn seal_negative_wrong_recipient() {
    seal_negative_case("wrong recipient", OvErrorCode::DecryptionFailed);
}

#[test]
fn seal_negative_unknown_version_byte() {
    seal_negative_case("unknown version byte", OvErrorCode::UnsupportedVersion);
}

#[test]
fn seal_negative_count() {
    assert_eq!(v().seal_negative.len(), 3);
}

// ---- vault_name (SPEC §4)

#[test]
fn vault_name_derives_key_and_encrypts_byte_for_byte() {
    let n = &v().vault_name;
    let vk = z32(&n.vault_key_hex);
    assert_eq!(to_hex(vault_name_key(&vk).as_ref()), n.name_key_hex);
    let enc = encrypt_vault_name_with_nonce(&vk, &n.vault_id, &n.name, &hex_array::<24>(&n.nonce_hex));
    assert_eq!(enc, n.encrypted_name);
    assert_eq!(decrypt_vault_name(&vk, &n.vault_id, &n.encrypted_name).unwrap(), n.name);
    assert_eq!(aad::vault_name(&n.vault_id), n.aad);
}

#[test]
fn vault_name_is_bound_to_the_vault_id() {
    let n = &v().vault_name;
    let other = "00000000-0000-4000-8000-000000000000";
    let e = decrypt_vault_name(&z32(&n.vault_key_hex), other, &n.encrypted_name).unwrap_err();
    assert!(e.is(OvErrorCode::DecryptionFailed));
}

// ---- service_account (SPEC §9)

#[test]
fn service_account_builds_and_parses_the_token() {
    let sa = &v().service_account;
    let payload: serde_json::Value = serde_json::from_str(&sa.payload_json).unwrap();
    let secret: [u8; 32] = from_b64u(payload["secret"].as_str().unwrap()).unwrap().try_into().unwrap();
    let url = payload["url"].as_str().unwrap();
    let token = build_sa_token(url, &sa.sa_id, &secret, &hex_array::<32>(&sa.kek_hex));
    assert_eq!(token.as_str(), sa.token);
    assert_eq!(from_b64u(&sa.token["ov_sa_".len()..]).unwrap(), sa.payload_json.as_bytes());
    let p = parse_sa_token(&sa.token).unwrap();
    assert_eq!(p.sa_id, sa.sa_id);
    assert_eq!(p.url, url);
    assert_eq!(to_hex(p.kek.as_ref()), sa.kek_hex);
    assert_eq!(sa_secret_hash(&p.secret), sa.secret_hash_hex);
    assert_eq!(sa_secret_prefix(&p.secret), sa.secret_prefix);
}

#[test]
fn service_account_rejects_malformed_tokens() {
    let sa = &v().service_account;
    assert!(parse_sa_token("ov_rt_abc").unwrap_err().is(OvErrorCode::InvalidToken));
    let mut payload: serde_json::Value = serde_json::from_str(&sa.payload_json).unwrap();
    payload["v"] = 2.into();
    let e = parse_sa_token(&format!("ov_sa_{}", b64u(payload.to_string().as_bytes()))).unwrap_err();
    assert!(e.is(OvErrorCode::InvalidToken) && e.message.contains("version"));
}

#[test]
fn service_account_wraps_master_and_keyset_and_unwraps_the_chain() {
    let sa = &v().service_account;
    let master = z32(&sa.master_key_hex);
    assert_eq!(sa.wrapped_master_aad, aad::sa_master(&sa.sa_id));
    let nonce = hex_array::<24>(&sa.wrapped_master_nonce_hex);
    assert_eq!(wrap_sa_master_with_nonce(&z32(&sa.kek_hex), &sa.sa_id, &master, &nonce), sa.wrapped_master);
    let ks = keyset_from_secrets(&z32(&sa.keyset_enc_sk_hex), &z32(&sa.keyset_sign_seed_hex));
    assert_eq!(ks.public.to_json(), pk_json(&sa.public));
    assert_eq!(ks.public.fingerprint(), sa.public.fingerprint);
    let ks_nonce = hex_array::<24>(&sa.wrapped_keyset_nonce_hex);
    assert_eq!(wrap_keyset_with_nonce(&master, &ks, &ks_nonce).wrapped, sa.wrapped_keyset);
    // token → kek → master → keyset
    let p = parse_sa_token(&sa.token).unwrap();
    let m = unwrap_sa_master(&p.kek, &p.sa_id, &sa.wrapped_master).unwrap();
    assert_eq!(to_hex(m.as_ref()), sa.master_key_hex);
    let back = unwrap_keyset(&m, &wrapped(&sa.public, &sa.wrapped_keyset)).unwrap();
    assert_eq!(to_hex(back.enc_sk.as_ref()), sa.keyset_enc_sk_hex);
}

#[test]
fn service_account_master_sealed_to_admin() {
    let sa = &v().service_account;
    let m = &sa.master_sealed_to_admin;
    assert_eq!(m.admin, v().keyset.principal);
    assert_eq!(m.aad, aad::sa_master(&sa.sa_id));
    let master = z32(&sa.master_key_hex);
    let admin_pk = from_b64u(&v().keyset.public.enc_pk).unwrap();
    let sealed =
        seal_sa_master_with(&admin_pk, &sa.sa_id, &master, &seal_opts(&m.ephemeral_sk_hex, &m.nonce_hex)).unwrap();
    assert_eq!(b64u(&sealed), m.sealed);
    let back = unseal_sa_master(&z32(&v().keyset.enc_sk_hex), &sa.sa_id, &from_b64u(&m.sealed).unwrap()).unwrap();
    assert_eq!(*back, *master);
}

// ---- refresh_token (SPEC §9)

#[test]
fn refresh_token_stored_hash() {
    assert_eq!(refresh_token_hash(&v().refresh_token.token), v().refresh_token.stored_hash_hex);
}

// ---- jwt (SPEC §9)

fn jwks() -> Jwks {
    serde_json::from_value(serde_json::to_value(&v().jwt.jwks).unwrap()).unwrap()
}

fn jwt_opts(now: i64) -> VerifyOptions {
    VerifyOptions {
        issuer: v().jwt.valid[0].claims.iss.clone(),
        audience: "ov-sync".into(),
        now,
        skew: DEFAULT_SKEW_SECS,
    }
}

fn jwt_valid_case(i: usize) {
    let c = &v().jwt.valid[i];
    let expected = serde_json::to_value(&c.claims).unwrap();
    assert_eq!(serde_json::to_value(decode_jwt(&c.token).unwrap().claims).unwrap(), expected);
    let claims = verify_jwt(&c.token, &jwks(), &jwt_opts(v().jwt.now)).unwrap();
    assert_eq!(serde_json::to_value(claims).unwrap(), expected);
}

#[test]
fn jwt_valid_0_user() {
    assert!(v().jwt.valid[0].claims.dev.is_some());
    jwt_valid_case(0);
}

#[test]
fn jwt_valid_1() {
    jwt_valid_case(1);
}

#[test]
fn jwt_valid_count() {
    assert_eq!(v().jwt.valid.len(), 2);
}

fn jwt_invalid_case(name: &str) {
    let c = v().jwt.invalid.iter().find(|c| c.case == name).unwrap_or_else(|| panic!("missing case {name:?}"));
    let mut refetched = 0;
    let r = verify_jwt_refetching(&c.token, &jwks(), &jwt_opts(v().jwt.now), || {
        refetched += 1;
        Ok(Some(jwks()))
    });
    let e = r.unwrap_err();
    assert!(e.is(OvErrorCode::Unauthorized), "{name}: {e:?}");
    assert_eq!(e.status, Some(c.expect), "{name}");
    assert_eq!(refetched, usize::from(name.starts_with("unknown kid")), "{name}");
}

#[test]
fn jwt_invalid_expired() {
    jwt_invalid_case("expired (exp + 60s skew < now)");
}

#[test]
fn jwt_invalid_not_yet_valid() {
    jwt_invalid_case("not yet valid");
}

#[test]
fn jwt_invalid_wrong_audience() {
    jwt_invalid_case("wrong audience");
}

#[test]
fn jwt_invalid_wrong_issuer() {
    jwt_invalid_case("wrong issuer");
}

#[test]
fn jwt_invalid_bad_signature() {
    jwt_invalid_case("bad signature");
}

#[test]
fn jwt_invalid_unknown_kid() {
    jwt_invalid_case("unknown kid (verifier refetches JWKS once, then rejects)");
}

#[test]
fn jwt_invalid_alg_none() {
    jwt_invalid_case("alg none");
}

#[test]
fn jwt_invalid_count() {
    assert_eq!(v().jwt.invalid.len(), 7);
}

#[test]
fn jwt_invalid_expired_is_just_outside_the_skew() {
    let expired = &v().jwt.invalid[0];
    assert!(verify_jwt(&expired.token, &jwks(), &jwt_opts(v().jwt.now - 2)).is_ok());
}

// ---- restore_proof (SPEC §18)

/// The archived keyset (the `keyset` vector) and the current one.
fn restore_keysets() -> (Keyset, Keyset) {
    let k = &v().keyset;
    let r = &v().restore_proof;
    let old = unwrap_keyset(&z32(&k.auk_hex), &wrapped(&k.public, &k.wrapped)).unwrap();
    let current = keyset_from_secrets(&z32(&r.new_enc_sk_hex), &z32(&r.new_sign_seed_hex));
    (old, current)
}

#[test]
fn restore_proof_archived_keyset_is_the_keyset_vector() {
    let r = &v().restore_proof;
    let (old, current) = restore_keysets();
    assert_eq!(b64u(&old.public.sign_pk), r.old_sign_pk);
    assert!(r.old_keyset.starts_with("keyset"), "old_keyset names the keyset vector: {}", r.old_keyset);
    assert_eq!(current.public.to_json(), pk_json(&r.new_public));
}

#[test]
fn restore_proof_message_and_proof_byte_for_byte() {
    let r = &v().restore_proof;
    let (old, current) = restore_keysets();
    let (epk, spk) = (&current.public.enc_pk, &current.public.sign_pk);
    assert_eq!(to_hex(&restore_proof_message(&r.user_id, epk, spk)), r.message_hex);
    assert_eq!(b64u(&restore_proof(&old.sign_seed, &r.user_id, epk, spk)), r.proof);
    let old_pk = from_b64u(&r.old_sign_pk).unwrap();
    let proof = from_b64u(&r.proof).unwrap();
    assert!(verify_restore_proof(&proof, &r.user_id, epk, spk, &old_pk));
    assert!(check_restore_proof(&proof, &r.user_id, epk, spk, &old_pk).is_ok());
}

fn restore_proof_invalid_case(name: &str) {
    let r = &v().restore_proof;
    let n = r.invalid.iter().find(|n| n.case == name).unwrap_or_else(|| panic!("missing case {name:?}"));
    let (_, current) = restore_keysets();
    let (epk, spk) = (&current.public.enc_pk, &current.public.sign_pk);
    let old_pk = from_b64u(&r.old_sign_pk).unwrap();
    let proof = from_b64u(&n.proof).unwrap();
    assert!(!verify_restore_proof(&proof, &r.user_id, epk, spk, &old_pk));
    let e = check_restore_proof(&proof, &r.user_id, epk, spk, &old_pk).unwrap_err();
    assert_eq!(e.wire_code(), n.expect);
}

#[test]
fn restore_proof_invalid_signed_by_the_new_keyset() {
    restore_proof_invalid_case("signed by the new keyset instead of the archived one");
}

#[test]
fn restore_proof_invalid_another_users_id() {
    restore_proof_invalid_case("another user's id in the message");
}

#[test]
fn restore_proof_invalid_count() {
    assert_eq!(v().restore_proof.invalid.len(), 2);
}

#[test]
fn restore_proof_reseal_byte_for_byte() {
    let r = &v().restore_proof;
    let (old, current) = restore_keysets();
    assert_eq!(r.reseal.archived_sealed_key, v().seal[0].sealed);
    let vault_id = r.reseal.aad.strip_prefix("ov-vault-key|").unwrap();
    let archived = from_b64u(&r.reseal.archived_sealed_key).unwrap();
    let opts = seal_opts(&r.reseal.ephemeral_sk_hex, &r.reseal.nonce_hex);
    let sealed = reseal_vault_key_with(&old.enc_sk, &current.public.enc_pk, vault_id, &archived, &opts).unwrap();
    assert_eq!(b64u(&sealed), r.reseal.sealed);
    let key = unseal_vault_key(&current.enc_sk, vault_id, &sealed).unwrap();
    assert_eq!(to_hex(key.as_ref()), v().seal[0].plaintext_hex);
}

#[test]
fn restore_proof_reseal_under_another_vault_fails() {
    let r = &v().restore_proof;
    let (old, current) = restore_keysets();
    let archived = from_b64u(&r.reseal.archived_sealed_key).unwrap();
    let other = "00000000-0000-0000-0000-000000000000";
    let e = reseal_vault_key(&old.enc_sk, &current.public.enc_pk, other, &archived).unwrap_err();
    assert!(e.is(OvErrorCode::DecryptionFailed));
}
