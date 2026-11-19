//! The ov v1 crypto below the facade (ov-crypto, SPEC §1-§9) for C++: what the desktop's
//! `AccountCrypto` calls directly. The names and shapes follow the desktop's former `ovd` bridge
//! (README.md, "Desktop swap").
//!
//! Byte inputs are borrowed (`rust::Slice`); the caller keeps and wipes them. Secret outputs move
//! out of their `Zeroizing` wrapper into the returned `rust::Vec`, which the caller wipes
//! (`ov::wipe`). AADs and other text inputs given as bytes must be UTF-8. Every function is
//! CPU-only and synchronous.

use ov_crypto::{auk, curves, envelope, keyset, primitives as prim, secret_key, tokens, vault_name};
use ov_error::{OvError, OvErrorCode};

use crate::edge::{edge, FfiError};
use crate::ffi;
use crate::primitives::{array, take};

type R<T> = Result<T, FfiError>;

pub(crate) fn invalid(what: impl Into<String>) -> OvError {
    OvError::new(OvErrorCode::InvalidRequest, what.into())
}

/// `None` for an empty slice (meaning "fresh random"), else exactly `N` bytes.
fn optional_array<const N: usize>(what: &str, bytes: &[u8]) -> Result<Option<zeroize::Zeroizing<[u8; N]>>, OvError> {
    if bytes.is_empty() {
        Ok(None)
    } else {
        array::<N>(what, bytes).map(Some)
    }
}

pub(crate) fn utf8<'a>(what: &str, bytes: &'a [u8]) -> Result<&'a str, OvError> {
    std::str::from_utf8(bytes).map_err(|_| invalid(format!("{what} isn't UTF-8")))
}

/// `ov::nfkc_utf8`: UTF-8 of the NFKC-normalised text (SPEC §3; the OPAQUE and AUK password input).
pub(crate) fn nfkc_utf8(text: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(take(auk::password_bytes(utf8("the text", text)?))))
}

/// `ov::generate_secret_key`: 16 random bytes (SPEC §2). Secret: wipe it.
pub(crate) fn generate_secret_key() -> R<Vec<u8>> {
    edge(|| Ok(secret_key::generate_secret_key()?.to_vec()))
}

/// `ov::format_secret_key`: the `K1-…` display form of a raw Secret Key.
pub(crate) fn format_secret_key(raw: &[u8]) -> R<String> {
    edge(|| {
        let raw = array::<{ secret_key::SECRET_KEY_BYTES }>("a Secret Key", raw)?;
        Ok(secret_key::format_secret_key(&raw).to_string())
    })
}

/// `ov::parse_secret_key`: the raw bytes of a displayed Secret Key; `invalid_secret_key` if malformed.
pub(crate) fn parse_secret_key(text: &str) -> R<Vec<u8>> {
    edge(|| Ok(secret_key::parse_secret_key(text)?.to_vec()))
}

/// `ov::wrap`: the version-1 envelope of SPEC §4 (`0x01 ‖ nonce ‖ XChaCha20-Poly1305`). An empty
/// `nonce` takes a fresh random one; a fixed 24-byte nonce is for the test vectors only.
pub(crate) fn wrap(key: &[u8], plaintext: &[u8], aad: &[u8], nonce: &[u8]) -> R<Vec<u8>> {
    edge(|| {
        let key = array::<{ prim::KEY_BYTES }>("the key", key)?;
        let aad = utf8("the AAD", aad)?;
        match optional_array::<{ prim::NONCE_BYTES }>("the nonce", nonce)? {
            Some(nonce) => Ok(envelope::wrap_with_nonce(&key, plaintext, aad, &nonce)),
            None => envelope::wrap(&key, plaintext, aad),
        }
    })
}

/// `ov::unwrap`: opens a [`wrap`] envelope; `decryption_failed` on a wrong key or AAD.
pub(crate) fn unwrap(key: &[u8], wrapped: &[u8], aad: &[u8]) -> R<Vec<u8>> {
    edge(|| {
        let key = array::<{ prim::KEY_BYTES }>("the key", key)?;
        Ok(take(envelope::unwrap(&key, wrapped, utf8("the AAD", aad)?)?))
    })
}

/// `ov::seal`: seals to an X25519 public key (SPEC §6, ov-crypto `seal_with`). Empty
/// `ephemeral_sk` / `nonce` take fresh random ones; fixed values are for the test vectors only.
pub(crate) fn seal(recipient_pk: &[u8], plaintext: &[u8], aad: &[u8], ephemeral_sk: &[u8], nonce: &[u8]) -> R<Vec<u8>> {
    edge(|| {
        let opts = envelope::SealOptions {
            ephemeral_secret_key: optional_array::<32>("the ephemeral key", ephemeral_sk)?,
            nonce: optional_array::<{ prim::NONCE_BYTES }>("the nonce", nonce)?.map(|n| *n),
        };
        envelope::seal_with(recipient_pk, plaintext, utf8("the AAD", aad)?, &opts)
    })
}

/// `ov::unseal`: opens a [`seal`]ed box with the recipient's X25519 secret key.
pub(crate) fn unseal(recipient_sk: &[u8], sealed: &[u8], aad: &[u8]) -> R<Vec<u8>> {
    edge(|| {
        let sk = array::<32>("the secret key", recipient_sk)?;
        Ok(take(envelope::unseal(&sk, sealed, utf8("the AAD", aad)?)?))
    })
}

/// `ov::seal_derived_key`: the AEAD key of a sealed box as the recipient derives it (test vectors).
pub(crate) fn seal_derived_key(recipient_sk: &[u8], sealed: &[u8]) -> R<Vec<u8>> {
    edge(|| {
        let sk = array::<32>("the secret key", recipient_sk)?;
        Ok(envelope::seal_derived_key(&sk, sealed)?.to_vec())
    })
}

/// `ov::x25519_public_key`.
pub(crate) fn x25519_public_key(secret_key: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(curves::x25519_public_key(&*array::<32>("the secret key", secret_key)?).to_vec()))
}

/// `ov::x25519_shared`: the shared secret; `low_order_point` for a low-order public key.
pub(crate) fn x25519_shared(secret_key: &[u8], public_key: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(curves::x25519_shared(&*array::<32>("the secret key", secret_key)?, public_key)?.to_vec()))
}

/// `ov::ed25519_public_key`: the public key of a 32-byte seed.
pub(crate) fn ed25519_public_key(seed: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(curves::ed25519_public_key(&*array::<32>("the seed", seed)?).to_vec()))
}

/// `ov::ed25519_sign`: a 64-byte signature.
pub(crate) fn ed25519_sign(seed: &[u8], message: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(curves::ed25519_sign(message, &*array::<32>("the seed", seed)?).to_vec()))
}

/// `ov::ed25519_verify`: false for a bad signature or malformed input (never throws).
pub(crate) fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    edge(|| Ok(curves::ed25519_verify(signature, message, public_key))).unwrap_or(false)
}

fn public_keys(p: &keyset::PublicKeys) -> ffi::PublicKeys {
    ffi::PublicKeys {
        enc_pk: p.enc_pk.to_vec(),
        sign_pk: p.sign_pk.to_vec(),
        sig: p.sig.to_vec(),
        fingerprint: keyset::fingerprint(&p.enc_pk, &p.sign_pk),
    }
}

/// `ov::keyset_from_secrets`: the public keys, self-signature and fingerprint the two private
/// halves of a keyset make (SPEC §5).
pub(crate) fn keyset_from_secrets(enc_sk: &[u8], sign_seed: &[u8]) -> R<ffi::PublicKeys> {
    edge(|| {
        let ks = keyset::keyset_from_secrets(&*array::<32>("enc_sk", enc_sk)?, &*array::<32>("sign_seed", sign_seed)?);
        Ok(public_keys(&ks.public))
    })
}

/// `ov::verify_public_keys`: whether the self-signature verifies (false for malformed input).
pub(crate) fn verify_public_keys(enc_pk: &[u8], sign_pk: &[u8], sig: &[u8]) -> bool {
    edge(|| {
        let pk = keyset::PublicKeys {
            enc_pk: *array::<32>("enc_pk", enc_pk)?,
            sign_pk: *array::<32>("sign_pk", sign_pk)?,
            sig: sig.try_into().map_err(|_| invalid("sig must be 64 bytes"))?,
        };
        Ok(keyset::verify_public_keys(&pk))
    })
    .unwrap_or(false)
}

/// `ov::fingerprint`: the safety-number form of a keyset's public keys (SPEC §5).
pub(crate) fn fingerprint(enc_pk: &[u8], sign_pk: &[u8]) -> String {
    keyset::fingerprint(enc_pk, sign_pk)
}

/// `ov::vault_name_key`: the key vault names are encrypted with (SPEC §7). Secret: wipe it.
pub(crate) fn vault_name_key(vault_key: &[u8]) -> R<Vec<u8>> {
    edge(|| Ok(vault_name::vault_name_key(&*array::<32>("the vault key", vault_key)?).to_vec()))
}

/// `ov::refresh_token_hash`: the hex SHA-256 a server stores for a refresh token (SPEC §9).
pub(crate) fn refresh_token_hash(token: &str) -> String {
    tokens::refresh_token_hash(token)
}

/// `ov::build_service_account_token`: the `ov_sa_…` token (SPEC §15). Secret: wipe it.
pub(crate) fn build_service_account_token(url: &str, sa_id: &str, secret: &[u8], kek: &[u8]) -> R<String> {
    edge(|| {
        let secret = array::<32>("the secret", secret)?;
        let kek = array::<32>("the KEK", kek)?;
        Ok(tokens::build_sa_token(url, sa_id, &secret, &kek).to_string())
    })
}

/// `ov::parse_service_account_token`; `invalid_token` if malformed. `secret` and `kek` are secret.
pub(crate) fn parse_service_account_token(text: &str) -> R<ffi::ServiceAccountToken> {
    edge(|| {
        let t = tokens::parse_sa_token(text)?;
        Ok(ffi::ServiceAccountToken {
            url: t.url.clone(),
            sa_id: t.sa_id.clone(),
            secret: t.secret.to_vec(),
            kek: t.kek.to_vec(),
        })
    })
}

/// `ov::service_account_secret_hash`: the hex SHA-256 the server stores for an SA secret.
pub(crate) fn service_account_secret_hash(secret: &[u8]) -> R<String> {
    edge(|| Ok(tokens::sa_secret_hash(&*array::<32>("the secret", secret)?)))
}

/// `ov::service_account_secret_prefix`: the short public prefix shown for an SA secret.
pub(crate) fn service_account_secret_prefix(secret: &[u8]) -> R<String> {
    edge(|| Ok(tokens::sa_secret_prefix(&*array::<32>("the secret", secret)?)))
}

#[cfg(test)]
mod tests {
    //! Each function against `vectors/test-vectors.json` (the C++ smoke repeats these through the
    //! header).

    use super::*;
    use ov_testkit::{b64u, hex_bytes, test_vectors};

    fn code<T>(r: R<T>) -> OvErrorCode {
        let Err(e) = r else { panic!("expected an error") };
        let c = e.0.code;
        let _ = crate::edge::take_last_error();
        c
    }

    #[test]
    fn secret_key_and_nfkc() {
        let tv = test_vectors();
        for k in &tv.secret_key {
            assert_eq!(format_secret_key(&hex_bytes(&k.raw_hex)).unwrap(), k.display);
            assert_eq!(parse_secret_key(&k.display).unwrap(), hex_bytes(&k.raw_hex));
        }
        assert_eq!(code(parse_secret_key("K1-nope")), OvErrorCode::InvalidSecretKey);
        assert_eq!(code(format_secret_key(&[1, 2])), OvErrorCode::InvalidRequest);
        let fresh = generate_secret_key().unwrap();
        assert_eq!(parse_secret_key(&format_secret_key(&fresh).unwrap()).unwrap(), fresh);
        for a in &tv.auk {
            assert_eq!(nfkc_utf8(a.password.as_bytes()).unwrap(), hex_bytes(&a.password_nfkc_hex));
        }
        assert_eq!(code(nfkc_utf8(&[0xff])), OvErrorCode::InvalidRequest);
    }

    #[test]
    fn keyset_wrap_and_curves() {
        let k = test_vectors().keyset;
        let pk = keyset_from_secrets(&hex_bytes(&k.enc_sk_hex), &hex_bytes(&k.sign_seed_hex)).unwrap();
        assert_eq!(pk.enc_pk, b64u(&k.public.enc_pk));
        assert_eq!(pk.sign_pk, b64u(&k.public.sign_pk));
        assert_eq!(pk.sig, b64u(&k.public.sig));
        assert_eq!(pk.fingerprint, k.public.fingerprint);
        assert_eq!(fingerprint(&pk.enc_pk, &pk.sign_pk), k.public.fingerprint);
        assert!(verify_public_keys(&pk.enc_pk, &pk.sign_pk, &pk.sig));
        assert!(!verify_public_keys(&pk.sign_pk, &pk.enc_pk, &pk.sig));
        assert!(!verify_public_keys(&pk.enc_pk, &pk.sign_pk, &pk.sig[..10]));

        // The wrapped keyset: AUK-wrapped enc_sk ‖ sign_seed with the vector's nonce
        let auk = hex_bytes(&k.auk_hex);
        let mut plain = hex_bytes(&k.enc_sk_hex);
        plain.extend(hex_bytes(&k.sign_seed_hex));
        let wrapped = wrap(&auk, &plain, k.aad.as_bytes(), &hex_bytes(&k.nonce_hex)).unwrap();
        assert_eq!(wrapped, b64u(&k.wrapped));
        assert_eq!(unwrap(&auk, &wrapped, k.aad.as_bytes()).unwrap(), plain);
        assert_eq!(code(unwrap(&auk, &wrapped, b"ov-other")), OvErrorCode::DecryptionFailed);
        let random = wrap(&auk, b"x", b"a", b"").unwrap();
        assert_eq!(unwrap(&auk, &random, b"a").unwrap(), b"x");
        assert_eq!(code(wrap(&auk, b"x", b"a", &[0; 5])), OvErrorCode::InvalidRequest);

        let enc_sk = hex_bytes(&k.enc_sk_hex);
        assert_eq!(x25519_public_key(&enc_sk).unwrap(), pk.enc_pk);
        let seed = hex_bytes(&k.sign_seed_hex);
        assert_eq!(ed25519_public_key(&seed).unwrap(), pk.sign_pk);
        let sig = ed25519_sign(&seed, b"msg").unwrap();
        assert!(ed25519_verify(&pk.sign_pk, b"msg", &sig));
        assert!(!ed25519_verify(&pk.sign_pk, b"msh", &sig));
        assert!(!ed25519_verify(b"short", b"msg", &sig));
    }

    #[test]
    fn seal_vectors() {
        let tv = test_vectors();
        for s in &tv.seal {
            let sealed = seal(
                &b64u(&s.recipient_enc_pk),
                &hex_bytes(&s.plaintext_hex),
                s.aad.as_bytes(),
                &hex_bytes(&s.ephemeral_sk_hex),
                &hex_bytes(&s.nonce_hex),
            )
            .unwrap();
            assert_eq!(sealed, b64u(&s.sealed));
            let sk = hex_bytes(&s.recipient_enc_sk_hex);
            assert_eq!(unseal(&sk, &sealed, s.aad.as_bytes()).unwrap(), hex_bytes(&s.plaintext_hex));
            assert_eq!(seal_derived_key(&sk, &sealed).unwrap(), hex_bytes(&s.derived_key_hex));
            let shared = x25519_shared(&sk, &hex_bytes(&s.ephemeral_pk_hex)).unwrap();
            assert_eq!(shared, x25519_shared(&hex_bytes(&s.ephemeral_sk_hex), &b64u(&s.recipient_enc_pk)).unwrap());
        }
        for n in &tv.seal_negative {
            let r = unseal(&hex_bytes(&n.recipient_enc_sk_hex), &b64u(&n.sealed), n.aad.as_bytes());
            assert!(r.is_err(), "{}", n.case);
            let _ = crate::edge::take_last_error();
        }
        assert_eq!(code(x25519_shared(&[1; 32], &[0; 32])), OvErrorCode::LowOrderPoint);
    }

    #[test]
    fn vault_name_and_tokens() {
        let tv = test_vectors();
        let v = &tv.vault_name;
        assert_eq!(vault_name_key(&hex_bytes(&v.vault_key_hex)).unwrap(), hex_bytes(&v.name_key_hex));

        let sa = &tv.service_account;
        let t = parse_service_account_token(&sa.token).unwrap();
        assert_eq!(t.sa_id, sa.sa_id);
        assert_eq!(t.kek, hex_bytes(&sa.kek_hex));
        assert_eq!(build_service_account_token(&t.url, &t.sa_id, &t.secret, &t.kek).unwrap(), sa.token);
        assert_eq!(service_account_secret_hash(&t.secret).unwrap(), sa.secret_hash_hex);
        assert_eq!(service_account_secret_prefix(&t.secret).unwrap(), sa.secret_prefix);
        assert_eq!(code(parse_service_account_token("ov_sa_junk")), OvErrorCode::InvalidToken);

        assert_eq!(refresh_token_hash(&tv.refresh_token.token), tv.refresh_token.stored_hash_hex);
    }
}
