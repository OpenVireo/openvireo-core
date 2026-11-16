//! The SPEC §22 `share` cases of `vectors/test-vectors.json`.

use ov_error::OvErrorCode;
use ov_share::{
    decrypt_share_payload, decrypt_share_ref, encrypt_share_payload_with_nonce, encrypt_share_ref_with_nonce,
    open_share, pad_share, parse_share_link, share_aad, share_auth, share_auth_hash, share_content_key, share_link,
    share_passcode_key, share_ref_aad, share_ref_key, KdfParams, SharePayload, ShareRef,
};
use ov_testkit::{b64u, hex_array, hex_bytes, test_vectors};

/// The vector's payload JSON as a typed value (the TS test does `JSON.parse(c.payload)`).
fn payload_from_json(json: &str) -> SharePayload {
    let v: serde_json::Value = serde_json::from_str(json).unwrap();
    let fields = v["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| ov_share::ShareField {
            k: f["k"].as_str().unwrap().into(),
            label: f["label"].as_str().unwrap().into(),
            value: f["value"].as_str().unwrap().into(),
            protected: f["protected"].as_bool().unwrap_or(false),
        })
        .collect();
    SharePayload {
        v: 1,
        kind: v["kind"].as_str().unwrap().into(),
        title: v["title"].as_str().map(Into::into),
        shared_by: v["shared_by"].as_str().map(Into::into),
        fields,
    }
}

#[test]
fn share_cases() {
    let share = test_vectors().share;
    assert_eq!(share.cases.len(), 2);
    for c in &share.cases {
        let key: [u8; 32] = b64u(&c.key).try_into().unwrap();
        let passcode_key = c.passcode.as_ref().map(|pc| {
            let k = c.kdf.as_ref().unwrap();
            let kdf = KdfParams { alg: k.alg.clone(), salt: k.salt.clone(), m: k.m, t: k.t, p: k.p };
            let p = share_passcode_key(pc, &kdf, true).unwrap();
            assert_eq!(hex::encode(&p[..]), *c.passcode_key_hex.as_ref().unwrap(), "{} passcode key", c.id);
            let auth = share_auth(&p);
            assert_eq!(auth[..], b64u(c.auth.as_ref().unwrap())[..], "{} auth", c.id);
            assert_eq!(hex::encode(share_auth_hash(&auth[..])), *c.auth_sha256_hex.as_ref().unwrap());
            p
        });
        let pk = passcode_key.as_deref();
        assert_eq!(hex::encode(&share_content_key(&key, pk)[..]), c.content_key_hex, "{} content key", c.id);
        assert_eq!(hex::encode(&pad_share(c.payload.as_bytes())[..]), c.padded_hex, "{} padding", c.id);
        assert_eq!(share_aad(&c.id), c.aad);

        let payload = payload_from_json(&c.payload);
        assert_eq!(serde_json::to_string(&payload).unwrap(), c.payload, "{} JSON bytes", c.id);
        let nonce: [u8; 24] = hex_array(&c.nonce_hex);
        let ct = encrypt_share_payload_with_nonce(&key, &c.id, &payload, pk, &nonce).unwrap();
        assert_eq!(ct, b64u(&c.ct), "{} ct", c.id);
        assert_eq!(decrypt_share_payload(&key, &c.id, &ct, pk).unwrap(), payload);

        // the AAD binds it to its id
        let other_id = format!("{}{}", if c.id.starts_with('A') { "B" } else { "A" }, &c.id[1..]);
        assert_eq!(decrypt_share_payload(&key, &other_id, &ct, pk).unwrap_err().code, OvErrorCode::DecryptionFailed);
        // a passcode share needs the passcode key
        if pk.is_some() {
            assert_eq!(decrypt_share_payload(&key, &c.id, &ct, None).unwrap_err().code, OvErrorCode::DecryptionFailed);
        }

        // the link round-trips
        let parts = parse_share_link(&c.link).unwrap();
        assert_eq!((parts.base.as_str(), parts.id.as_str()), ("https://share.openvireo.example", c.id.as_str()));
        assert_eq!(*parts.key, key);
        assert_eq!(share_link("https://share.openvireo.example/", &c.id, &key).as_str(), c.link);

        // and opens (no passcode case only: the vector KDF is below the SPEC minimum on purpose)
        if c.passcode.is_none() {
            assert_eq!(open_share(&c.link, None, None, &c.ct).unwrap(), payload);
        }
    }
}

#[test]
fn owner_reference() {
    let r = test_vectors().share.ref_;
    let sk = hex_bytes(&r.owner_enc_sk_hex);
    assert_eq!(hex::encode(&share_ref_key(&sk)[..]), r.ref_key_hex);
    assert_eq!(share_ref_aad(&r.share_id), r.aad);
    let reference: ShareRef = serde_json::from_str(&r.plaintext).unwrap();
    assert_eq!(serde_json::to_string(&reference).unwrap(), r.plaintext);
    let nonce: [u8; 24] = hex_array(&r.nonce_hex);
    assert_eq!(encrypt_share_ref_with_nonce(&sk, &r.share_id, &reference, &nonce).unwrap(), r.ref_);
    assert_eq!(decrypt_share_ref(&sk, &r.share_id, &r.ref_).unwrap(), reference);
    assert_eq!(decrypt_share_ref(&sk, "other", &r.ref_).unwrap_err().code, OvErrorCode::DecryptionFailed);
    assert_eq!(decrypt_share_ref(&sk, &r.share_id, "!!").unwrap_err().code, OvErrorCode::DecryptionFailed);
}
