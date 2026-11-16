//! The legacy C ABI gives the TS SDK's bytes: the opaque-ke transcript replayed through `ov_call`, with
//! the exact field lists `packages/sdk/src/opaque/index.ts` sends.
#![cfg(feature = "legacy-c-abi")]

use ov_opaque::legacy::{ov_alloc, ov_call, ov_free, ov_out_clear, ov_out_len, ov_out_ptr};
use ov_testkit::{hex_bytes, opaque_transcripts};

fn pack(fields: &[&[u8]]) -> Vec<u8> {
    let mut v = Vec::new();
    for f in fields {
        v.extend_from_slice(&(f.len() as u32).to_le_bytes());
        v.extend_from_slice(f);
    }
    v
}

fn unpack(mut b: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = u32::from_le_bytes(b[..4].try_into().unwrap()) as usize;
        out.push(b[4..4 + n].to_vec());
        b = &b[4 + n..];
    }
    out
}

/// Like the SDK's `call`: Ok(fields), Err(status).
fn call(op: u32, fields: &[&[u8]]) -> Result<Vec<Vec<u8>>, i32> {
    let input = pack(fields);
    let ptr = ov_alloc(input.len());
    // SAFETY: `ptr` has room for `input.len()` bytes; it and the output buffer are used as the ABI says.
    unsafe {
        std::ptr::copy_nonoverlapping(input.as_ptr(), ptr, input.len());
        let status = ov_call(op, ptr, input.len());
        let out = (status == 0).then(|| unpack(std::slice::from_raw_parts(ov_out_ptr(), ov_out_len())));
        ov_free(ptr, input.len());
        ov_out_clear();
        out.ok_or(status)
    }
}

#[test]
fn legacy_abi_replays_the_sdk_transcript() {
    let t = opaque_transcripts().opaque_ke;
    let h = |s: &str| hex_bytes(s);
    let (pw, id_u, id_s, ctx) = (h(&t.password_nfkc_hex), t.id_u.as_bytes(), t.id_s.as_bytes(), t.context.as_bytes());
    let reg = &t.registration;

    let r = call(1, &[&h(&reg.client_start_seed_hex), &pw]).unwrap();
    assert_eq!(hex::encode(&r[0]), reg.request_hex);
    let s = call(10, &[&h(&reg.server_seed_hex), &r[0]]).unwrap();
    assert_eq!((hex::encode(&s[0]), hex::encode(&s[1])), (reg.server_setup_hex.clone(), reg.response_hex.clone()));
    let f = call(2, &[&h(&reg.client_finish_seed_hex), &r[1], &s[1], id_u, id_s]).unwrap();
    assert_eq!((hex::encode(&f[0]), hex::encode(&f[1])), (reg.record_hex.clone(), reg.export_key_hex.clone()));
    let stored = call(11, &[&s[0], &f[0]]).unwrap().remove(0);
    assert_eq!(hex::encode(&stored), reg.stored_record_hex);

    let l = &t.login;
    let c = call(3, &[&h(&l.client_start_seed_hex), &pw]).unwrap();
    assert_eq!(hex::encode(&c[0]), l.ke1_hex);
    let s = call(12, &[&h(&l.server_seed_hex), &c[0], &stored, ctx, id_u, id_s]).unwrap();
    assert_eq!(hex::encode(&s[0]), l.ke2_hex);
    let f = call(4, &[&h(&l.client_finish_seed_hex), &c[1], &s[0], ctx, id_u, id_s]).unwrap();
    assert_eq!(hex::encode(&f[0]), l.auth_u_hex);
    assert_eq!(hex::encode(&f[1]), l.session_key_hex);
    assert_eq!(hex::encode(&f[2]), l.export_key_hex);
    assert_eq!(hex::encode(&call(13, &[&s[1], &f[0]]).unwrap()[0]), l.session_key_hex);

    let w = &t.login_wrong_password;
    let c = call(3, &[&h(&w.client_start_seed_hex), w.password.as_bytes()]).unwrap();
    let s = call(12, &[&h(&w.server_seed_hex), &c[0], &stored, ctx, id_u, id_s]).unwrap();
    assert_eq!(hex::encode(&s[0]), w.ke2_hex);
    assert_eq!(call(4, &[&h(&w.client_finish_seed_hex), &c[1], &s[0], ctx, id_u, id_s]), Err(1));
    // A wrong auth_u is an auth failure on the server side too.
    assert_eq!(call(13, &[&s[1], &[0u8; 64]]), Err(1));
}

#[test]
fn legacy_abi_rejects_bad_input() {
    assert_eq!(call(1, &[b"short seed", b"pw"]), Err(2));
    assert_eq!(call(1, &[&[0; 32]]), Err(2));
    assert_eq!(call(99, &[]), Err(2));
    assert_eq!(call(4, &[&[0; 32], b"junk", b"", b"", b"", b""]), Err(2));
}
