//! The legacy C ABI (feature `legacy-c-abi`): the dependency-free WASM module the TS SDK loads today
//! (`packages/sdk/src/opaque/index.ts`, built by `crates/ov-opaque/build.sh`). Remove it once the SDK
//! moves to ov-wasm (Wave 3, IW). It is a thin layer over the safe API, with the same bytes as before.
//!
//! ABI: `ov_alloc`/`ov_free` for the input buffer, then `ov_call(op, ptr, len) -> status`. Input and
//! output are lists of fields, each `u32 LE length ‖ bytes`. The output stays in a module buffer
//! (`ov_out_ptr`/`ov_out_len`) until `ov_out_clear`, which zeroes it. Every call that needs randomness
//! takes a 32-byte seed from the caller (crypto.getRandomValues) for a ChaCha20 RNG, so the module needs
//! no host imports. Status: 0 ok, 1 authentication failed, 2 bad input. Passwords arrive as bytes that
//! the caller already NFKC-normalised.

use crate::{server, wire, ClientLoginState, ClientRegistrationState, OpaqueError};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::cell::RefCell;
use zeroize::{Zeroize, Zeroizing};

const OK: i32 = 0;
const AUTH_FAILED: i32 = 1;
const BAD_INPUT: i32 = 2;

thread_local! {
    static OUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

#[no_mangle]
pub extern "C" fn ov_alloc(len: usize) -> *mut u8 {
    let mut v = Vec::<u8>::with_capacity(len.max(1));
    let p = v.as_mut_ptr();
    std::mem::forget(v);
    p
}

/// # Safety
/// `ptr` and `len` must come from `ov_alloc`.
#[no_mangle]
pub unsafe extern "C" fn ov_free(ptr: *mut u8, len: usize) {
    // SAFETY: the caller passes a pointer and length from `ov_alloc`, whose capacity is `len.max(1)`.
    let mut v = unsafe { Vec::from_raw_parts(ptr, len.max(1), len.max(1)) };
    v.zeroize();
}

#[no_mangle]
pub extern "C" fn ov_out_ptr() -> *const u8 {
    OUT.with(|o| o.borrow().as_ptr())
}

#[no_mangle]
pub extern "C" fn ov_out_len() -> usize {
    OUT.with(|o| o.borrow().len())
}

#[no_mangle]
pub extern "C" fn ov_out_clear() {
    OUT.with(|o| {
        let mut o = o.borrow_mut();
        o.zeroize();
        *o = Vec::new();
    });
}

fn fields(b: &[u8], n: usize) -> Result<Vec<&[u8]>, OpaqueError> {
    wire::unpack(b, n).map_err(|_| OpaqueError::InvalidInput("bad input"))
}

fn rng(seed: &[u8]) -> Result<ChaCha20Rng, OpaqueError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| OpaqueError::InvalidInput("bad seed"))?;
    Ok(ChaCha20Rng::from_seed(seed))
}

fn run(op: u32, inp: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpaqueError> {
    match op {
        // client: [seed, pw] -> [request, state]
        1 => {
            let f = fields(inp, 2)?;
            let r = crate::start_registration_bytes(&mut rng(f[0])?, f[1])?;
            Ok(wire::pack(&[&r.request, &r.state.to_bytes()]))
        }
        // client: [seed, state, response, idU, idS] -> [record, export_key]
        2 => {
            let f = fields(inp, 5)?;
            let state = ClientRegistrationState::from_bytes(f[1])?;
            let r = crate::finish_registration_raw(&mut rng(f[0])?, state, f[2], f[3], f[4])?;
            Ok(wire::pack(&[&r.record, &r.export_key]))
        }
        // client: [seed, pw] -> [ke1, state]
        3 => {
            let f = fields(inp, 2)?;
            let r = crate::start_login_bytes(&mut rng(f[0])?, f[1])?;
            Ok(wire::pack(&[&r.ke1, &r.state.to_bytes()]))
        }
        // client: [seed, state, ke2, context, idU, idS] -> [auth_u, session_key, export_key]
        4 => {
            let f = fields(inp, 6)?;
            let state = ClientLoginState::from_bytes(f[1])?;
            let r = crate::finish_login_raw(&mut rng(f[0])?, state, f[2], f[3], f[4], f[5])?;
            Ok(wire::pack(&[&r.auth_u, &r.session_key, &r.export_key]))
        }
        // test server: [seed, request] -> [setup, response]
        10 => {
            let f = fields(inp, 2)?;
            let r = server::registration_response(&mut rng(f[0])?, f[1])?;
            Ok(wire::pack(&[&r.setup, &r.response]))
        }
        // test server: [setup, record] -> [stored record]
        11 => {
            let f = fields(inp, 2)?;
            Ok(wire::pack(&[&server::store_record(f[0], f[1])?]))
        }
        // test server: [seed, ke1, stored record, context, idU, idS] -> [ke2, state]
        12 => {
            let f = fields(inp, 6)?;
            let r = server::credential_response_raw(&mut rng(f[0])?, f[1], f[2], f[3], f[4], f[5])?;
            Ok(wire::pack(&[&r.ke2, &r.state]))
        }
        // test server: [state, auth_u] -> [session_key]
        13 => {
            let f = fields(inp, 2)?;
            Ok(wire::pack(&[&server::user_auth(f[0], f[1])?]))
        }
        _ => Err(OpaqueError::InvalidInput("unknown op")),
    }
}

/// # Safety
/// `ptr` and `len` must describe memory from `ov_alloc`.
#[no_mangle]
pub unsafe extern "C" fn ov_call(op: u32, ptr: *const u8, len: usize) -> i32 {
    ov_out_clear();
    // SAFETY: the caller passes `len` initialised bytes at `ptr` from `ov_alloc`.
    let inp = unsafe { std::slice::from_raw_parts(ptr, len) };
    match run(op, inp) {
        Ok(mut out) => {
            OUT.with(|o| *o.borrow_mut() = std::mem::take(&mut *out));
            OK
        }
        Err(OpaqueError::AuthFailed) => AUTH_FAILED,
        Err(OpaqueError::InvalidInput(_)) => BAD_INPUT,
    }
}
