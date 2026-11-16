//! OPAQUE (SPEC §8, RFC 9807) for openvireo-core, over opaque-ke 4.0.1.
//!
//! Suite: ristretto255 OPRF and 3DH, SHA-512, KSF = Argon2id v1.3 (64 MiB, 2 passes, 1 lane, all-zero
//! 16-byte salt). That is libsodium's `crypto_pwhash` INTERACTIVE setting, which libopaque uses, so this
//! crate talks to the libopaque auth server and shares records with the libopaque C client (desktop).
//! The key-exchange context is `ov-opaque-v1` ([`CONTEXT`]). The OPAQUE password input is the UTF-8 of
//! the NFKC-normalised password ([`password_bytes`]).
//!
//! The client API is two steps per flow:
//!
//! - registration: [`start_registration`] → `request` for `/auth/register/start`, then
//!   [`finish_registration`] on the server's response → `record` for `/auth/register/finish`;
//! - login: [`start_login`] → `ke1` for `/auth/login/start`, then [`finish_login`] on `ke2` → `auth_u`
//!   for `/auth/login/finish` and the session key.
//!
//! Randomness comes from the caller's CSPRNG (`rng`), so a seeded RNG replays recorded transcripts.
//! Secrets (states, export and session keys) are wiped on drop.
//!
//! Features: `legacy-c-abi` (default until the SDK moves to ov-wasm) keeps the old dependency-free WASM
//! C ABI ([`legacy`]); `test-server` adds opaque-ke's server side ([`server`]); `interop` turns on the
//! live libopaque test.

use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    CredentialResponse, Identifiers, RegistrationResponse, Ristretto255, TripleDh,
};
use ov_error::{OvError, OvErrorCode};
use rand_core::{CryptoRng, RngCore};
use std::fmt;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

#[cfg(feature = "legacy-c-abi")]
pub mod legacy;
#[cfg(feature = "test-server")]
pub mod server;
mod wire;

/// The OPAQUE key-exchange context (SPEC §8; the discovery document's `opaque.context`).
pub const CONTEXT: &str = "ov-opaque-v1";

/// The opaque-ke cipher suite (SPEC §8).
pub struct Suite;
impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

/// Argon2id v1.3, 64 MiB, t=2, p=1: `crypto_pwhash_MEMLIMIT_INTERACTIVE` and
/// `crypto_pwhash_OPSLIMIT_INTERACTIVE`. opaque-ke passes an all-zero 16-byte salt.
pub(crate) fn ksf() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(65536, 2, 1, None).expect("constant Argon2 params"))
}

/// Why an OPAQUE step failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpaqueError {
    /// Authentication failed: a wrong password, or the fake record the server sends for an unknown
    /// email. Callers show the same message as a 401.
    AuthFailed,
    /// A message, state or argument was malformed. The string says which step failed (no secrets).
    InvalidInput(&'static str),
}

impl fmt::Display for OpaqueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OpaqueError::AuthFailed => f.write_str("wrong password"),
            OpaqueError::InvalidInput(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for OpaqueError {}

/// Both kinds become `opaque_failed`, with the TS SDK's messages.
impl From<OpaqueError> for OvError {
    fn from(e: OpaqueError) -> Self {
        OvError::new(OvErrorCode::OpaqueFailed, e.to_string())
    }
}

pub(crate) fn bad<E>(message: &'static str) -> impl FnOnce(E) -> OpaqueError {
    move |_| OpaqueError::InvalidInput(message)
}

/// The OPAQUE identities (SPEC §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpaqueIds {
    /// `idU`: the account email, trimmed and lowercased.
    pub id_u: String,
    /// `idS`: the issuer host, for example `accounts.openvireo.com`.
    pub id_s: String,
}

/// `idU` = trimmed, lowercased email; `idS` = the issuer host (the discovery document's `opaque.ids`, or
/// the issuer URL's host). Mirrors the TS SDK's `opaqueIds`: when `issuer_or_host` starts with a
/// `scheme://`, it is reduced to the URL's host (lowercased, userinfo dropped, the scheme's default port
/// dropped). Unlike the WHATWG URL parser it does not punycode non-ASCII host names.
pub fn opaque_ids(email: &str, issuer_or_host: &str) -> OpaqueIds {
    let id_s = js_trim(issuer_or_host);
    let id_s = match url_host(id_s) {
        Some(host) => host,
        None => id_s.to_string(),
    };
    OpaqueIds { id_u: js_trim(email).to_lowercase(), id_s }
}

/// `String.prototype.trim`: Unicode White_Space plus U+FEFF.
fn js_trim(s: &str) -> &str {
    s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
}

/// The host (`hostname[:port]`) of `scheme://...`, or None when `s` has no scheme.
fn url_host(s: &str) -> Option<String> {
    let (scheme, rest) = s.split_once("://")?;
    let mut chars = scheme.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphabetic());
    if !first_ok || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    let special = matches!(scheme.as_str(), "http" | "https" | "ws" | "wss" | "ftp" | "file");
    let end = rest.find(|c: char| c == '/' || c == '?' || c == '#' || (special && c == '\\')).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // The port separator is the last ':' outside an IPv6 literal.
    let (host, port) = match host_port.rfind(':') {
        Some(i) if !host_port[i..].contains(']') => (&host_port[..i], Some(&host_port[i + 1..])),
        _ => (host_port, None),
    };
    let host = host.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        _ => None,
    };
    Some(match port.filter(|p| !p.is_empty()) {
        None => host,
        Some(p) => match p.parse::<u16>() {
            Ok(n) if Some(n) == default_port => host,
            Ok(n) => format!("{host}:{n}"),
            Err(_) => format!("{host}:{p}"),
        },
    })
}

/// The OPAQUE password input: the UTF-8 bytes of NFKC(password), as the TS SDK's `passwordBytes`.
pub fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    let normalized = Zeroizing::new(password.nfkc().collect::<String>());
    Zeroizing::new(normalized.as_bytes().to_vec())
}

fn check_password(pw: &[u8]) -> Result<(), OpaqueError> {
    if pw.is_empty() || pw.len() > 0xffff {
        return Err(OpaqueError::InvalidInput("password must be 1..65535 UTF-8 bytes"));
    }
    Ok(())
}

/// Client state between the two registration steps. It holds the password (finish needs it again)
/// and is wiped on drop.
pub struct ClientRegistrationState {
    inner: ClientRegistration<Suite>,
    password: Zeroizing<Vec<u8>>,
}

/// Client state between the two login steps. It holds the password and is wiped on drop.
pub struct ClientLoginState {
    inner: ClientLogin<Suite>,
    password: Zeroizing<Vec<u8>>,
}

macro_rules! state_bytes {
    ($ty:ident, $inner:ident, $what:literal) => {
        impl $ty {
            /// The state as bytes, `u32le len ‖ opaque-ke state ‖ u32le len ‖ password` (the legacy C
            /// ABI's format). Secret: wipe it, never store it.
            pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
                let state = Zeroizing::new(self.inner.serialize().to_vec());
                wire::pack(&[&state, &self.password])
            }

            /// Parses [`to_bytes`](Self::to_bytes).
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, OpaqueError> {
                let f = wire::unpack(bytes, 2).map_err(bad($what))?;
                let inner = $inner::<Suite>::deserialize(f[0]).map_err(bad($what))?;
                Ok($ty { inner, password: Zeroizing::new(f[1].to_vec()) })
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($ty), "(redacted)"))
            }
        }
    };
}
state_bytes!(ClientRegistrationState, ClientRegistration, "reading the registration state failed");
state_bytes!(ClientLoginState, ClientLogin, "reading the login state failed");

/// [`start_registration`]'s result.
#[derive(Debug)]
pub struct RegistrationStart {
    /// `request` for `/auth/register/start` (OPAQUE M).
    pub request: Vec<u8>,
    pub state: ClientRegistrationState,
}

/// [`finish_registration`]'s result.
pub struct RegistrationFinish {
    /// `record` for `/auth/register/finish`.
    pub record: Vec<u8>,
    /// The export key. Not used in v1 (SPEC §8).
    pub export_key: Zeroizing<Vec<u8>>,
}

/// [`start_login`]'s result.
#[derive(Debug)]
pub struct LoginStart {
    /// `ke1` for `/auth/login/start`.
    pub ke1: Vec<u8>,
    pub state: ClientLoginState,
}

/// [`finish_login`]'s result.
pub struct LoginFinish {
    /// `authU` (KE3) for `/auth/login/finish`.
    pub auth_u: Vec<u8>,
    /// The session key (the server derives the same one).
    pub session_key: Zeroizing<Vec<u8>>,
    /// The export key (the same as at registration).
    pub export_key: Zeroizing<Vec<u8>>,
}

macro_rules! redacted_debug {
    ($ty:ident, $public:ident) => {
        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($ty)).field(stringify!($public), &self.$public).finish_non_exhaustive()
            }
        }
    };
}
redacted_debug!(RegistrationFinish, record);
redacted_debug!(LoginFinish, auth_u);

/// Starts a registration. `password` is NFKC-normalised ([`password_bytes`]) and must be 1..65535 bytes.
pub fn start_registration<R: RngCore + CryptoRng>(
    rng: &mut R,
    password: &str,
) -> Result<RegistrationStart, OpaqueError> {
    let pw = password_bytes(password);
    check_password(&pw)?;
    start_registration_bytes(rng, &pw)
}

/// [`start_registration`] on password bytes that are already UTF-8(NFKC(password)). No length check.
pub(crate) fn start_registration_bytes<R: RngCore + CryptoRng>(
    rng: &mut R,
    pw: &[u8],
) -> Result<RegistrationStart, OpaqueError> {
    let r = ClientRegistration::<Suite>::start(rng, pw).map_err(bad("registration request failed"))?;
    Ok(RegistrationStart {
        request: r.message.serialize().to_vec(),
        state: ClientRegistrationState { inner: r.state, password: Zeroizing::new(pw.to_vec()) },
    })
}

/// Finishes a registration on the server's `response`. Consumes (and wipes) the state.
pub fn finish_registration<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: ClientRegistrationState,
    response: &[u8],
    ids: &OpaqueIds,
) -> Result<RegistrationFinish, OpaqueError> {
    finish_registration_raw(rng, state, response, ids.id_u.as_bytes(), ids.id_s.as_bytes())
}

pub(crate) fn finish_registration_raw<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: ClientRegistrationState,
    response: &[u8],
    id_u: &[u8],
    id_s: &[u8],
) -> Result<RegistrationFinish, OpaqueError> {
    const WHAT: &str = "finishing the registration failed";
    let response = RegistrationResponse::deserialize(response).map_err(bad(WHAT))?;
    let k = ksf();
    let r = state
        .inner
        .finish(rng, &state.password, response, ClientRegistrationFinishParameters::new(ids(id_u, id_s), Some(&k)))
        .map_err(bad(WHAT))?;
    Ok(RegistrationFinish { record: r.message.serialize().to_vec(), export_key: Zeroizing::new(r.export_key.to_vec()) })
}

/// Starts a login. `password` is NFKC-normalised ([`password_bytes`]) and must be 1..65535 bytes.
pub fn start_login<R: RngCore + CryptoRng>(rng: &mut R, password: &str) -> Result<LoginStart, OpaqueError> {
    let pw = password_bytes(password);
    check_password(&pw)?;
    start_login_bytes(rng, &pw)
}

pub(crate) fn start_login_bytes<R: RngCore + CryptoRng>(rng: &mut R, pw: &[u8]) -> Result<LoginStart, OpaqueError> {
    let r = ClientLogin::<Suite>::start(rng, pw).map_err(bad("credential request failed"))?;
    Ok(LoginStart {
        ke1: r.message.serialize().to_vec(),
        state: ClientLoginState { inner: r.state, password: Zeroizing::new(pw.to_vec()) },
    })
}

/// Processes `ke2`. Consumes (and wipes) the state. [`OpaqueError::AuthFailed`] on a wrong password or
/// a fake record for an unknown email. `context` is [`CONTEXT`] unless discovery says otherwise.
pub fn finish_login<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: ClientLoginState,
    ke2: &[u8],
    ids: &OpaqueIds,
    context: &str,
) -> Result<LoginFinish, OpaqueError> {
    finish_login_raw(rng, state, ke2, context.as_bytes(), ids.id_u.as_bytes(), ids.id_s.as_bytes())
}

pub(crate) fn finish_login_raw<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: ClientLoginState,
    ke2: &[u8],
    context: &[u8],
    id_u: &[u8],
    id_s: &[u8],
) -> Result<LoginFinish, OpaqueError> {
    let ke2 = CredentialResponse::deserialize(ke2).map_err(bad("recovering the credentials failed"))?;
    let k = ksf();
    let r = state
        .inner
        .finish(rng, &state.password, ke2, ClientLoginFinishParameters::new(Some(context), ids(id_u, id_s), Some(&k)))
        .map_err(|_| OpaqueError::AuthFailed)?;
    Ok(LoginFinish {
        auth_u: r.message.serialize().to_vec(),
        session_key: Zeroizing::new(r.session_key.to_vec()),
        export_key: Zeroizing::new(r.export_key.to_vec()),
    })
}

pub(crate) fn ids<'a>(id_u: &'a [u8], id_s: &'a [u8]) -> Identifiers<'a> {
    Identifiers { client: Some(id_u), server: Some(id_s) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_match_the_ts_sdk() {
        let ids = |e, i| {
            let r = opaque_ids(e, i);
            (r.id_u, r.id_s)
        };
        assert_eq!(
            ids("  Alice@Example.COM ", "accounts.openvireo.com"),
            ("alice@example.com".into(), "accounts.openvireo.com".into())
        );
        assert_eq!(ids("a@b.c", "https://accounts.openvireo.com"), ("a@b.c".into(), "accounts.openvireo.com".into()));
        assert_eq!(
            ids("a@b.c", " HTTPS://Accounts.OpenVireo.com/path?q#f "),
            ("a@b.c".into(), "accounts.openvireo.com".into())
        );
        assert_eq!(ids("a@b.c", "https://accounts.example:443"), ("a@b.c".into(), "accounts.example".into()));
        assert_eq!(ids("a@b.c", "http://localhost:8000/"), ("a@b.c".into(), "localhost:8000".into()));
        assert_eq!(ids("a@b.c", "https://user:pw@host.example:8443"), ("a@b.c".into(), "host.example:8443".into()));
        assert_eq!(ids("a@b.c", "http://[::1]:80/"), ("a@b.c".into(), "[::1]".into()));
        assert_eq!(ids("a@b.c", "http://[::1]:8080"), ("a@b.c".into(), "[::1]:8080".into()));
        // No scheme: kept as is (trimmed), like the SDK.
        assert_eq!(ids("a@b.c", "Host.Example:8000"), ("a@b.c".into(), "Host.Example:8000".into()));
        assert_eq!(ids("\u{feff}ÄB@x.y", "h"), ("äb@x.y".into(), "h".into()));
    }

    #[test]
    fn password_is_nfkc_utf8() {
        assert_eq!(&*password_bytes("ﬁ Å"), "fi Å".as_bytes());
        assert!(matches!(
            start_login(&mut rand_chacha::ChaCha20Rng::from_seed_zero(), ""),
            Err(OpaqueError::InvalidInput(_))
        ));
    }

    #[test]
    fn errors_map_to_opaque_failed() {
        let e: OvError = OpaqueError::AuthFailed.into();
        assert_eq!((e.wire_code(), e.message.as_str()), ("opaque_failed", "wrong password"));
        let e: OvError = OpaqueError::InvalidInput("credential request failed").into();
        assert_eq!(e.message, "credential request failed");
    }

    trait SeedZero {
        fn from_seed_zero() -> Self;
    }
    impl SeedZero for rand_chacha::ChaCha20Rng {
        fn from_seed_zero() -> Self {
            <Self as rand_core::SeedableRng>::from_seed([0; 32])
        }
    }
}
