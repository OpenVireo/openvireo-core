//! The in-memory auth server: every client route of `openapi.yaml`. Ported from `auth-server.ts`,
//! with real EdDSA access tokens, refresh-token rotation (SPEC §9), TOTP, invitations, devices,
//! audit, billing and the org/SA routes the TS fake left out.

use std::collections::BTreeMap;

use ov_crypto::curves::{ed25519_public_key, ed25519_sign};
use ov_crypto::encoding::{b64u, from_b64u};
use ov_crypto::jwt::{verify_jwt, Jwk, Jwks, VerifyOptions, DEFAULT_SKEW_SECS};
use ov_host::{HttpResponse, Method};
use ov_protocol::discovery::{KdfMin, OpaqueConfig, OpenVireoConfiguration};
use ov_protocol::types::*;
use rand_chacha::ChaCha20Rng;
use rand_core::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::http::{empty, error, error_with, iso, matches, ok, parse_iso, Params, Req, Res, Table};
use super::{str_of, sync, World, OPAQUE_CONTEXT};

/// The issuer.
pub(crate) const ISSUER: &str = "https://auth.test";
const IDS: &str = "auth.test";
const KID: &str = "test-key-1";
const SESSION_MS: i64 = 5 * 60_000;
const REFRESH_LIFETIME_MS: i64 = 30 * 86_400_000;
const REFRESH_GRACE_MS: i64 = 60_000;

/// The discovery document (SPEC §10).
pub(crate) fn configuration() -> OpenVireoConfiguration {
    OpenVireoConfiguration {
        issuer: ISSUER.into(),
        api: format!("{ISSUER}/api/v1"),
        sync: format!("https://{}/api/v1", super::SYNC_HOST),
        jwks_uri: format!("{ISSUER}/.well-known/jwks.json"),
        opaque: OpaqueConfig {
            lib: "opaque-ke".into(),
            version: "4.0.1".into(),
            context: OPAQUE_CONTEXT.into(),
            ids: IDS.into(),
        },
        kdf_min: Some(KdfMin { m: 19456, t: 2 }),
        web: Some("https://app.test".into()),
        share: Some("https://share.test".into()),
    }
}

// ------------------------------------------------------------------------------------ state

pub(crate) struct User {
    pub id: String,
    pub email: String,
    rec: Zeroizing<Vec<u8>>,
    kdf: Kdf,
    keyset: WrappedKeyset,
    /// Base32 secret of the enabled TOTP.
    pub totp_secret: Option<String>,
    pending_totp: Option<String>,
    /// A fixed code that is always accepted (the TS fake's `totp` map).
    pub fixed_totp: Option<String>,
}

enum Pending {
    Register { setup: Zeroizing<Vec<u8>>, email: String, user_id: String },
    Login { state: Zeroizing<Vec<u8>>, email: Option<String> },
    Recover { setup: Zeroizing<Vec<u8>>, token: String },
    Restore { state: Zeroizing<Vec<u8>>, user_id: String, verified: Option<Vec<VaultGrant>> },
    Password { setup: Zeroizing<Vec<u8>>, principal: String },
    Email { setup: Zeroizing<Vec<u8>>, principal: String, email: String },
}

struct PendingRec {
    at: i64,
    kind: Pending,
}

struct Mfa {
    email: String,
    wrong: u32,
    at: i64,
    device: DeviceInfo,
}

struct Refresh {
    principal: String,
    device_id: String,
    used: bool,
    rotated_at: Option<i64>,
    replacement: Option<String>,
    last_used: i64,
}

struct TokenInfo {
    principal: String,
    iat_ms: i64,
}

struct DeviceRec {
    user_id: String,
    name: String,
    platform: Platform,
    created_at: i64,
    last_seen_at: i64,
}

pub(crate) struct AccessRec {
    pub role: VaultRole,
    keys: BTreeMap<i64, String>,
    granted_by: Option<String>,
    granted_at: i64,
}

pub(crate) struct VaultRec {
    org_id: Option<String>,
    owner_id: Option<String>,
    encrypted_name: String,
    current: i64,
    pending: Option<i64>,
    /// When the pending version was started (ms), for the 24-hour rule (SPEC §7).
    pending_since: i64,
    pub access: Table<AccessRec>,
    rotation_required: bool,
    pub archived: bool,
    created_at: i64,
}

pub(crate) struct MemberRec {
    role: OrgRole,
    status: MemberStatus,
}

struct InvRec {
    email: String,
    role: OrgRole,
    expires_at: i64,
    invited_by: String,
    token: String,
}

pub(crate) struct OrgRec {
    name: String,
    created_at: i64,
    policy: ShareLinkPolicy,
    pub members: Table<MemberRec>,
    invitations: Table<InvRec>,
    audit: Vec<AuditEvent>,
}

struct SecretRec {
    hash: String,
    prefix: String,
    name: Option<String>,
    wrapped_master: String,
    created_at: i64,
    last_used_at: Option<i64>,
    expires_at: Option<String>,
}

struct SaRec {
    org_id: String,
    name: String,
    keyset: WrappedKeyset,
    master: Table<String>,
    secrets: Table<SecretRec>,
    expires_at: Option<String>,
    disabled: bool,
    created_by: String,
    created_at: i64,
}

struct ShareRec {
    owner: String,
    vault_id: Option<String>,
    ct: Option<String>,
    reference: Option<String>,
    kdf: Option<Kdf>,
    auth_hash: Option<String>,
    failed: i64,
    max_opens: Option<i64>,
    opens: i64,
    opened_at: Vec<String>,
    created_at: i64,
    expires_at: i64,
    ended: Option<ShareEndReason>,
    ended_at: Option<i64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecoveryStatus {
    Approved,
    Cancelled,
    Completed,
}

struct Recovery {
    email: String,
    not_before: i64,
    expires_at: i64,
    status: RecoveryStatus,
}

struct Archive {
    email: String,
    rec: Zeroizing<Vec<u8>>,
    kdf: Kdf,
    keyset: WrappedKeyset,
    expires_at: i64,
    grants: Vec<VaultGrant>,
    failures: u32,
    locked: bool,
}

pub(crate) struct AuthState {
    signing_seed: Zeroizing<[u8; 32]>,
    /// email (lowercase) → user.
    pub users: Table<User>,
    pending: Table<PendingRec>,
    mfa: Table<Mfa>,
    refresh: Table<Refresh>,
    /// jti → issued access token (removed = revoked).
    tokens: Table<TokenInfo>,
    devices: Table<DeviceRec>,
    pub vaults: Table<VaultRec>,
    pub orgs: Table<OrgRec>,
    sas: Table<SaRec>,
    shares: Table<ShareRec>,
    recoveries: Table<Recovery>,
    archives: Table<Archive>,
    /// user id → erase date (RFC 3339) while pending deletion.
    deletions: Table<String>,
    /// user id → (new email, code).
    pub email_codes: Table<(String, String)>,
    pub plans: Table<Plan>,
    fake_records: Table<Zeroizing<Vec<u8>>>,
    pub access_events: Vec<Value>,
    pub recent_token_ms: i64,
    pub deletion_days: i64,
    pub token_ttl_secs: i64,
}

impl AuthState {
    pub fn new(rng: &mut ChaCha20Rng) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut());
        AuthState {
            signing_seed: seed,
            users: Table::default(),
            pending: Table::default(),
            mfa: Table::default(),
            refresh: Table::default(),
            tokens: Table::default(),
            devices: Table::default(),
            vaults: Table::default(),
            orgs: Table::default(),
            sas: Table::default(),
            shares: Table::default(),
            recoveries: Table::default(),
            archives: Table::default(),
            deletions: Table::default(),
            email_codes: Table::default(),
            plans: Table::default(),
            fake_records: Table::default(),
            access_events: vec![],
            recent_token_ms: 5 * 60_000,
            deletion_days: 30,
            token_ttl_secs: 600,
        }
    }

    /// The JWKS with the one signing key.
    pub fn jwks(&self) -> Jwks {
        Jwks {
            keys: vec![Jwk {
                kty: "OKP".into(),
                crv: Some("Ed25519".into()),
                x: Some(b64u(&ed25519_public_key(&self.signing_seed))),
                kid: Some(KID.into()),
                use_: Some("sig".into()),
                alg: Some("EdDSA".into()),
            }],
        }
    }

    pub fn user_by_id(&self, id: &str) -> Option<&User> {
        self.users.values().find(|u| u.id == id)
    }

    fn user_by_id_mut(&mut self, id: &str) -> Option<&mut User> {
        self.users.values_mut().find(|u| u.id == id)
    }

    /// Revokes every access and refresh token of a principal ("signed out everywhere").
    pub fn revoke_principal(&mut self, principal: &str) {
        self.tokens.retain(|_, t| t.principal != principal);
        self.refresh.retain(|_, r| r.principal != principal);
    }
}

/// The principal's current role on a vault (for the sync server's live mode).
pub(crate) fn live_role(w: &World, principal: &str, vault: &str) -> Option<String> {
    let v = w.auth.vaults.get(vault).filter(|v| !v.archived)?;
    v.access.get(principal).map(|a| a.role.as_str().to_string())
}

fn uid(principal: &str) -> &str {
    principal.split_once(':').map_or("", |(_, id)| id)
}

fn norm_email(e: &str) -> String {
    e.trim().to_lowercase()
}

fn b64(s: &str) -> Result<Vec<u8>, HttpResponse> {
    from_b64u(s).map_err(|_| error(400, "invalid_request", "bad base64url"))
}

fn sha256_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn opaque_bad<E>(_: E) -> HttpResponse {
    error(400, "invalid_request", "bad OPAQUE message")
}

fn expired() -> HttpResponse {
    error(410, "session_expired", "expired")
}

// ------------------------------------------------------------------------------------ tokens

/// Signs an access token (SPEC §9).
pub(crate) fn issue(w: &mut World, principal: &str, dev: Option<&str>) -> String {
    let now = w.now_s();
    let jti = w.uuid();
    let id = uid(principal).to_string();
    let pending = if principal.starts_with("user:") { w.auth.deletions.get(&id).cloned() } else { None };
    let mut claims = json!({
        "iss": ISSUER, "aud": ["ov-api", "ov-sync"], "sub": principal,
        "iat": now, "nbf": now, "exp": now + w.auth.token_ttl_secs, "jti": jti,
    });
    if let Some(d) = dev {
        claims["dev"] = d.into();
    }
    if let Some(sa) = w.auth.sas.get(&id).filter(|_| principal.starts_with("sa:")) {
        claims["org"] = sa.org_id.clone().into();
    }
    match pending {
        Some(del) => claims["del"] = del.into(),
        None => {
            let q = w.auth.plans.get(&id).and_then(|p| p.limits.get("vault_bytes").copied().flatten());
            let vlt: Vec<Value> = w
                .auth
                .vaults
                .iter()
                .filter(|(_, v)| !v.archived)
                .filter_map(|(vid, v)| {
                    let a = v.access.get(principal)?;
                    let mut c = json!({ "id": vid, "r": a.role.as_str() });
                    if let Some(q) = q {
                        c["q"] = q.into();
                    }
                    Some(c)
                })
                .collect();
            claims["vlt"] = vlt.into();
        }
    }
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": KID });
    let signing_input = format!("{}.{}", b64u(header.to_string().as_bytes()), b64u(claims.to_string().as_bytes()));
    let sig = ed25519_sign(signing_input.as_bytes(), &w.auth.signing_seed);
    let iat_ms = w.now_ms();
    w.auth.tokens.insert(jti, TokenInfo { principal: principal.to_string(), iat_ms });
    format!("{signing_input}.{}", b64u(&sig))
}

/// A verified, unrevoked access token.
pub(crate) struct Caller {
    pub principal: String,
    pub dev: Option<String>,
    pub iat_ms: i64,
}

fn caller(w: &World, req: &Req, pending_ok: bool) -> Result<Caller, HttpResponse> {
    let unauthorized = || error(401, "unauthorized", "unauthorized");
    let token = req.bearer();
    if !ov_crypto::jwt::is_jwt(token) {
        return Err(unauthorized());
    }
    let opts =
        VerifyOptions { issuer: ISSUER.into(), audience: "ov-api".into(), now: w.now_s(), skew: DEFAULT_SKEW_SECS };
    let claims = verify_jwt(token, &w.auth.jwks(), &opts).map_err(|_| unauthorized())?;
    let info = claims.jti.as_deref().and_then(|j| w.auth.tokens.get(j)).ok_or_else(unauthorized)?;
    if let Some(at) = w.auth.deletions.get(uid(&claims.sub)).filter(|_| claims.sub.starts_with("user:")) {
        if !pending_ok {
            return Err(error_with(
                403,
                "account_pending_deletion",
                "scheduled for deletion",
                json!({ "scheduled_for": at }),
            ));
        }
    }
    Ok(Caller { principal: claims.sub, dev: claims.dev, iat_ms: info.iat_ms })
}

fn user_caller(w: &World, req: &Req, pending_ok: bool) -> Result<Caller, HttpResponse> {
    let c = caller(w, req, pending_ok)?;
    if !c.principal.starts_with("user:") || w.auth.user_by_id(uid(&c.principal)).is_none() {
        return Err(error(403, "forbidden", "users only"));
    }
    Ok(c)
}

fn require_recent(w: &World, c: &Caller) -> Result<(), HttpResponse> {
    if w.now_ms() - c.iat_ms > w.auth.recent_token_ms {
        return Err(error(403, "forbidden", "Log in again to do this"));
    }
    Ok(())
}

/// Sends an `access` event to the subjects' streams and records it.
fn notify(w: &mut World, subjects: Vec<String>, data: Value) {
    w.auth.access_events.push(json!({ "subjects": subjects, "data": data }));
    sync::notify_access(w, &subjects, &data);
}

fn audit(w: &mut World, org: &str, actor: &str, action: &str, target: Option<&str>) {
    let id = w.uuid();
    let at = iso(w.now_ms());
    if let Some(o) = w.auth.orgs.get_mut(org) {
        o.audit.push(AuditEvent {
            id,
            at,
            actor: actor.into(),
            action: action.into(),
            target: target.map(str::to_string),
            ip: None,
            details: None,
        });
    }
}

/// A session for the user (SPEC §9): a device, a refresh token and an access token.
fn session(w: &mut World, email: &str, device: &DeviceInfo, status: u16) -> Res {
    let now = w.now_ms();
    let user_id = w.auth.users.get(email).map(|u| u.id.clone()).ok_or_else(|| error(404, "not_found", "no user"))?;
    let device_id = match device.id.as_deref().filter(|d| w.auth.devices.get(d).is_some_and(|r| r.user_id == user_id)) {
        Some(d) => {
            let rec = w.auth.devices.get_mut(d).expect("checked");
            rec.last_seen_at = now;
            rec.name.clone_from(&device.name);
            d.to_string()
        }
        None => {
            let d = w.uuid();
            let rec = DeviceRec {
                user_id: user_id.clone(),
                name: device.name.clone(),
                platform: device.platform.clone(),
                created_at: now,
                last_seen_at: now,
            };
            w.auth.devices.insert(d.clone(), rec);
            d
        }
    };
    let principal = format!("user:{user_id}");
    let rt = new_refresh(w, &principal, &device_id);
    let access_token = issue(w, &principal, Some(&device_id));
    let u = w.auth.users.get(email).expect("exists");
    ok(
        status,
        &Session {
            access_token,
            refresh_token: rt,
            expires_in: w.auth.token_ttl_secs,
            device_id,
            user: SessionUser { id: u.id.clone(), email: u.email.clone() },
            kdf: u.kdf.clone(),
            keyset: u.keyset.clone(),
        },
    )
}

fn new_refresh(w: &mut World, principal: &str, device_id: &str) -> String {
    let rt = format!("ov_rt_{}", b64u(&w.random_bytes(32)));
    let now = w.now_ms();
    w.auth.refresh.insert(
        rt.clone(),
        Refresh {
            principal: principal.into(),
            device_id: device_id.into(),
            used: false,
            rotated_at: None,
            replacement: None,
            last_used: now,
        },
    );
    rt
}

fn take_pending(w: &mut World, sid: &str) -> Option<Pending> {
    let now = w.now_ms();
    let p = w.auth.pending.remove(sid)?;
    (now - p.at <= SESSION_MS).then_some(p.kind)
}

fn put_pending(w: &mut World, kind: Pending) -> String {
    let sid = w.uuid();
    let at = w.now_ms();
    w.auth.pending.insert(sid.clone(), PendingRec { at, kind });
    sid
}

fn registration_response(w: &mut World, request: &str) -> Result<(Zeroizing<Vec<u8>>, String), HttpResponse> {
    let request = b64(request)?;
    let r = ov_opaque::server::registration_response(&mut w.rng, &request).map_err(opaque_bad)?;
    Ok((r.setup, b64u(&r.response)))
}

fn store_record(setup: &[u8], record: &str) -> Result<Zeroizing<Vec<u8>>, HttpResponse> {
    ov_opaque::server::store_record(setup, &b64(record)?).map_err(opaque_bad)
}

fn credential_response(
    w: &mut World,
    ke1: &str,
    rec: &[u8],
    email: &str,
) -> Result<(Zeroizing<Vec<u8>>, String), HttpResponse> {
    let ids = ov_opaque::opaque_ids(email, IDS);
    let r = ov_opaque::server::credential_response(&mut w.rng, &b64(ke1)?, rec, &ids, OPAQUE_CONTEXT)
        .map_err(opaque_bad)?;
    Ok((r.state, b64u(&r.ke2)))
}

fn user_auth(state: &[u8], auth_u: &str) -> bool {
    from_b64u(auth_u).is_ok_and(|a| ov_opaque::server::user_auth(state, &a).is_ok())
}

/// A record for an unknown email, so `login/start` looks the same (SPEC §8).
fn fake_record(w: &mut World, email: &str) -> Result<Zeroizing<Vec<u8>>, HttpResponse> {
    if let Some(r) = w.auth.fake_records.get(email) {
        return Ok(r.clone());
    }
    let password = b64u(&w.random_bytes(16));
    let start = ov_opaque::start_registration(&mut w.rng, &password).map_err(opaque_bad)?;
    let resp = ov_opaque::server::registration_response(&mut w.rng, &start.request).map_err(opaque_bad)?;
    let ids = ov_opaque::opaque_ids(email, IDS);
    let fin = ov_opaque::finish_registration(&mut w.rng, start.state, &resp.response, &ids).map_err(opaque_bad)?;
    let rec = ov_opaque::server::store_record(&resp.setup, &fin.record).map_err(opaque_bad)?;
    w.auth.fake_records.insert(email, rec.clone());
    Ok(rec)
}

/// The TOTP code for a base32 secret at `ms`.
pub(crate) fn totp_at(secret: &str, ms: i64) -> Option<String> {
    let params = ov_share::totp::parse_totp_uri(&format!("otpauth://totp/x?secret={secret}")).ok()?;
    Some(ov_share::totp::totp_code(&params, ms).code.to_string())
}

fn totp_ok(w: &World, u: &User, code: &str, secret: Option<&str>) -> bool {
    if u.fixed_totp.as_deref() == Some(code) && secret.is_none() {
        return true;
    }
    let Some(secret) = secret.or(u.totp_secret.as_deref()) else { return false };
    let now = w.now_ms();
    [-30_000, 0, 30_000].iter().any(|d| totp_at(secret, now + d).as_deref() == Some(code))
}

fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0);
    for &b in bytes {
        buf = (buf << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            out.push(A[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

// ------------------------------------------------------------------------------------ JSON views

fn public_of(w: &World, principal: &str) -> Option<PublicPrincipal> {
    let id = uid(principal);
    if principal.starts_with("user:") {
        let u = w.auth.user_by_id(id)?;
        return Some(PublicPrincipal {
            enc_pk: u.keyset.enc_pk.clone(),
            sign_pk: u.keyset.sign_pk.clone(),
            sig: u.keyset.sig.clone(),
            principal: principal.into(),
            email: Some(u.email.clone()),
            name: None,
        });
    }
    let sa = w.auth.sas.get(id)?;
    Some(PublicPrincipal {
        enc_pk: sa.keyset.enc_pk.clone(),
        sign_pk: sa.keyset.sign_pk.clone(),
        sig: sa.keyset.sig.clone(),
        principal: principal.into(),
        email: None,
        name: Some(sa.name.clone()),
    })
}

fn display(w: &World, principal: &str) -> Option<String> {
    public_of(w, principal).and_then(|p| p.email.or(p.name))
}

fn vault_json(w: &World, id: &str, principal: &str) -> Option<Vault> {
    let v = w.auth.vaults.get(id)?;
    let a = v.access.get(principal)?;
    let mut keys: Vec<VaultKey> = a
        .keys
        .iter()
        .filter(|(k, _)| **k == v.current || Some(**k) == v.pending)
        .map(|(k, s)| VaultKey { key_version: *k, sealed_key: s.clone() })
        .collect();
    keys.sort_by_key(|k| std::cmp::Reverse(k.key_version));
    Some(Vault {
        id: id.into(),
        org_id: v.org_id.clone(),
        owner_id: v.owner_id.clone(),
        encrypted_name: v.encrypted_name.clone(),
        role: a.role.clone(),
        current_key_version: v.current,
        pending_key_version: v.pending,
        rotation_required: Some(v.rotation_required),
        keys,
        created_at: Some(iso(v.created_at)),
    })
}

fn vault_res(w: &World, id: &str, principal: &str, status: u16) -> Res {
    match vault_json(w, id, principal) {
        Some(v) => ok(status, &v),
        None => Err(error(404, "not_found", "no such vault")),
    }
}

fn member_json(w: &World, uid: &str, m: &MemberRec) -> Member {
    let u = w.auth.user_by_id(uid);
    Member {
        user_id: uid.into(),
        email: u.map(|u| u.email.clone()).unwrap_or_default(),
        name: None,
        role: m.role.clone(),
        status: m.status.clone(),
        public: u.map(|u| PublicKeys {
            enc_pk: u.keyset.enc_pk.clone(),
            sign_pk: u.keyset.sign_pk.clone(),
            sig: u.keyset.sig.clone(),
        }),
    }
}

fn org_json(w: &World, id: &str, principal: &str) -> Option<Org> {
    let o = w.auth.orgs.get(id)?;
    let m = o.members.get(uid(principal))?;
    Some(Org {
        id: id.into(),
        name: o.name.clone(),
        role: m.role.clone(),
        plan: None,
        item_share_links: Some(o.policy.clone()),
        created_at: iso(o.created_at),
    })
}

fn is_admin(w: &World, org: &str, principal: &str) -> bool {
    w.auth
        .orgs
        .get(org)
        .and_then(|o| o.members.get(uid(principal)))
        .is_some_and(|m| m.status == MemberStatus::Confirmed && matches!(m.role, OrgRole::Owner | OrgRole::Admin))
}

fn org_admin(w: &World, org: &str, c: &Caller) -> Result<(), HttpResponse> {
    if !w.auth.orgs.contains(org) {
        return Err(error(404, "not_found", "no such org"));
    }
    if !is_admin(w, org, &c.principal) {
        return Err(error(403, "forbidden", "owners and admins only"));
    }
    Ok(())
}

fn sa_json(w: &World, id: &str, principal: &str) -> Option<ServiceAccount> {
    let sa = w.auth.sas.get(id)?;
    let admin = is_admin(w, &sa.org_id, principal);
    Some(ServiceAccount {
        id: id.into(),
        org_id: sa.org_id.clone(),
        name: sa.name.clone(),
        public: Some(PublicKeys {
            enc_pk: sa.keyset.enc_pk.clone(),
            sign_pk: sa.keyset.sign_pk.clone(),
            sig: sa.keyset.sig.clone(),
        }),
        keyset: admin.then(|| sa.keyset.clone()),
        master_key: sa.master.get(principal).cloned(),
        created_by: Some(sa.created_by.clone()),
        created_at: Some(iso(sa.created_at)),
        expires_at: sa.expires_at.clone(),
        disabled: Some(sa.disabled),
    })
}

fn secret_json(s: &SecretRec, id: &str) -> SaSecret {
    SaSecret {
        id: id.into(),
        prefix: s.prefix.clone(),
        name: s.name.clone(),
        created_at: iso(s.created_at),
        last_used_at: s.last_used_at.map(iso),
        expires_at: s.expires_at.clone(),
    }
}

fn share_json(id: &str, s: &ShareRec) -> Share {
    let status = if s.ended.is_some() {
        ShareStatus::Ended
    } else if s.ct.is_some() {
        ShareStatus::Active
    } else {
        ShareStatus::Pending
    };
    Share {
        id: id.into(),
        vault_id: s.vault_id.clone(),
        reference: s.reference.clone(),
        passcode: s.kdf.is_some(),
        max_opens: s.max_opens,
        opens: s.opens,
        opened_at: s.opened_at.clone(),
        created_at: iso(s.created_at),
        expires_at: iso(s.expires_at),
        status,
        ended_at: s.ended_at.map(iso),
        end_reason: s.ended.clone(),
    }
}

fn end_share(s: &mut ShareRec, reason: ShareEndReason, now: i64) {
    if s.ended.is_none() {
        s.ended = Some(reason);
        s.ended_at = Some(now);
        s.ct = None;
    }
}

// ------------------------------------------------------------------------------------ routing

type Handled = (Option<&'static str>, Option<HttpResponse>);

/// Routes outside `/api/v1`: discovery and the JWKS.
pub(crate) fn handle_root(w: &mut World, req: &Req) -> Handled {
    if matches(req, Method::Get, "/.well-known/openvireo-configuration").is_some() {
        return (Some("/.well-known/openvireo-configuration"), ok(200, &configuration()).ok());
    }
    if matches(req, Method::Get, "/.well-known/jwks.json").is_some() {
        return (Some("/.well-known/jwks.json"), ok(200, &w.auth.jwks()).ok());
    }
    (None, None)
}

/// Routes below `/api/v1`. Patterns use the contract's parameter names.
pub(crate) fn handle(w: &mut World, req: &Req) -> Handled {
    macro_rules! routes {
        ($( $m:ident $pat:literal => $f:expr ;)+) => {
            $(
                if let Some(p) = matches(req, Method::$m, $pat) {
                    let res: Res = $f(w, req, &p);
                    return (Some($pat), Some(res.unwrap_or_else(|e| e)));
                }
            )+
        };
    }
    routes! {
        Post "/auth/register/start" => register_start;
        Post "/auth/register/finish" => register_finish;
        Post "/auth/login/start" => login_start;
        Post "/auth/login/finish" => login_finish;
        Post "/auth/login/mfa" => login_mfa;
        Post "/auth/refresh" => refresh;
        Post "/auth/logout" => logout;
        Post "/auth/service-account" => sa_exchange;
        Post "/auth/recover/start" => recover_start;
        Post "/auth/recover/finish" => recover_finish;
        Get "/auth/recover/{token}" => recover_info;
        Get "/me" => me;
        Delete "/me" => schedule_deletion;
        Get "/me/deletion" => deletion_preview;
        Post "/me/deletion/cancel" => cancel_deletion;
        Post "/me/password/start" => password_start;
        Post "/me/password/finish" => password_finish;
        Post "/me/web-session" => web_session;
        Post "/me/email" => email_request;
        Post "/me/email/start" => email_start;
        Post "/me/email/finish" => email_finish;
        Post "/me/totp" => totp_start;
        Put "/me/totp" => totp_confirm;
        Delete "/me/totp" => totp_disable;
        Get "/me/recovery" => recovery_status;
        Post "/me/recovery/restore/start" => restore_start;
        Post "/me/recovery/restore/verify" => restore_verify;
        Post "/me/recovery/restore/finish" => restore_finish;
        Get "/users/lookup" => lookup_user;
        Get "/principals/{principal}/public-key" => public_key;
        Get "/devices" => list_devices;
        Delete "/devices/{id}" => revoke_device;
        Post "/orgs" => create_org;
        Get "/orgs/{org}" => get_org;
        Patch "/orgs/{org}" => update_org;
        Delete "/orgs/{org}" => delete_org;
        Get "/orgs/{org}/members" => list_members;
        Patch "/orgs/{org}/members/{user}" => set_member_role;
        Delete "/orgs/{org}/members/{user}" => remove_member;
        Post "/orgs/{org}/members/{user}/confirm" => confirm_member;
        Get "/orgs/{org}/invitations" => list_invitations;
        Post "/orgs/{org}/invitations" => invite;
        Delete "/orgs/{org}/invitations/{id}" => cancel_invitation;
        Post "/invitations/accept" => accept_invitation;
        Get "/orgs/{org}/service-accounts" => list_sas;
        Post "/orgs/{org}/service-accounts" => create_sa;
        Get "/orgs/{org}/audit" => org_audit;
        Get "/vaults" => list_vaults;
        Post "/vaults" => create_vault;
        Get "/vaults/{vault}" => get_vault;
        Patch "/vaults/{vault}" => rename_vault;
        Delete "/vaults/{vault}" => delete_vault;
        Post "/vaults/{vault}/owner" => transfer_vault;
        Get "/vaults/{vault}/access" => list_access;
        Post "/vaults/{vault}/access" => grant_access;
        Post "/vaults/{vault}/keys" => start_rotation;
        Post "/vaults/{vault}/keys/{version}/activate" => activate_key;
        Get "/service-accounts/{sa}" => get_sa;
        Patch "/service-accounts/{sa}" => update_sa;
        Delete "/service-accounts/{sa}" => delete_sa;
        Get "/service-accounts/{sa}/secrets" => list_secrets;
        Post "/service-accounts/{sa}/secrets" => issue_secret;
        Patch "/service-accounts/{sa}/secrets/{id}" => update_secret;
        Delete "/service-accounts/{sa}/secrets/{id}" => revoke_secret;
        Get "/shares" => list_shares;
        Post "/shares" => create_share;
        Put "/shares/{id}" => upload_share;
        Delete "/shares/{id}" => revoke_share;
        Get "/public/shares/{id}" => public_share;
        Post "/public/shares/{id}/open" => open_share;
        Get "/billing/apple/eligibility" => apple_eligibility;
        Post "/billing/apple/transactions" => apple_transaction;
    }
    (None, None)
}

// ------------------------------------------------------------------------------------ authentication

fn register_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: RegisterStartRequest = req.json()?;
    let email = norm_email(&b.email);
    if w.auth.users.contains(&email) {
        return Err(error(409, "conflict", "This email is taken"));
    }
    let (setup, response) = registration_response(w, &b.request)?;
    let user_id = w.uuid();
    let session_id = put_pending(w, Pending::Register { setup, email, user_id: user_id.clone() });
    ok(200, &RegisterStartResponse { session_id, response, user_id })
}

fn register_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: RegisterFinishRequest = req.json()?;
    let Some(Pending::Register { setup, email, user_id }) = take_pending(w, &b.session_id) else {
        return Err(expired());
    };
    if w.auth.users.contains(&email) {
        return Err(error(409, "conflict", "This email is taken"));
    }
    let rec = store_record(&setup, &b.record)?;
    let user = User {
        id: user_id,
        email: email.clone(),
        rec,
        kdf: b.kdf,
        keyset: b.keyset,
        totp_secret: None,
        pending_totp: None,
        fixed_totp: None,
    };
    w.auth.users.insert(email.clone(), user);
    session(w, &email, &b.device, 201)
}

fn login_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: LoginStartRequest = req.json()?;
    let email = norm_email(&b.email);
    let (rec, known) = match w.auth.users.get(&email) {
        Some(u) => (u.rec.clone(), true),
        None => (fake_record(w, &email)?, false),
    };
    let (state, ke2) = credential_response(w, &b.ke1, &rec, &email)?;
    let session_id = put_pending(w, Pending::Login { state, email: known.then_some(email) });
    ok(200, &LoginStartResponse { session_id, ke2 })
}

fn login_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: LoginFinishRequest = req.json()?;
    let wrong = || error(401, "unauthorized", "wrong email or password");
    let Some(Pending::Login { state, email }) = take_pending(w, &b.session_id) else { return Err(wrong()) };
    let Some(email) = email.filter(|_| user_auth(&state, &b.auth_u)) else { return Err(wrong()) };
    let u = w.auth.users.get(&email).ok_or_else(wrong)?;
    if u.totp_secret.is_some() || u.fixed_totp.is_some() {
        let mfa_token = format!("mfa-{}", w.uuid());
        let at = w.now_ms();
        w.auth.mfa.insert(mfa_token.clone(), Mfa { email, wrong: 0, at, device: b.device });
        return ok(200, &MfaChallenge { mfa_required: true, mfa_token, methods: Some(vec!["totp".into()]) });
    }
    session(w, &email, &b.device, 200)
}

fn login_mfa(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: LoginMfaRequest = req.json()?;
    let now = w.now_ms();
    let invalid = || error(401, "unauthorized", "The MFA token is invalid or expired");
    let m = w.auth.mfa.get(&b.mfa_token).filter(|m| now - m.at <= SESSION_MS).ok_or_else(invalid)?;
    let u = w.auth.users.get(&m.email).ok_or_else(invalid)?;
    if !totp_ok(w, u, &b.totp, None) {
        let m = w.auth.mfa.get_mut(&b.mfa_token).expect("exists");
        m.wrong += 1;
        if m.wrong >= 5 {
            w.auth.mfa.remove(&b.mfa_token);
        }
        return Err(error(401, "invalid_mfa", "The code is incorrect"));
    }
    let m = w.auth.mfa.remove(&b.mfa_token).expect("exists");
    session(w, &m.email, &m.device, 200)
}

fn refresh(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: RefreshRequest = req.json()?;
    let now = w.now_ms();
    let Some(r) = w.auth.refresh.get(&b.refresh_token) else {
        return Err(error(401, "unauthorized", "unknown refresh token"));
    };
    if now - r.last_used > REFRESH_LIFETIME_MS {
        w.auth.refresh.remove(&b.refresh_token);
        return Err(error(401, "session_expired", "The session expired"));
    }
    let (principal, device_id) = (r.principal.clone(), r.device_id.clone());
    if r.used {
        let replacement_unused = r.replacement.as_deref().and_then(|t| w.auth.refresh.get(t)).is_some_and(|n| !n.used);
        if r.rotated_at.is_some_and(|at| now - at <= REFRESH_GRACE_MS) && replacement_unused {
            // Grace period (SPEC §9): the lost replacement is revoked and a new one issued.
            if let Some(old) = r.replacement.clone() {
                w.auth.refresh.remove(&old);
            }
            let rt = new_refresh(w, &principal, &device_id);
            w.auth.refresh.get_mut(&b.refresh_token).expect("exists").replacement = Some(rt.clone());
            let access_token = issue(w, &principal, Some(&device_id));
            return ok(200, &TokenPair { access_token, refresh_token: rt, expires_in: w.auth.token_ttl_secs });
        }
        w.auth.refresh.retain(|_, x| x.device_id != device_id);
        return Err(error(401, "token_reused", "This refresh token was already used"));
    }
    let rt = new_refresh(w, &principal, &device_id);
    let r = w.auth.refresh.get_mut(&b.refresh_token).expect("exists");
    r.used = true;
    r.rotated_at = Some(now);
    r.replacement = Some(rt.clone());
    if let Some(d) = w.auth.devices.get_mut(&device_id) {
        d.last_seen_at = now;
    }
    let access_token = issue(w, &principal, Some(&device_id));
    ok(200, &TokenPair { access_token, refresh_token: rt, expires_in: w.auth.token_ttl_secs })
}

fn logout(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = caller(w, req, true)?;
    if let Some(dev) = c.dev {
        w.auth.refresh.retain(|_, r| r.device_id != dev);
    }
    Ok(empty(204))
}

fn sa_exchange(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: ServiceAccountExchangeRequest = req.json()?;
    let now = w.now_ms();
    let bad = || error(401, "unauthorized", "bad secret");
    let hash = sha256_hex(&from_b64u(&b.secret).map_err(|_| bad())?);
    let sa = w.auth.sas.get(&b.sa_id).ok_or_else(bad)?;
    let past = |e: &Option<String>| e.as_deref().and_then(parse_iso).is_some_and(|t| t <= now);
    if sa.disabled || past(&sa.expires_at) {
        return Err(bad());
    }
    let (sid, secret) = sa.secrets.iter().find(|(_, s)| s.hash == hash).ok_or_else(bad)?;
    if past(&secret.expires_at) {
        return Err(bad());
    }
    let (sid, wrapped_master, keyset) = (sid.to_string(), secret.wrapped_master.clone(), sa.keyset.clone());
    let sa = w.auth.sas.get_mut(&b.sa_id).expect("exists");
    sa.secrets.get_mut(&sid).expect("exists").last_used_at = Some(now);
    let access_token = issue(w, &format!("sa:{}", b.sa_id), None);
    ok(200, &ServiceAccountExchange { access_token, expires_in: w.auth.token_ttl_secs, wrapped_master, keyset })
}

// ------------------------------------------------------------------------------------ recovery (SPEC §18)

/// The approved reset behind a token, or the error the routes answer.
fn recovery(w: &World, token: &str) -> Result<String, HttpResponse> {
    let now = w.now_ms();
    let r = w.auth.recoveries.get(token).ok_or_else(|| error(404, "not_found", "unknown token"))?;
    if r.status == RecoveryStatus::Cancelled {
        return Err(error(410, "recovery_cancelled", "This reset was cancelled"));
    }
    if r.status != RecoveryStatus::Approved || now > r.expires_at {
        return Err(error(410, "session_expired", "This link was used or has expired"));
    }
    if now < r.not_before {
        let nb = iso(r.not_before);
        return Err(error_with(
            409,
            "recovery_not_ready",
            &format!("The link works from {nb}"),
            json!({ "not_before": nb }),
        ));
    }
    Ok(r.email.clone())
}

pub(crate) fn approve_reset(w: &mut World, email: &str, delay_secs: i64) -> String {
    let token = format!("ov_rc_{}", b64u(&w.random_bytes(32)));
    let now = w.now_ms();
    w.auth.recoveries.insert(
        token.clone(),
        Recovery {
            email: norm_email(email),
            not_before: now + delay_secs * 1000,
            expires_at: now + 72 * 3_600_000,
            status: RecoveryStatus::Approved,
        },
    );
    token
}

pub(crate) fn cancel_reset(w: &mut World, token: &str) {
    if let Some(r) = w.auth.recoveries.get_mut(token) {
        r.status = RecoveryStatus::Cancelled;
    }
}

fn recover_info(w: &mut World, _req: &Req, p: &Params) -> Res {
    let email = recovery(w, p.get("token"))?;
    let r = w.auth.recoveries.get(p.get("token")).expect("checked");
    let u = w.auth.users.get(&email).ok_or_else(|| error(404, "not_found", "no user"))?;
    let pr = format!("user:{}", u.id);
    let personal = w
        .auth
        .vaults
        .values()
        .filter(|v| !v.archived && v.owner_id.as_deref() == Some(u.id.as_str()) && v.access.contains(&pr))
        .filter(|v| v.access.len() == 1)
        .count() as i64;
    let all = w.auth.vaults.values().filter(|v| !v.archived && v.access.contains(&pr)).count() as i64;
    let sole: Vec<String> = w
        .auth
        .orgs
        .values()
        .filter(|o| {
            let admins: Vec<&str> = o
                .members
                .iter()
                .filter(|(_, m)| {
                    m.status == MemberStatus::Confirmed && matches!(m.role, OrgRole::Owner | OrgRole::Admin)
                })
                .map(|(k, _)| k)
                .collect();
            admins == [u.id.as_str()]
        })
        .map(|o| o.name.clone())
        .collect();
    ok(
        200,
        &RecoveryReset {
            email,
            not_before: iso(r.not_before),
            expires_at: iso(r.expires_at),
            archive_days: Some(30),
            archives: RecoveryArchives {
                personal_vaults: Some(personal),
                shared_grants: Some(all - personal),
                sole_admin_orgs: Some(sole),
            },
        },
    )
}

fn recover_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: RecoverStartRequest = req.json()?;
    recovery(w, &b.token)?;
    let (setup, response) = registration_response(w, &b.request)?;
    let session_id = put_pending(w, Pending::Recover { setup, token: b.token });
    ok(200, &OpaqueRegistrationResponse { session_id, response })
}

fn recover_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let b: RecoverFinishRequest = req.json()?;
    let Some(Pending::Recover { setup, token }) = take_pending(w, &b.session_id) else { return Err(expired()) };
    let email = recovery(w, &token)?;
    let rec = store_record(&setup, &b.record)?;
    let now = w.now_ms();
    let u = w.auth.users.get(&email).ok_or_else(|| error(404, "not_found", "no user"))?;
    let (user_id, pr) = (u.id.clone(), format!("user:{}", u.id));
    let mut archive = Archive {
        email: u.email.clone(),
        rec: u.rec.clone(),
        kdf: u.kdf.clone(),
        keyset: u.keyset.clone(),
        expires_at: now + 30 * 86_400_000,
        grants: vec![],
        failures: 0,
        locked: false,
    };
    for (id, v) in w.auth.vaults.iter_mut() {
        if v.archived {
            continue;
        }
        let Some(a) = v.access.get(&pr) else { continue };
        if let Some(sealed) = a.keys.get(&v.current) {
            archive.grants.push(VaultGrant {
                principal: pr.clone(),
                role: a.role.clone(),
                key_version: v.current,
                sealed_key: sealed.clone(),
                vault_id: id.to_string(),
            });
        }
        if v.owner_id.as_deref() == Some(user_id.as_str()) && v.access.len() == 1 {
            v.archived = true;
        }
        v.access.remove(&pr);
    }
    for o in w.auth.orgs.values_mut() {
        if let Some(m) = o.members.get_mut(&user_id).filter(|m| m.status == MemberStatus::Confirmed) {
            m.status = MemberStatus::Accepted;
        }
    }
    for sa in w.auth.sas.values_mut() {
        sa.master.remove(&pr);
    }
    w.auth.revoke_principal(&pr);
    w.auth.archives.insert(user_id.clone(), archive);
    let u = w.auth.users.get_mut(&email).expect("exists");
    u.rec = rec;
    u.kdf = b.kdf;
    u.keyset = b.keyset;
    u.totp_secret = None;
    u.fixed_totp = None;
    w.auth.recoveries.get_mut(&token).expect("exists").status = RecoveryStatus::Completed;
    session(w, &email, &b.device, 200)
}

fn recovery_status(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let body = match w.auth.archives.get(uid(&c.principal)) {
        Some(a) => RecoveryArchive {
            archived: true,
            email: Some(a.email.clone()),
            expires_at: Some(iso(a.expires_at)),
            vaults: Some(a.grants.len() as i64),
            locked: Some(a.locked),
        },
        None => RecoveryArchive { archived: false, email: None, expires_at: None, vaults: None, locked: None },
    };
    ok(200, &body)
}

/// The restore routes' checks: a recent token, an archive, not locked.
fn restore_caller(w: &World, req: &Req) -> Result<String, HttpResponse> {
    let c = user_caller(w, req, false)?;
    if w.now_ms() - c.iat_ms > w.auth.recent_token_ms {
        return Err(error(403, "forbidden", "Sign in again to restore"));
    }
    let user_id = uid(&c.principal).to_string();
    let a = w.auth.archives.get(&user_id).ok_or_else(|| error(404, "not_found", "no recovery archive"))?;
    if a.locked {
        return Err(error(403, "restore_locked", "Too many failed attempts"));
    }
    Ok(user_id)
}

fn restore_failed(w: &mut World, user_id: &str, res: HttpResponse) -> HttpResponse {
    if let Some(a) = w.auth.archives.get_mut(user_id) {
        a.failures += 1;
        if a.failures >= 10 {
            a.locked = true;
        }
    }
    res
}

fn restore_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let user_id = restore_caller(w, req)?;
    let b: RestoreStartRequest = req.json()?;
    let a = w.auth.archives.get(&user_id).expect("checked");
    let (rec, email) = (a.rec.clone(), a.email.clone());
    let (state, ke2) = credential_response(w, &b.ke1, &rec, &email)?;
    let session_id = put_pending(w, Pending::Restore { state, user_id, verified: None });
    ok(200, &RestoreStartResponse { session_id, ke2, email: Some(email) })
}

fn restore_verify(w: &mut World, req: &Req, _p: &Params) -> Res {
    let user_id = restore_caller(w, req)?;
    let b: RestoreVerifyRequest = req.json()?;
    let now = w.now_ms();
    let state = match w.auth.pending.get(&b.session_id) {
        Some(PendingRec { at, kind: Pending::Restore { state, user_id: u, verified: None } })
            if *u == user_id && now - at <= SESSION_MS =>
        {
            state.clone()
        }
        _ => return Err(expired()),
    };
    if !user_auth(&state, &b.auth_u) {
        let res = error(401, "unauthorized", "The old password is wrong");
        return Err(restore_failed(w, &user_id, res));
    }
    let a = w.auth.archives.get(&user_id).expect("checked");
    let pr = format!("user:{user_id}");
    let grants: Vec<VaultGrant> = a
        .grants
        .iter()
        .filter(|g| w.auth.vaults.get(&g.vault_id).is_some_and(|v| v.current == g.key_version))
        .map(|g| VaultGrant { principal: pr.clone(), ..g.clone() })
        .collect();
    let (kdf, keyset) = (a.kdf.clone(), a.keyset.clone());
    if let Some(PendingRec { kind: Pending::Restore { verified, .. }, .. }) = w.auth.pending.get_mut(&b.session_id) {
        *verified = Some(grants.clone());
    }
    ok(200, &RestoreVerified { session_id: b.session_id, kdf, keyset, grants })
}

fn restore_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let user_id = restore_caller(w, req)?;
    let b: RestoreFinishRequest = req.json()?;
    let verified = match w.auth.pending.get(&b.session_id) {
        Some(PendingRec { kind: Pending::Restore { user_id: u, verified: Some(v), .. }, .. }) if *u == user_id => {
            v.clone()
        }
        _ => return Err(expired()),
    };
    let pr = format!("user:{user_id}");
    let u = w.auth.user_by_id(&user_id).expect("caller exists");
    let a = w.auth.archives.get(&user_id).expect("checked");
    let key32 = |s: &str| from_b64u(s).ok().and_then(|v| <[u8; 32]>::try_from(v).ok());
    let proof_ok = match (key32(&u.keyset.enc_pk), key32(&u.keyset.sign_pk), from_b64u(&a.keyset.sign_pk)) {
        (Some(enc), Some(sign), Ok(old)) => {
            let proof = from_b64u(&b.proof).unwrap_or_default();
            ov_crypto::restore::verify_restore_proof(&proof, &user_id, &enc, &sign, &old)
        }
        _ => false,
    };
    if !proof_ok {
        let res = error(400, "invalid_proof", "The proof doesn't match the archived keys");
        return Err(restore_failed(w, &user_id, res));
    }
    for g in &b.grants {
        if g.principal != pr || !verified.iter().any(|v| v.vault_id == g.vault_id && v.key_version == g.key_version) {
            let res = error(400, "invalid_request", &format!("grant for {} was not returned by verify", g.vault_id));
            return Err(restore_failed(w, &user_id, res));
        }
    }
    let archived = w.auth.archives.remove(&user_id).expect("checked");
    let now = w.now_ms();
    for g in &b.grants {
        let Some(v) = w.auth.vaults.get_mut(&g.vault_id).filter(|v| v.current == g.key_version) else { continue };
        let role = archived.grants.iter().find(|a| a.vault_id == g.vault_id).map_or(g.role.clone(), |a| a.role.clone());
        let keys = BTreeMap::from([(g.key_version, g.sealed_key.clone())]);
        v.access.insert(pr.clone(), AccessRec { role, keys, granted_by: None, granted_at: now });
        v.archived = false;
    }
    w.auth.pending.remove(&b.session_id);
    Ok(empty(204))
}

// ------------------------------------------------------------------------------------ me

fn me(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, true)?;
    let id = uid(&c.principal);
    let u = w.auth.user_by_id(id).expect("checked");
    let orgs: Vec<MeOrg> = w
        .auth
        .orgs
        .iter()
        .filter_map(|(oid, o)| {
            let m = o.members.get(id)?;
            Some(MeOrg {
                id: oid.into(),
                name: o.name.clone(),
                role: m.role.clone(),
                status: m.status.clone(),
                plan: None,
                item_share_links: Some(o.policy.clone()),
            })
        })
        .collect();
    ok(
        200,
        &Me {
            id: u.id.clone(),
            email: u.email.clone(),
            name: None,
            kdf: u.kdf.clone(),
            keyset: u.keyset.clone(),
            mfa: MeMfa { totp: Some(u.totp_secret.is_some() || u.fixed_totp.is_some()) },
            plan: w.auth.plans.get(id).cloned(),
            orgs: Some(orgs),
            deletion_scheduled_for: w.auth.deletions.get(id).cloned(),
        },
    )
}

/// Each org the user is in and what deleting the account does to it (SPEC §23).
fn deletion_orgs(w: &World, user_id: &str) -> Vec<DeletionOrg> {
    w.auth
        .orgs
        .iter()
        .filter_map(|(id, o)| {
            let m = o.members.get(user_id)?;
            let others: Vec<(&str, &MemberRec)> =
                o.members.iter().filter(|(u, x)| *u != user_id && x.status == MemberStatus::Confirmed).collect();
            let owners =
                others.iter().filter(|(u, x)| x.role == OrgRole::Owner && !w.auth.deletions.contains(u)).count();
            let outcome = if m.role != OrgRole::Owner || m.status != MemberStatus::Confirmed || owners > 0 {
                DeletionOutcome::Leave
            } else if !others.is_empty() {
                DeletionOutcome::Blocked
            } else {
                DeletionOutcome::Delete
            };
            let members = if outcome == DeletionOutcome::Blocked {
                others
                    .iter()
                    .map(|(u, x)| DeletionMember {
                        id: (*u).into(),
                        email: w.auth.user_by_id(u).map(|u| u.email.clone()).unwrap_or_default(),
                        role: x.role.clone(),
                    })
                    .collect()
            } else {
                vec![]
            };
            Some(DeletionOrg { id: id.into(), name: o.name.clone(), role: m.role.clone(), outcome, members })
        })
        .collect()
}

fn deletion_preview(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, true)?;
    let id = uid(&c.principal);
    let orgs = deletion_orgs(w, id);
    let vaults: Vec<DeletionVault> = w
        .auth
        .vaults
        .iter()
        .filter(|(_, v)| v.owner_id.as_deref() == Some(id) && !v.archived)
        .map(|(vid, v)| DeletionVault {
            id: vid.into(),
            encrypted_name: v.encrypted_name.clone(),
            shared_with: v
                .access
                .iter()
                .filter(|(p, _)| *p != c.principal)
                .map(|(p, a)| DeletionShare { principal: p.into(), display: display(w, p), role: a.role.clone() })
                .collect(),
        })
        .collect();
    let subscription = w.auth.plans.get(id).and_then(|p| {
        let b = p.billing.as_ref()?;
        Some(DeletionSubscription {
            plan: p.id.clone()?,
            period_end: b.renews_at.clone().or_else(|| b.ends_at.clone()),
            source: Some(b.source.clone()),
            manage: Some(b.manage.clone()),
        })
    });
    let scheduled = w.auth.deletions.get(id).cloned();
    let blocked = orgs.iter().any(|o| o.outcome == DeletionOutcome::Blocked);
    ok(
        200,
        &DeletionPreview {
            would_erase_on: scheduled.clone().unwrap_or_else(|| iso(w.now_ms() + w.auth.deletion_days * 86_400_000)),
            scheduled_for: scheduled,
            vaults,
            orgs,
            subscription,
            share_links: w.auth.shares.values().filter(|s| s.owner == c.principal && s.ended.is_none()).count() as i64,
            blocked,
        },
    )
}

fn schedule_deletion(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    require_recent(w, &c)?;
    let id = uid(&c.principal).to_string();
    let email = w.auth.user_by_id(&id).expect("checked").email.clone();
    if str_of(&req.value(), "confirm").to_lowercase() != email {
        return Err(error(400, "confirm_mismatch", "Type your account email"));
    }
    let blocked: Vec<Value> = deletion_orgs(w, &id)
        .into_iter()
        .filter(|o| o.outcome == DeletionOutcome::Blocked)
        .map(|o| json!({ "id": o.id, "name": o.name }))
        .collect();
    if !blocked.is_empty() {
        return Err(error_with(409, "deletion_blocked", "blocked", json!({ "orgs": blocked })));
    }
    let now = w.now_ms();
    let at = iso(now + w.auth.deletion_days * 86_400_000);
    w.auth.deletions.insert(id, at.clone());
    w.auth.revoke_principal(&c.principal);
    for s in w.auth.shares.values_mut().filter(|s| s.owner == c.principal) {
        end_share(s, ShareEndReason::Revoked, now);
    }
    notify(w, vec![c.principal.clone()], json!({ "vault": null, "change": "deletion_scheduled", "at": at }));
    ok(202, &DeletionScheduled { scheduled_for: at })
}

fn cancel_deletion(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, true)?;
    require_recent(w, &c)?;
    if w.auth.deletions.remove(uid(&c.principal)).is_none() {
        return Err(error(409, "conflict", "not pending"));
    }
    Ok(empty(204))
}

fn password_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    require_recent(w, &c)?;
    let b: PasswordStartRequest = req.json()?;
    let (setup, response) = registration_response(w, &b.request)?;
    let session_id = put_pending(w, Pending::Password { setup, principal: c.principal });
    ok(200, &OpaqueRegistrationResponse { session_id, response })
}

fn password_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: PasswordFinishRequest = req.json()?;
    let Some(Pending::Password { setup, principal }) = take_pending(w, &b.session_id) else { return Err(expired()) };
    if principal != c.principal {
        return Err(expired());
    }
    let u = w.auth.user_by_id(uid(&principal)).expect("checked");
    let same = |k: &WrappedKeyset| (k.enc_pk.clone(), k.sign_pk.clone(), k.sig.clone());
    if same(&b.keyset) != same(&u.keyset) {
        return Err(error(400, "invalid_request", "keyset must keep the same public keys"));
    }
    let rec = store_record(&setup, &b.record)?;
    let u = w.auth.user_by_id_mut(uid(&principal)).expect("checked");
    u.rec = rec;
    u.kdf = b.kdf;
    u.keyset = b.keyset;
    // Other devices are signed out.
    let dev = c.dev.unwrap_or_default();
    w.auth.refresh.retain(|_, r| r.principal != principal || r.device_id == dev);
    Ok(empty(204))
}

fn web_session(w: &mut World, req: &Req, _p: &Params) -> Res {
    user_caller(w, req, false)?;
    let code = format!("ov_ws_{}", w.uuid());
    ok(200, &WebSession { code, expires_in: 60 })
}

fn email_request(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    require_recent(w, &c)?;
    let b: EmailChangeRequest = req.json()?;
    let email = norm_email(&b.email);
    if w.auth.users.contains(&email) {
        return Err(error(409, "conflict", "Another account uses this email"));
    }
    let n = u32::from_le_bytes(w.random_bytes(4).try_into().expect("4 bytes")) % 100_000_000;
    w.auth.email_codes.insert(uid(&c.principal), (email, format!("{n:08}")));
    ok(202, &EmailCodeSent { expires_in: Some(1800) })
}

fn email_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: EmailStartRequest = req.json()?;
    let id = uid(&c.principal).to_string();
    let Some((email, code)) = w.auth.email_codes.get(&id).cloned().filter(|(e, _)| *e == norm_email(&b.email)) else {
        return Err(error(410, "session_expired", "Ask for a new code"));
    };
    if code != b.code {
        return Err(error(400, "invalid_code", "The code is incorrect"));
    }
    w.auth.email_codes.remove(&id);
    let (setup, response) = registration_response(w, &b.request)?;
    let session_id = put_pending(w, Pending::Email { setup, principal: c.principal, email });
    ok(200, &OpaqueRegistrationResponse { session_id, response })
}

fn email_finish(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: EmailFinishRequest = req.json()?;
    let Some(Pending::Email { setup, principal, email }) = take_pending(w, &b.session_id) else {
        return Err(expired());
    };
    if principal != c.principal {
        return Err(expired());
    }
    let rec = store_record(&setup, &b.record)?;
    let old = w.auth.user_by_id(uid(&principal)).expect("checked").email.clone();
    let mut u = w.auth.users.remove(&old).expect("exists");
    u.rec = rec;
    u.email.clone_from(&email);
    w.auth.users.insert(email, u);
    Ok(empty(204))
}

fn totp_start(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let secret = base32(&w.random_bytes(20));
    let u = w.auth.user_by_id_mut(uid(&c.principal)).expect("checked");
    u.pending_totp = Some(secret.clone());
    let otpauth_uri =
        format!("otpauth://totp/OpenVireo:{}?secret={secret}&issuer=OpenVireo", u.email.replace('@', "%40"));
    ok(200, &TotpEnrolment { secret, otpauth_uri })
}

fn totp_confirm(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: TotpCodeRequest = req.json()?;
    let u = w.auth.user_by_id(uid(&c.principal)).expect("checked");
    let Some(secret) = u.pending_totp.clone() else {
        return Err(error(409, "conflict", "Start the enrolment first"));
    };
    if !totp_ok(w, u, &b.totp, Some(&secret)) {
        return Err(error(400, "invalid_mfa", "The code is incorrect"));
    }
    let u = w.auth.user_by_id_mut(uid(&c.principal)).expect("checked");
    u.totp_secret = Some(secret);
    u.pending_totp = None;
    Ok(empty(204))
}

fn totp_disable(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: TotpCodeRequest = req.json()?;
    let u = w.auth.user_by_id(uid(&c.principal)).expect("checked");
    if u.totp_secret.is_none() && u.fixed_totp.is_none() {
        return Err(error(409, "conflict", "TOTP is off"));
    }
    if !totp_ok(w, u, &b.totp, None) {
        return Err(error(400, "invalid_mfa", "The code is incorrect"));
    }
    let u = w.auth.user_by_id_mut(uid(&c.principal)).expect("checked");
    u.totp_secret = None;
    u.fixed_totp = None;
    Ok(empty(204))
}

fn lookup_user(w: &mut World, req: &Req, _p: &Params) -> Res {
    caller(w, req, false)?;
    let email = norm_email(req.query("email").unwrap_or_default());
    let u = w.auth.users.get(&email).ok_or_else(|| error(404, "not_found", "no such user"))?;
    ok(200, &public_of(w, &format!("user:{}", u.id)).expect("exists"))
}

fn public_key(w: &mut World, req: &Req, p: &Params) -> Res {
    caller(w, req, false)?;
    match public_of(w, p.get("principal")) {
        Some(k) => ok(200, &k),
        None => Err(error(404, "not_found", "no such principal")),
    }
}

fn list_devices(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let devices: Vec<Device> = w
        .auth
        .devices
        .iter()
        .filter(|(_, d)| d.user_id == uid(&c.principal))
        .map(|(id, d)| Device {
            id: id.into(),
            name: d.name.clone(),
            platform: d.platform.clone(),
            created_at: iso(d.created_at),
            last_seen_at: iso(d.last_seen_at),
            current: c.dev.as_deref() == Some(id),
        })
        .collect();
    ok(200, &DeviceList { devices })
}

fn revoke_device(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let id = p.get("id");
    if !w.auth.devices.get(id).is_some_and(|d| d.user_id == uid(&c.principal)) {
        return Err(error(404, "not_found", "no such device"));
    }
    w.auth.devices.remove(id);
    w.auth.refresh.retain(|_, r| r.device_id != id);
    Ok(empty(204))
}

// ------------------------------------------------------------------------------------ orgs

fn create_org(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: CreateOrgRequest = req.json()?;
    let id = w.uuid();
    let mut members = Table::default();
    members.insert(uid(&c.principal), MemberRec { role: OrgRole::Owner, status: MemberStatus::Confirmed });
    let org = OrgRec {
        name: b.name,
        created_at: w.now_ms(),
        policy: ShareLinkPolicy::On,
        members,
        invitations: Table::default(),
        audit: vec![],
    };
    w.auth.orgs.insert(id.clone(), org);
    audit(w, &id, &c.principal, "org.create", None);
    ok(201, &org_json(w, &id, &c.principal).expect("member"))
}

fn get_org(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    org_json(w, p.get("org"), &c.principal).map_or_else(|| Err(error(404, "not_found", "no such org")), |o| ok(200, &o))
}

fn update_org(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    org_admin(w, org, &c)?;
    let b: UpdateOrgRequest = req.json()?;
    let now = w.now_ms();
    let o = w.auth.orgs.get_mut(org).expect("checked");
    if let Some(n) = b.name {
        o.name = n;
    }
    if let Some(policy) = b.item_share_links {
        o.policy = policy.clone();
        if policy == ShareLinkPolicy::Off {
            let org_vaults: Vec<String> = w
                .auth
                .vaults
                .iter()
                .filter(|(_, v)| v.org_id.as_deref() == Some(org))
                .map(|(k, _)| k.to_string())
                .collect();
            for s in w.auth.shares.values_mut() {
                if s.vault_id.as_ref().is_some_and(|v| org_vaults.contains(v)) {
                    end_share(s, ShareEndReason::Policy, now);
                }
            }
        }
    }
    audit(w, org, &c.principal, "org.update", None);
    ok(200, &org_json(w, org, &c.principal).expect("member"))
}

fn delete_org(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    let role = w.auth.orgs.get(org).and_then(|o| o.members.get(uid(&c.principal))).map(|m| m.role.clone());
    match role {
        None => return Err(error(404, "not_found", "no such org")),
        Some(OrgRole::Owner) => {}
        Some(_) => return Err(error(403, "forbidden", "owners only")),
    }
    let o = w.auth.orgs.remove(org).expect("checked");
    let vaults: Vec<String> =
        w.auth.vaults.iter().filter(|(_, v)| v.org_id.as_deref() == Some(org)).map(|(k, _)| k.to_string()).collect();
    for v in &vaults {
        w.auth.vaults.remove(v);
        sync::delete(w, &format!("vaults/{v}"));
    }
    w.auth.sas.retain(|_, sa| sa.org_id != org);
    let subjects = o.members.keys().map(|u| format!("user:{u}")).collect();
    notify(w, subjects, json!({ "vault": null, "change": "org" }));
    Ok(empty(204))
}

fn list_members(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let o = w.auth.orgs.get(p.get("org")).filter(|o| o.members.contains(uid(&c.principal)));
    let o = o.ok_or_else(|| error(404, "not_found", "no such org"))?;
    let members = o.members.iter().map(|(u, m)| member_json(w, u, m)).collect();
    ok(200, &MemberList { members })
}

fn store_sa_master_keys(w: &mut World, keys: Option<Vec<SaMasterGrant>>) {
    for k in keys.unwrap_or_default() {
        if let Some(sa) = w.auth.sas.get_mut(&k.sa_id) {
            sa.master.insert(k.principal, k.sealed_key);
        }
    }
}

fn set_member_role(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let (org, user) = (p.get("org"), p.get("user"));
    org_admin(w, org, &c)?;
    let b: SetMemberRoleRequest = req.json()?;
    let caller_owner =
        w.auth.orgs.get(org).and_then(|o| o.members.get(uid(&c.principal))).is_some_and(|m| m.role == OrgRole::Owner);
    if b.role == OrgRole::Owner && !caller_owner {
        return Err(error(403, "forbidden", "only owners create owners"));
    }
    let m = w.auth.orgs.get_mut(org).and_then(|o| o.members.get_mut(user));
    let m = m.ok_or_else(|| error(404, "not_found", "no such member"))?;
    m.role = b.role.clone();
    if b.role == OrgRole::Member {
        let pr = format!("user:{user}");
        for sa in w.auth.sas.values_mut().filter(|sa| sa.org_id == org) {
            sa.master.remove(&pr);
        }
    }
    store_sa_master_keys(w, b.sa_master_keys);
    audit(w, org, &c.principal, "org.member.role", Some(&format!("user:{user}")));
    notify(w, vec![format!("user:{user}")], json!({ "vault": null, "change": "org" }));
    let m = w.auth.orgs.get(org).and_then(|o| o.members.get(user)).expect("exists");
    ok(200, &member_json(w, user, m))
}

fn remove_member(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let (org, user) = (p.get("org"), p.get("user"));
    if uid(&c.principal) != user {
        org_admin(w, org, &c)?;
    }
    let o = w.auth.orgs.get_mut(org).ok_or_else(|| error(404, "not_found", "no such org"))?;
    if o.members.remove(user).is_none() {
        return Err(error(404, "not_found", "no such member"));
    }
    let pr = format!("user:{user}");
    for v in w.auth.vaults.values_mut().filter(|v| v.org_id.as_deref() == Some(org)) {
        if v.access.remove(&pr).is_some() {
            v.rotation_required = true;
        }
    }
    for sa in w.auth.sas.values_mut().filter(|sa| sa.org_id == org) {
        sa.master.remove(&pr);
    }
    audit(w, org, &c.principal, "org.member.remove", Some(&pr));
    notify(w, vec![pr], json!({ "vault": null, "change": "org" }));
    Ok(empty(204))
}

fn confirm_member(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let (org, user) = (p.get("org"), p.get("user"));
    org_admin(w, org, &c)?;
    let b: ConfirmMemberRequest = req.json()?;
    if !w.auth.orgs.get(org).is_some_and(|o| o.members.contains(user)) {
        return Err(error(404, "not_found", "no such member"));
    }
    let grants = b.grants.unwrap_or_default();
    for g in &grants {
        let v = w.auth.vaults.get(&g.vault_id).filter(|v| v.org_id.as_deref() == Some(org));
        let Some(v) = v else { return Err(error(400, "invalid_request", "not an org vault")) };
        if g.principal != format!("user:{user}") {
            return Err(error(400, "invalid_request", "grants must be sealed to the member"));
        }
        if g.key_version != v.current {
            return Err(error(409, "conflict", "not current"));
        }
    }
    let now = w.now_ms();
    for g in &grants {
        let v = w.auth.vaults.get_mut(&g.vault_id).expect("checked");
        let keys = BTreeMap::from([(g.key_version, g.sealed_key.clone())]);
        let rec = AccessRec { role: g.role.clone(), keys, granted_by: Some(c.principal.clone()), granted_at: now };
        v.access.insert(g.principal.clone(), rec);
    }
    store_sa_master_keys(w, b.sa_master_keys);
    let o = w.auth.orgs.get_mut(org).expect("checked");
    o.members.get_mut(user).expect("checked").status = MemberStatus::Confirmed;
    let pr = format!("user:{user}");
    audit(w, org, &c.principal, "org.member.confirm", Some(&pr));
    for g in &grants {
        notify(w, vec![pr.clone()], json!({ "vault": g.vault_id, "change": "granted" }));
    }
    let m = w.auth.orgs.get(org).and_then(|o| o.members.get(user)).expect("exists");
    ok(200, &member_json(w, user, m))
}

fn invitation_json(id: &str, i: &InvRec) -> Invitation {
    Invitation {
        id: id.into(),
        email: i.email.clone(),
        role: i.role.clone(),
        expires_at: iso(i.expires_at),
        invited_by: i.invited_by.clone(),
    }
}

fn list_invitations(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    org_admin(w, p.get("org"), &c)?;
    let o = w.auth.orgs.get(p.get("org")).expect("checked");
    let invitations = o.invitations.iter().map(|(id, i)| invitation_json(id, i)).collect();
    ok(200, &InvitationList { invitations })
}

fn invite(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    org_admin(w, org, &c)?;
    let b: InviteRequest = req.json()?;
    let id = w.uuid();
    let token = format!("ov_inv_{}", b64u(&w.random_bytes(24)));
    let rec = InvRec {
        email: norm_email(&b.email),
        role: b.role,
        expires_at: w.now_ms() + 7 * 86_400_000,
        invited_by: c.principal.clone(),
        token,
    };
    let out = invitation_json(&id, &rec);
    w.auth.orgs.get_mut(org).expect("checked").invitations.insert(id, rec);
    audit(w, org, &c.principal, "org.invite", Some(&out.email));
    ok(201, &out)
}

fn cancel_invitation(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    org_admin(w, p.get("org"), &c)?;
    let o = w.auth.orgs.get_mut(p.get("org")).expect("checked");
    match o.invitations.remove(p.get("id")) {
        Some(_) => Ok(empty(204)),
        None => Err(error(404, "not_found", "no such invitation")),
    }
}

/// The `(org, invitation id)` of an invitation token.
fn find_invitation(w: &World, token: &str) -> Option<(String, String)> {
    w.auth.orgs.iter().find_map(|(oid, o)| {
        o.invitations.iter().find(|(_, i)| i.token == token).map(|(iid, _)| (oid.to_string(), iid.to_string()))
    })
}

pub(crate) fn invitation_token(w: &World, org: &str, email: &str) -> Option<String> {
    let email = norm_email(email);
    w.auth.orgs.get(org)?.invitations.values().find(|i| i.email == email).map(|i| i.token.clone())
}

fn accept_invitation(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: AcceptInvitationRequest = req.json()?;
    let (org, iid) = find_invitation(w, &b.token).ok_or_else(|| error(404, "not_found", "unknown invitation"))?;
    let user_id = uid(&c.principal).to_string();
    let email = w.auth.user_by_id(&user_id).expect("checked").email.clone();
    let now = w.now_ms();
    let o = w.auth.orgs.get_mut(&org).expect("found");
    let inv = o.invitations.get(&iid).expect("found");
    if inv.expires_at <= now {
        return Err(error(410, "gone", "This invitation has expired"));
    }
    if inv.email != email {
        return Err(error(403, "forbidden", "This invitation is for another email"));
    }
    let inv = o.invitations.remove(&iid).expect("found");
    o.members.insert(user_id.clone(), MemberRec { role: inv.role, status: MemberStatus::Accepted });
    audit(w, &org, &c.principal, "org.invite.accept", None);
    let admins: Vec<String> = w
        .auth
        .orgs
        .get(&org)
        .expect("found")
        .members
        .iter()
        .filter(|(_, m)| m.status == MemberStatus::Confirmed && matches!(m.role, OrgRole::Owner | OrgRole::Admin))
        .map(|(u, _)| format!("user:{u}"))
        .collect();
    notify(w, admins, json!({ "vault": null, "change": "org" }));
    let m = w.auth.orgs.get(&org).and_then(|o| o.members.get(&user_id)).expect("exists");
    ok(200, &member_json(w, &user_id, m))
}

fn org_audit(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    org_admin(w, org, &c)?;
    let limit = req.query("limit").and_then(|l| l.parse::<usize>().ok()).unwrap_or(50).clamp(1, 500);
    let o = w.auth.orgs.get(org).expect("checked");
    let mut events: Vec<&AuditEvent> = o.audit.iter().rev().collect();
    if let Some(before) = req.query("before") {
        let i = events.iter().position(|e| e.id == before).map_or(events.len(), |i| i + 1);
        events.drain(..i);
    }
    let next = (events.len() > limit).then(|| events[limit - 1].id.clone());
    let events = events.into_iter().take(limit).cloned().collect();
    ok(200, &AuditPage { events, next })
}

// ------------------------------------------------------------------------------------ vaults

fn list_vaults(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vaults = w
        .auth
        .vaults
        .iter()
        .filter(|(_, v)| !v.archived && v.access.contains(&c.principal))
        .filter_map(|(id, _)| vault_json(w, id, &c.principal))
        .collect();
    ok(200, &VaultList { vaults })
}

fn create_vault(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let b: CreateVaultRequest = req.json()?;
    if !b.grants.iter().any(|g| g.principal == c.principal) {
        return Err(error(400, "invalid_request", "the caller must be one of the grantees"));
    }
    if w.auth.vaults.contains(&b.id) {
        return Err(error(409, "conflict", "This vault id is taken"));
    }
    if let Some(org) = &b.org_id {
        if !is_admin(w, org, &c.principal) {
            return Err(error(403, "forbidden", "only owners and admins create org vaults"));
        }
        let missing: Vec<String> = w
            .auth
            .orgs
            .get(org)
            .expect("checked")
            .members
            .iter()
            .filter(|(_, m)| m.status == MemberStatus::Confirmed && matches!(m.role, OrgRole::Owner | OrgRole::Admin))
            .map(|(u, _)| format!("user:{u}"))
            .filter(|p| !b.grants.iter().any(|g| &g.principal == p && g.role == VaultRole::Manage))
            .collect();
        if !missing.is_empty() {
            return Err(error(400, "invalid_request", &format!("missing manage grants for {}", missing.join(", "))));
        }
    }
    let now = w.now_ms();
    let mut access = Table::default();
    for g in &b.grants {
        let keys = BTreeMap::from([(g.key_version, g.sealed_key.clone())]);
        access.insert(
            g.principal.clone(),
            AccessRec { role: g.role.clone(), keys, granted_by: Some(c.principal.clone()), granted_at: now },
        );
    }
    let owner_id = if b.org_id.is_some() { None } else { Some(uid(&c.principal).to_string()) };
    let rec = VaultRec {
        org_id: b.org_id.clone(),
        owner_id,
        encrypted_name: b.encrypted_name,
        current: 1,
        pending: None,
        pending_since: 0,
        access,
        rotation_required: false,
        archived: false,
        created_at: now,
    };
    w.auth.vaults.insert(b.id.clone(), rec);
    if let Some(org) = &b.org_id {
        audit(w, org, &c.principal, "vault.create", Some(&b.id));
    }
    let others: Vec<String> = b.grants.iter().map(|g| g.principal.clone()).filter(|p| *p != c.principal).collect();
    if !others.is_empty() {
        notify(w, others, json!({ "vault": b.id, "change": "granted" }));
    }
    vault_res(w, &b.id, &c.principal, 201)
}

/// The vault and the caller's role on it; 404 when the caller has no access.
fn vault_role(w: &World, vault: &str, principal: &str) -> Result<VaultRole, HttpResponse> {
    w.auth
        .vaults
        .get(vault)
        .filter(|v| !v.archived)
        .and_then(|v| v.access.get(principal))
        .map(|a| a.role.clone())
        .ok_or_else(|| error(404, "not_found", "no such vault"))
}

fn require_manage(w: &World, vault: &str, principal: &str) -> Result<(), HttpResponse> {
    if vault_role(w, vault, principal)? != VaultRole::Manage {
        return Err(error(403, "forbidden", "manage access needed"));
    }
    Ok(())
}

fn get_vault(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    vault_role(w, p.get("vault"), &c.principal)?;
    vault_res(w, p.get("vault"), &c.principal, 200)
}

fn rename_vault(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    require_manage(w, vault, &c.principal)?;
    let b: RenameVaultRequest = req.json()?;
    w.auth.vaults.get_mut(vault).expect("checked").encrypted_name = b.encrypted_name;
    vault_res(w, vault, &c.principal, 200)
}

fn delete_vault(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    require_manage(w, vault, &c.principal)?;
    let v = w.auth.vaults.remove(vault).expect("checked");
    let now = w.now_ms();
    for s in w.auth.shares.values_mut().filter(|s| s.vault_id.as_deref() == Some(vault)) {
        end_share(s, ShareEndReason::AccessLost, now);
    }
    let others: Vec<String> = v.access.keys().filter(|p| *p != c.principal).map(str::to_string).collect();
    if !others.is_empty() {
        notify(w, others, json!({ "vault": vault, "change": "revoked" }));
    }
    Ok(empty(204))
}

fn transfer_vault(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    vault_role(w, vault, &c.principal)?;
    let b: TransferVaultRequest = req.json()?;
    let v = w.auth.vaults.get_mut(vault).expect("checked");
    if v.org_id.is_some() {
        return Err(error(400, "invalid_request", "org vault"));
    }
    if v.owner_id.as_deref() != Some(uid(&c.principal)) {
        return Err(error(403, "forbidden", "not the owner"));
    }
    let current = v.current;
    let Some(a) = v.access.get_mut(&b.principal).filter(|a| a.keys.contains_key(&current)) else {
        return Err(error(409, "not_a_member", "They must already have access"));
    };
    a.role = VaultRole::Manage;
    v.owner_id = Some(uid(&b.principal).to_string());
    v.access.remove(&c.principal);
    v.rotation_required = true;
    notify(w, vec![b.principal.clone()], json!({ "vault": vault, "change": "granted" }));
    vault_res(w, vault, &b.principal, 200)
}

fn list_access(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    vault_role(w, vault, &c.principal)?;
    let v = w.auth.vaults.get(vault).expect("checked");
    let access = v
        .access
        .iter()
        .map(|(pr, a)| VaultAccess {
            principal: pr.into(),
            role: a.role.clone(),
            key_version: a.keys.keys().max().copied().unwrap_or(v.current),
            display: display(w, pr),
            granted_by: a.granted_by.clone(),
            granted_at: Some(iso(a.granted_at)),
        })
        .collect();
    ok(200, &VaultAccessList { access })
}

fn grant_access(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    require_manage(w, vault, &c.principal)?;
    let b: GrantAccessRequest = req.json()?;
    let now = w.now_ms();
    let v = w.auth.vaults.get_mut(vault).expect("checked");
    if b.grants.iter().any(|g| g.key_version != v.current) {
        return Err(error(409, "conflict", "not current"));
    }
    for g in &b.grants {
        let keys = BTreeMap::from([(g.key_version, g.sealed_key.clone())]);
        let rec = AccessRec { role: g.role.clone(), keys, granted_by: Some(c.principal.clone()), granted_at: now };
        v.access.insert(g.principal.clone(), rec);
    }
    if let Some(org) = v.org_id.clone() {
        audit(w, &org, &c.principal, "vault.access.grant", Some(vault));
    }
    let subjects = b.grants.iter().map(|g| g.principal.clone()).collect();
    notify(w, subjects, json!({ "vault": vault, "change": "granted" }));
    ok(200, &json!({}))
}

fn start_rotation(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    require_manage(w, vault, &c.principal)?;
    let b: StartRotationRequest = req.json()?;
    let now = w.now_ms();
    let v = w.auth.vaults.get_mut(vault).expect("checked");
    if let Some(p) = v.pending {
        // A pending rotation older than 24 hours is abandoned (SPEC §7), as the auth server does
        if now - v.pending_since <= 24 * 3_600_000 {
            return Err(error(409, "conflict", "Another rotation is pending"));
        }
        for a in v.access.values_mut() {
            a.keys.remove(&p);
        }
        v.pending = None;
    }
    if b.key_version != v.current + 1 {
        return Err(error(409, "conflict", "key_version must be current_key_version + 1"));
    }
    let removed = b.remove.unwrap_or_default();
    for r in &removed {
        v.access.remove(r);
    }
    for g in &b.grants {
        if let Some(a) = v.access.get_mut(&g.principal) {
            a.keys.insert(g.key_version, g.sealed_key.clone());
        }
    }
    v.pending = Some(b.key_version);
    v.pending_since = now;
    let remaining: Vec<String> = v.access.keys().map(str::to_string).collect();
    if !removed.is_empty() {
        notify(w, removed, json!({ "vault": vault, "change": "revoked" }));
    }
    notify(w, remaining, json!({ "vault": vault, "change": "rotating" }));
    Ok(empty(202))
}

fn activate_key(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let vault = p.get("vault");
    require_manage(w, vault, &c.principal)?;
    let n: i64 = p.get("version").parse().map_err(|_| error(400, "invalid_request", "bad version"))?;
    let v = w.auth.vaults.get_mut(vault).expect("checked");
    if v.pending != Some(n) {
        return Err(error(409, "conflict", "no such pending key version"));
    }
    v.current = n;
    v.pending = None;
    v.rotation_required = false;
    for a in v.access.values_mut() {
        a.keys.retain(|k, _| *k >= n);
    }
    let subjects = v.access.keys().map(str::to_string).collect();
    notify(w, subjects, json!({ "vault": vault, "change": "rotated" }));
    Ok(empty(204))
}

// ------------------------------------------------------------------------------------ service accounts

fn list_sas(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    if !w.auth.orgs.get(org).is_some_and(|o| o.members.contains(uid(&c.principal))) {
        return Err(error(404, "not_found", "no such org"));
    }
    let service_accounts = w
        .auth
        .sas
        .iter()
        .filter(|(_, sa)| sa.org_id == org)
        .filter_map(|(id, _)| sa_json(w, id, &c.principal))
        .collect();
    ok(200, &ServiceAccountList { service_accounts })
}

fn create_sa(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let org = p.get("org");
    org_admin(w, org, &c)?;
    let b: CreateServiceAccountRequest = req.json()?;
    if w.auth.sas.contains(&b.id) {
        return Err(error(409, "conflict", "This id is taken"));
    }
    let now = w.now_ms();
    let mut master = Table::default();
    for m in b.master_keys {
        master.insert(m.principal, m.sealed_key);
    }
    let mut secrets = Table::default();
    secrets.insert(b.secret.id.clone(), secret_rec(b.secret, now));
    let sa = SaRec {
        org_id: org.into(),
        name: b.name,
        keyset: b.keyset,
        master,
        secrets,
        expires_at: b.expires_at,
        disabled: false,
        created_by: c.principal.clone(),
        created_at: now,
    };
    w.auth.sas.insert(b.id.clone(), sa);
    audit(w, org, &c.principal, "sa.create", Some(&format!("sa:{}", b.id)));
    ok(201, &sa_json(w, &b.id, &c.principal).expect("exists"))
}

fn secret_rec(s: NewSaSecret, now: i64) -> SecretRec {
    SecretRec {
        hash: s.secret_hash,
        prefix: s.prefix,
        name: s.name,
        wrapped_master: s.wrapped_master,
        created_at: now,
        last_used_at: None,
        expires_at: s.expires_at,
    }
}

/// The SA, for a caller who is an owner or admin of its org.
fn sa_admin(w: &World, req: &Req, sa: &str) -> Result<Caller, HttpResponse> {
    let c = caller(w, req, false)?;
    let org = w.auth.sas.get(sa).map(|s| s.org_id.clone()).ok_or_else(|| error(404, "not_found", "no such SA"))?;
    org_admin(w, &org, &c)?;
    Ok(c)
}

fn get_sa(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let sa = p.get("sa");
    let visible = w.auth.sas.get(sa).is_some_and(|s| {
        w.auth.orgs.get(&s.org_id).is_some_and(|o| o.members.contains(uid(&c.principal)))
            || c.principal == format!("sa:{sa}")
    });
    if !visible {
        return Err(error(404, "not_found", "no such SA"));
    }
    ok(200, &sa_json(w, sa, &c.principal).expect("exists"))
}

fn update_sa(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    let c = sa_admin(w, req, sa)?;
    let b: UpdateServiceAccountRequest = req.json()?;
    let s = w.auth.sas.get_mut(sa).expect("checked");
    if let Some(n) = b.name {
        s.name = n;
    }
    if let Some(e) = b.expires_at {
        s.expires_at = e;
    }
    if let Some(d) = b.disabled {
        s.disabled = d;
    }
    ok(200, &sa_json(w, sa, &c.principal).expect("exists"))
}

fn delete_sa(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    let c = sa_admin(w, req, sa)?;
    let s = w.auth.sas.remove(sa).expect("checked");
    let pr = format!("sa:{sa}");
    for v in w.auth.vaults.values_mut() {
        if v.access.remove(&pr).is_some() {
            v.rotation_required = true;
        }
    }
    w.auth.revoke_principal(&pr);
    audit(w, &s.org_id, &c.principal, "sa.delete", Some(&pr));
    Ok(empty(204))
}

fn list_secrets(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    sa_admin(w, req, sa)?;
    let secrets = w.auth.sas.get(sa).expect("checked").secrets.iter().map(|(id, s)| secret_json(s, id)).collect();
    ok(200, &SaSecretList { secrets })
}

fn issue_secret(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    sa_admin(w, req, sa)?;
    let b: NewSaSecret = req.json()?;
    let now = w.now_ms();
    w.auth.sas.get_mut(sa).expect("checked").secrets.insert(b.id.clone(), secret_rec(b, now));
    ok(201, &json!({}))
}

fn update_secret(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    let c = sa_admin(w, req, sa)?;
    let b: UpdateSaSecretRequest = req.json()?;
    let org = w.auth.sas.get(sa).expect("checked").org_id.clone();
    let s = w.auth.sas.get_mut(sa).expect("checked").secrets.get_mut(p.get("id"));
    let s = s.ok_or_else(|| error(404, "not_found", "no such secret"))?;
    s.expires_at = b.expires_at;
    let out = secret_json(s, p.get("id"));
    audit(w, &org, &c.principal, "sa.secret.update", Some(p.get("id")));
    ok(200, &out)
}

fn revoke_secret(w: &mut World, req: &Req, p: &Params) -> Res {
    let sa = p.get("sa");
    sa_admin(w, req, sa)?;
    match w.auth.sas.get_mut(sa).expect("checked").secrets.remove(p.get("id")) {
        Some(_) => Ok(empty(204)),
        None => Err(error(404, "not_found", "no such secret")),
    }
}

// ------------------------------------------------------------------------------------ share links (SPEC §22)

fn list_shares(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let shares = w
        .auth
        .shares
        .iter()
        .rev()
        .filter(|(_, s)| s.owner == c.principal && (s.ct.is_some() || s.ended.is_some()))
        .map(|(id, s)| share_json(id, s))
        .collect();
    ok(200, &ShareList { shares })
}

fn create_share(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = caller(w, req, false)?;
    if !c.principal.starts_with("user:") {
        return Err(error(403, "forbidden", "users only"));
    }
    let b: CreateShareRequest = req.json()?;
    if let Some(v) = &b.vault_id {
        let role = vault_role(w, v, &c.principal).map_err(|_| error(404, "not_found", "Vault not found"))?;
        let org = w.auth.vaults.get(v).and_then(|v| v.org_id.clone());
        match org.and_then(|o| w.auth.orgs.get(&o)).map(|o| o.policy.clone()) {
            Some(ShareLinkPolicy::Off) => return Err(error(403, "forbidden", "Share links are off for this org")),
            Some(ShareLinkPolicy::Managers) if role != VaultRole::Manage => {
                return Err(error(403, "forbidden", "Only managers can share from this vault"));
            }
            _ => {}
        }
    }
    if !(3600..=30 * 86_400).contains(&b.expires_in) {
        return Err(error(400, "invalid_request", "expires_in"));
    }
    if b.kdf.is_some() != b.auth.is_some() {
        return Err(error(400, "invalid_request", "kdf and auth go together"));
    }
    let auth_hash = match &b.auth {
        Some(a) => Some(sha256_hex(&b64(a)?)),
        None => None,
    };
    let id = b64u(&w.random_bytes(16));
    let now = w.now_ms();
    let rec = ShareRec {
        owner: c.principal,
        vault_id: b.vault_id,
        ct: None,
        reference: None,
        kdf: b.kdf,
        auth_hash,
        failed: 0,
        max_opens: b.max_opens,
        opens: 0,
        opened_at: vec![],
        created_at: now,
        expires_at: now + b.expires_in * 1000,
        ended: None,
        ended_at: None,
    };
    let out = share_json(&id, &rec);
    w.auth.shares.insert(id, rec);
    ok(201, &out)
}

fn upload_share(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let b: UploadShareRequest = req.json()?;
    let s = w.auth.shares.get_mut(p.get("id")).filter(|s| s.owner == c.principal);
    let s = s.ok_or_else(|| error(404, "not_found", "Share not found"))?;
    if s.ct.is_some() || s.ended.is_some() {
        return Err(error(409, "conflict", "already uploaded"));
    }
    let ct = from_b64u(&b.ct).map_err(|_| error(400, "invalid_request", "ct"))?;
    if ct.first() != Some(&1) || ct.len() < 41 || (ct.len() - 41) % 512 != 0 || ct.len() > 65_536 {
        return Err(error(400, "invalid_request", "ct"));
    }
    s.ct = Some(b.ct);
    s.reference = Some(b.reference);
    let out = share_json(p.get("id"), s);
    ok(200, &out)
}

fn revoke_share(w: &mut World, req: &Req, p: &Params) -> Res {
    let c = caller(w, req, false)?;
    let now = w.now_ms();
    let s = w.auth.shares.get_mut(p.get("id")).filter(|s| s.owner == c.principal);
    let s = s.ok_or_else(|| error(404, "not_found", "Share not found"))?;
    end_share(s, ShareEndReason::Revoked, now);
    Ok(empty(204))
}

fn gone() -> HttpResponse {
    error(404, "not_found", "This link has expired, was already opened, or doesn't exist")
}

/// The share if it can still be opened (ending it when it just expired).
fn live_share<'a>(w: &'a mut World, id: &str) -> Option<&'a mut ShareRec> {
    let now = w.now_ms();
    let s = w.auth.shares.get_mut(id)?;
    if s.ct.is_none() || s.ended.is_some() {
        return None;
    }
    if s.expires_at <= now {
        end_share(s, ShareEndReason::Expired, now);
        return None;
    }
    Some(s)
}

fn public_share(w: &mut World, _req: &Req, p: &Params) -> Res {
    let s = live_share(w, p.get("id")).ok_or_else(gone)?;
    ok(
        200,
        &PublicShareInfo {
            expires_at: iso(s.expires_at),
            opens_left: s.max_opens.map(|m| m - s.opens),
            kdf: s.kdf.clone(),
        },
    )
}

fn open_share(w: &mut World, req: &Req, p: &Params) -> Res {
    let now = w.now_ms();
    let body: OpenShareRequest = serde_json::from_slice(&req.body).unwrap_or_default();
    let s = live_share(w, p.get("id")).ok_or_else(gone)?;
    if let Some(hash) = &s.auth_hash {
        let given = body.auth.as_deref().and_then(|a| from_b64u(a).ok()).map(|a| sha256_hex(&a));
        if given.as_ref() != Some(hash) {
            s.failed += 1;
            if s.failed >= 5 {
                end_share(s, ShareEndReason::Passcode, now);
                return Err(gone());
            }
            let left = 5 - s.failed;
            return Err(error_with(403, "invalid_passcode", "Wrong passcode", json!({ "attempts_left": left })));
        }
    }
    let ct = s.ct.clone().expect("live");
    s.opens += 1;
    s.opened_at.push(iso(now));
    if s.max_opens.is_some_and(|m| s.opens >= m) {
        end_share(s, ShareEndReason::Opened, now);
    }
    ok(200, &OpenedShare { ct, opens_left: s.max_opens.map(|m| m - s.opens) })
}

// ------------------------------------------------------------------------------------ billing (SPEC §19)

fn apple_eligibility(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let reason = if let Some(org) = req.query("org") {
        let owner = w
            .auth
            .orgs
            .get(org)
            .and_then(|o| o.members.get(uid(&c.principal)))
            .is_some_and(|m| m.role == OrgRole::Owner);
        (!owner).then_some("not_owner")
    } else {
        match w.auth.plans.get(uid(&c.principal)).and_then(|p| p.billing.as_ref()).map(|b| b.source.as_str()) {
            Some("stripe") => Some("billed_by_stripe"),
            Some("apple") => Some("billed_by_apple"),
            _ => None,
        }
    };
    ok(200, &AppleEligibility { eligible: reason.is_none(), reason: reason.map(str::to_string) })
}

fn apple_transaction(w: &mut World, req: &Req, _p: &Params) -> Res {
    let c = user_caller(w, req, false)?;
    let b: AppleTransactionRequest = req.json()?;
    if b.signed_transaction.split('.').count() != 3 {
        return Err(error(400, "apple_verification_failed", "The transaction doesn't verify"));
    }
    let plan = Plan {
        id: Some("premium".into()),
        limits: BTreeMap::new(),
        billing: Some(Billing {
            source: "apple".into(),
            interval: "year".into(),
            status: "active".into(),
            renews_at: Some(iso(w.now_ms() + 365 * 86_400_000)),
            ends_at: None,
            manage: "app_store".into(),
        }),
    };
    w.auth.plans.insert(uid(&c.principal), plan.clone());
    ok(200, &AppleTransactionRecorded { subject: c.principal, plan })
}

/// For helpers: the user's id by email.
pub(crate) fn user_id(w: &World, email: &str) -> Option<String> {
    w.auth.users.get(&norm_email(email)).map(|u| u.id.clone())
}

/// For helpers: adds an accepted member (the invitation flow skipped).
pub(crate) fn add_member(w: &mut World, org: &str, email: &str, role: OrgRole) -> bool {
    let Some(id) = user_id(w, email) else { return false };
    let Some(o) = w.auth.orgs.get_mut(org) else { return false };
    o.members.insert(id, MemberRec { role, status: MemberStatus::Accepted });
    true
}

/// For helpers: sets or clears the fixed TOTP code.
pub(crate) fn set_totp_code(w: &mut World, email: &str, code: Option<&str>) -> bool {
    match w.auth.users.get_mut(&norm_email(email)) {
        Some(u) => {
            u.fixed_totp = code.map(str::to_string);
            true
        }
        None => false,
    }
}

/// For helpers: the current code of the user's enabled (or pending) TOTP, else the fixed code.
pub(crate) fn totp_now(w: &World, email: &str) -> Option<String> {
    let u = w.auth.users.get(&norm_email(email))?;
    match u.totp_secret.as_deref().or(u.pending_totp.as_deref()) {
        Some(s) => totp_at(s, w.now_ms()),
        None => u.fixed_totp.clone(),
    }
}

impl World {
    /// Marks `version` pending on a vault without sealing it to anyone (another manager's rotation
    /// whose key nobody else holds). Test helper.
    pub(crate) fn start_pending_rotation(&mut self, vault: &str, version: i64) -> bool {
        let now = self.now_ms();
        match self.auth.vaults.get_mut(vault) {
            Some(v) => {
                v.pending = Some(version);
                v.pending_since = now;
                true
            }
            None => false,
        }
    }
}
