//! The servers answer every endpoint ov-protocol types: one walk through the whole API with the
//! ov-protocol builders and parsers, then a check that every operation key of
//! `crates/ov-protocol/tests/openapi/samples.json` (the contract) got a successful answer.

use std::collections::BTreeSet;
use std::sync::Arc;

use ov_crypto::curves::{ed25519_public_key, x25519_public_key};
use ov_crypto::encoding::b64u;
use ov_error::{OvError, OvErrorCode};
use ov_host::{HttpRequest, HttpResponse, Method, TransportError};
use ov_protocol::auth::*;
use ov_protocol::discovery::{build_discovery, build_jwks, parse_discovery, parse_jwks};
use ov_protocol::parse_empty;
use ov_protocol::sse::{to_sync_event, SseParser, SyncEvent};
use ov_protocol::sync::*;
use ov_protocol::types::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

use super::*;
use crate::ManualClock;

const NOW: i64 = 1_794_744_000_000; // 2026-11-15T12:00:00Z

fn servers() -> TestServers {
    TestServers::new(Arc::new(ManualClock::new(NOW)))
}

fn send(s: &TestServers, req: HttpRequest) -> HttpResponse {
    block_on(s.http().send(req)).expect("the transport answers")
}

/// Unwraps a parser result, naming the call on failure.
fn ok<T>(what: &str, r: Result<T, OvError>) -> T {
    r.unwrap_or_else(|e| panic!("{what}: {:?} {} ({:?})", e.code, e.message, e.status))
}

fn kdf() -> Kdf {
    Kdf { alg: "argon2id".into(), salt: "AAAAAAAAAAAAAAAAAAAAAA".into(), m: 19456, t: 2, p: 1 }
}

fn device() -> DeviceInfo {
    DeviceInfo { id: None, name: "test".into(), platform: Platform::Cli }
}

/// A keyset with real public keys (the restore proof checks `sign_pk`), and its signing seed.
fn keyset(n: u8) -> (WrappedKeyset, [u8; 32]) {
    let seed = [n; 32];
    let ks = WrappedKeyset {
        enc_pk: b64u(&x25519_public_key(&[n.wrapping_add(100); 32])),
        sign_pk: b64u(&ed25519_public_key(&seed)),
        sig: b64u(&[0; 64]),
        wrapped: b64u(b"wrapped"),
    };
    (ks, seed)
}

struct Client {
    s: TestServers,
    api: AuthApi,
    sync: SyncApi,
    rng: ChaCha20Rng,
}

impl Client {
    fn new(s: &TestServers) -> Self {
        let config = ok("discovery", parse_discovery(&send(s, build_discovery(&s.issuer()).unwrap())));
        assert_eq!(config.sync, s.sync_url());
        Client {
            s: s.clone(),
            api: AuthApi::new(&config.api).unwrap(),
            sync: SyncApi::new(&config.sync).unwrap(),
            rng: ChaCha20Rng::from_seed([7; 32]),
        }
    }

    fn send(&self, req: HttpRequest) -> HttpResponse {
        send(&self.s, req)
    }

    fn ids(email: &str) -> ov_opaque::OpaqueIds {
        ov_opaque::opaque_ids(email, "auth.test")
    }

    /// An OPAQUE registration record for `password`, through a `*/start` call that answers
    /// `{session_id, response}`.
    fn registration(
        &mut self,
        email: &str,
        password: &str,
        start: impl FnOnce(&Self, String) -> HttpResponse,
    ) -> (String, String) {
        let st = ov_opaque::start_registration(&mut self.rng, password).unwrap();
        let res = start(self, b64u(&st.request));
        let r = ok("registration start", parse_opaque_registration(&res));
        let response = ov_crypto::encoding::from_b64u(&r.response).unwrap();
        let fin = ov_opaque::finish_registration(&mut self.rng, st.state, &response, &Self::ids(email)).unwrap();
        (r.session_id, b64u(&fin.record))
    }

    fn register(&mut self, email: &str, password: &str, ks: &WrappedKeyset) -> Session {
        let st = ov_opaque::start_registration(&mut self.rng, password).unwrap();
        let res = self.send(
            self.api.build_register_start(&RegisterStartRequest { email: email.into(), request: b64u(&st.request) }),
        );
        let r = ok("register/start", parse_register_start(&res));
        let response = ov_crypto::encoding::from_b64u(&r.response).unwrap();
        let fin = ov_opaque::finish_registration(&mut self.rng, st.state, &response, &Self::ids(email)).unwrap();
        let body = RegisterFinishRequest {
            session_id: r.session_id,
            record: b64u(&fin.record),
            kdf: kdf(),
            keyset: ks.clone(),
            device: device(),
        };
        let s = ok("register/finish", parse_session(&self.send(self.api.build_register_finish(&body))));
        assert_eq!(s.user.id, r.user_id);
        s
    }

    /// KE1 → `(session_id, ke2)` through `start`, then `auth_u`.
    fn opaque_login(
        &mut self,
        email: &str,
        password: &str,
        start: impl FnOnce(&Self, String) -> (String, String),
    ) -> Result<(String, String), ov_opaque::OpaqueError> {
        let st = ov_opaque::start_login(&mut self.rng, password).unwrap();
        let (sid, ke2) = start(self, b64u(&st.ke1));
        let ke2 = ov_crypto::encoding::from_b64u(&ke2).unwrap();
        let fin = ov_opaque::finish_login(&mut self.rng, st.state, &ke2, &Self::ids(email), OPAQUE_CONTEXT)?;
        Ok((sid, b64u(&fin.auth_u)))
    }

    fn login(&mut self, email: &str, password: &str) -> LoginFinishResponse {
        let (sid, auth_u) = self
            .opaque_login(email, password, |c, ke1| {
                let res = c.send(c.api.build_login_start(&LoginStartRequest { email: email.into(), ke1 }));
                let r = ok("login/start", parse_login_start(&res));
                (r.session_id, r.ke2)
            })
            .expect("right password");
        let body = LoginFinishRequest { session_id: sid, auth_u, device: device() };
        ok("login/finish", parse_login_finish(&self.send(self.api.build_login_finish(&body))))
    }

    fn session(&mut self, email: &str, password: &str) -> Session {
        match self.login(email, password) {
            LoginFinishResponse::Session(s) => *s,
            LoginFinishResponse::Mfa(_) => panic!("unexpected MFA"),
        }
    }
}

fn grant(principal: &str, role: VaultRole, version: i64) -> Grant {
    Grant { principal: principal.into(), role, key_version: version, sealed_key: b64u(&[version as u8; 80]) }
}

/// Every operation key of the contract that a client uses (the internal routes are auth server →
/// sync server only, as in ov-protocol's `EXCLUDED`).
fn contract_ops() -> BTreeSet<String> {
    let samples: serde_json::Map<String, serde_json::Value> =
        serde_json::from_str(include_str!("../../../ov-protocol/tests/openapi/samples.json")).unwrap();
    samples
        .keys()
        .filter_map(|k| k.strip_suffix(" op"))
        .filter(|k| !k.contains("/internal/"))
        .map(str::to_string)
        .collect()
}

#[test]
fn every_typed_endpoint_answers() {
    let s = servers();
    let mut c = Client::new(&s);
    let jwks = ok("jwks", parse_jwks(&c.send(build_jwks(&s.discovery().jwks_uri).unwrap())));
    assert_eq!(jwks.keys[0].kid.as_deref(), Some("test-key-1"));

    // ---- accounts
    let (alice_ks, alice_seed) = keyset(1);
    let (bob_ks, _) = keyset(2);
    let alice = c.register("alice@example.com", "correct horse ü", &alice_ks);
    let bob = c.register("bob@example.com", "bob password", &bob_ks);
    let alice_pr = format!("user:{}", alice.user.id);
    let bob_pr = format!("user:{}", bob.user.id);
    let a = c.session("alice@example.com", "correct horse ü");
    let mut at = a.access_token.clone();

    // A wrong password and an unknown email look the same.
    let wrong = c.opaque_login("alice@example.com", "nope", |c, ke1| {
        let r = ok(
            "login/start",
            parse_login_start(
                &c.send(c.api.build_login_start(&LoginStartRequest { email: "alice@example.com".into(), ke1 })),
            ),
        );
        (r.session_id, r.ke2)
    });
    assert!(wrong.is_err());
    let unknown = c.opaque_login("nobody@example.com", "x", |c, ke1| {
        let r = ok(
            "login/start",
            parse_login_start(
                &c.send(c.api.build_login_start(&LoginStartRequest { email: "nobody@example.com".into(), ke1 })),
            ),
        );
        (r.session_id, r.ke2)
    });
    assert!(unknown.is_err());

    // ---- refresh rotation, reuse
    let pair = ok("refresh", parse_refresh(&c.send(c.api.build_refresh(&a.refresh_token))));
    let reused = c.send(c.api.build_refresh(&a.refresh_token));
    // Within 60 s with the replacement unused: the grace period answers.
    let grace = ok("refresh grace", parse_refresh(&reused));
    assert_ne!(grace.refresh_token, pair.refresh_token);
    let e = parse_refresh(&c.send(c.api.build_refresh(&pair.refresh_token))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized, "the lost replacement was revoked");

    // ---- me, devices, keys
    let me = ok("me", parse_me(&c.send(c.api.build_me(&at))));
    assert_eq!(me.email, "alice@example.com");
    let devices = ok("devices", parse_devices(&c.send(c.api.build_list_devices(&at)))).devices;
    assert_eq!(devices.len(), 2);
    let other = devices.iter().find(|d| !d.current).unwrap().id.clone();
    ok("revoke device", parse_empty(&c.send(c.api.build_revoke_device(&at, &other))));
    ok("web session", parse_web_session(&c.send(c.api.build_web_session(&at))));
    let bob_pub = ok("lookup", parse_public_principal(&c.send(c.api.build_lookup_user(&at, "bob@example.com"))));
    assert_eq!(bob_pub.principal, bob_pr);
    ok("public key", parse_public_principal(&c.send(c.api.build_public_key(&at, &bob_pr))));

    // ---- TOTP
    let enrol = ok("totp start", parse_totp_start(&c.send(c.api.build_totp_start(&at))));
    assert!(enrol.otpauth_uri.starts_with("otpauth://totp/"));
    let code = s.totp_now("alice@example.com").unwrap();
    ok("totp confirm", parse_empty(&c.send(c.api.build_totp_confirm(&at, &code))));
    let LoginFinishResponse::Mfa(ch) = c.login("alice@example.com", "correct horse ü") else { panic!("MFA expected") };
    let e = parse_session(
        &c.send(c.api.build_login_mfa(&LoginMfaRequest { mfa_token: ch.mfa_token.clone(), totp: "000000".into() })),
    );
    assert_eq!(e.unwrap_err().code, OvErrorCode::InvalidMfa);
    let body = LoginMfaRequest { mfa_token: ch.mfa_token, totp: s.totp_now("alice@example.com").unwrap() };
    let mfa_session = ok("login/mfa", parse_session(&c.send(c.api.build_login_mfa(&body))));
    at = mfa_session.access_token.clone();
    let code = s.totp_now("alice@example.com").unwrap();
    ok("totp disable", parse_empty(&c.send(c.api.build_totp_disable(&at, &code))));

    // ---- password change
    let tok = at.clone();
    let (sid, record) = c.registration("alice@example.com", "new pw", |c, request| {
        c.send(c.api.build_password_start(&tok, &PasswordStartRequest { request }))
    });
    let body = PasswordFinishRequest { session_id: sid, record, kdf: kdf(), keyset: alice_ks.clone() };
    ok("password finish", parse_empty(&c.send(c.api.build_password_finish(&at, &body))));
    let alice_pw = "new pw";
    c.session("alice@example.com", alice_pw);

    // ---- email change (bob)
    let mut bt = c.session("bob@example.com", "bob password").access_token;
    ok("email request", parse_email_request(&c.send(c.api.build_email_request(&bt, "bobby@example.com"))));
    let code = s.email_code(&bob.user.id).unwrap();
    let tok = bt.clone();
    let (sid, record) = c.registration("bobby@example.com", "bob password", |c, request| {
        let body = EmailStartRequest { email: "bobby@example.com".into(), code, request };
        c.send(c.api.build_email_start(&tok, &body))
    });
    ok(
        "email finish",
        parse_empty(&c.send(c.api.build_email_finish(&bt, &EmailFinishRequest { session_id: sid, record }))),
    );
    let bob_email = "bobby@example.com";
    bt = c.session(bob_email, "bob password").access_token;

    // ---- orgs and invitations
    let org = ok("create org", parse_org(&c.send(c.api.build_create_org(&at, "Acme"))));
    ok("get org", parse_org(&c.send(c.api.build_get_org(&at, &org.id))));
    let body = UpdateOrgRequest { name: Some("Acme Inc".into()), item_share_links: Some(ShareLinkPolicy::Managers) };
    assert_eq!(ok("update org", parse_org(&c.send(c.api.build_update_org(&at, &org.id, &body)))).name, "Acme Inc");
    let inv = InviteRequest { email: bob_email.into(), role: OrgRole::Member };
    ok("invite", parse_invitation(&c.send(c.api.build_invite(&at, &org.id, &inv))));
    let inv = InviteRequest { email: "carol@example.com".into(), role: OrgRole::Member };
    let carol = ok("invite", parse_invitation(&c.send(c.api.build_invite(&at, &org.id, &inv))));
    assert_eq!(
        ok("invitations", parse_invitations(&c.send(c.api.build_list_invitations(&at, &org.id)))).invitations.len(),
        2
    );
    ok("cancel invitation", parse_empty(&c.send(c.api.build_cancel_invitation(&at, &org.id, &carol.id))));
    let token = s.invitation_token(&org.id, bob_email).unwrap();
    let m = ok("accept", parse_member(&c.send(c.api.build_accept_invitation(&bt, &token))));
    assert_eq!(m.status, MemberStatus::Accepted);
    let members = ok("members", parse_members(&c.send(c.api.build_list_members(&at, &org.id)))).members;
    assert_eq!(members.len(), 2);
    let m = ok(
        "confirm",
        parse_member(&c.send(c.api.build_confirm_member(&at, &org.id, &bob.user.id, &ConfirmMemberRequest::default()))),
    );
    assert_eq!(m.status, MemberStatus::Confirmed);
    let body = SetMemberRoleRequest { role: OrgRole::Admin, sa_master_keys: None };
    ok("role", parse_member(&c.send(c.api.build_set_member_role(&at, &org.id, &bob.user.id, &body))));

    // ---- vaults, access, rotation
    let v1 = "11111111-1111-4111-8111-111111111111";
    let body = CreateVaultRequest {
        id: v1.into(),
        org_id: None,
        encrypted_name: b64u(b"name"),
        grants: vec![grant(&alice_pr, VaultRole::Manage, 1)],
    };
    ok("create vault", parse_vault(&c.send(c.api.build_create_vault(&at, &body))));
    let v2 = "22222222-2222-4222-8222-222222222222";
    let body = CreateVaultRequest { id: v2.into(), ..body };
    ok("create vault", parse_vault(&c.send(c.api.build_create_vault(&at, &body))));
    assert_eq!(ok("vaults", parse_vaults(&c.send(c.api.build_list_vaults(&at)))).vaults.len(), 2);
    ok("get vault", parse_vault(&c.send(c.api.build_get_vault(&at, v1))));
    ok("rename vault", parse_vault(&c.send(c.api.build_rename_vault(&at, v1, &b64u(b"renamed")))));
    ok("grant", parse_empty(&c.send(c.api.build_grant_access(&at, v1, &[grant(&bob_pr, VaultRole::Read, 1)]))));
    assert_eq!(ok("access", parse_access(&c.send(c.api.build_list_access(&at, v1)))).access.len(), 2);
    let body = StartRotationRequest {
        key_version: 2,
        grants: vec![grant(&alice_pr, VaultRole::Manage, 2), grant(&bob_pr, VaultRole::Read, 2)],
        remove: None,
    };
    ok("rotate", parse_empty(&c.send(c.api.build_start_rotation(&at, v1, &body))));
    ok("activate", parse_empty(&c.send(c.api.build_activate_key(&at, v1, 2))));
    let v = ok("transfer", parse_vault(&c.send(c.api.build_transfer_vault(&at, v1, &bob_pr))));
    assert_eq!((v.owner_id.as_deref(), v.role), (Some(bob.user.id.as_str()), VaultRole::Manage));

    // ---- the sync server (new token: v2 is in its vlt). The password change signed out alice's
    // other devices, so the MFA session's device is the one left.
    let e = parse_refresh(&c.send(c.api.build_refresh(&grace.refresh_token))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized);
    let pair = ok("refresh", parse_refresh(&c.send(c.api.build_refresh(&mfa_session.refresh_token))));
    let st = pair.access_token.clone();
    let stream = block_on(s.http().open_stream(c.sync.build_events(Some(&st)))).unwrap();
    assert_eq!(stream.status(), 200);
    let blob = BlobPath::vault(v2);
    let put = ok(
        "put",
        parse_blob_put(&c.send(c.sync.build_blob_put(&blob, Some(&st), vec![1, 2, 3], &PutCondition::Create))),
    );
    assert!(put.created);
    let mut parser = SseParser::new();
    let mut events = vec![];
    while events.is_empty() {
        let chunk = block_on(stream.next_chunk()).unwrap().unwrap();
        events.extend(parser.feed(&chunk).iter().filter_map(to_sync_event));
    }
    assert!(matches!(&events[0], SyncEvent::Vault { id, revision: Some(1), .. } if id == v2));
    stream.close();
    let GetResult::Ok { version, .. } =
        ok("get", parse_blob_get(&c.send(c.sync.build_blob_get(&blob, Some(&st), None))))
    else {
        panic!("blob expected")
    };
    let head = ok("head", parse_blob_head(&c.send(c.sync.build_blob_head(&blob, Some(&st), Some(&version.etag)))));
    assert!(matches!(head, HeadResult::NotModified(_)));
    let e = parse_blob_put(&c.send(c.sync.build_blob_put(
        &blob,
        Some(&st),
        vec![9],
        &PutCondition::IfMatch("\"x\"".into()),
    )));
    assert_eq!(e.unwrap_err().code, OvErrorCode::PreconditionFailed);
    let cond = PutCondition::IfMatch(version.etag.clone());
    ok("put", parse_blob_put(&c.send(c.sync.build_blob_put(&blob, Some(&st), vec![4, 5], &cond))));
    let list = ok("sync vaults", parse_list_vaults(&c.send(c.sync.build_list_vaults(&st))));
    assert_eq!(list.iter().map(|m| m.revision).collect::<Vec<_>>(), [2]);
    assert_eq!(ok("history", parse_history(&c.send(c.sync.build_history(&blob, Some(&st))))).len(), 2);
    assert_eq!(ok("revision", parse_revision(&c.send(c.sync.build_revision(&blob, Some(&st), 1)))).data, [1, 2, 3]);
    let e = parse_blob_get(&c.send(c.sync.build_blob_get(&BlobPath::vault(v1), Some(&st), None))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Forbidden, "v1 now belongs to bob");
    // legacy device-token routes
    ok("health", parse_health(&c.send(c.sync.build_health())));
    ok("databases", parse_list_databases(&c.send(c.sync.build_list_databases(DEVICE_TOKEN))));
    ok("pairing", parse_pairing_code(&c.send(c.sync.build_create_pairing_code(DEVICE_TOKEN))));
    let claim = ok("claim", parse_pairing_claim(&c.send(c.sync.build_claim_pairing_code(PAIRING_CODE, "Web"))));
    let db = BlobPath::database("main");
    ok(
        "db put",
        parse_blob_put(&c.send(c.sync.build_blob_put(&db, Some(&claim.token), vec![1], &PutCondition::Create))),
    );

    // ---- service accounts
    let secret = [5u8; 32];
    let new_secret = |id: &str| NewSaSecret {
        id: id.into(),
        name: None,
        secret_hash: hex::encode(Sha256::digest(secret)),
        prefix: b64u(&secret)[..8].into(),
        wrapped_master: b64u(b"wm"),
        expires_at: None,
    };
    let (sa_ks, _) = keyset(3);
    let sa_id = "33333333-3333-4333-8333-333333333333";
    let body = CreateServiceAccountRequest {
        id: sa_id.into(),
        name: "ci".into(),
        expires_at: None,
        keyset: sa_ks,
        master_keys: vec![SaMasterGrant { sa_id: sa_id.into(), principal: alice_pr.clone(), sealed_key: b64u(b"m") }],
        secret: new_secret("s1"),
    };
    ok("create SA", parse_service_account(&c.send(c.api.build_create_service_account(&at, &org.id, &body))));
    assert_eq!(
        ok("SAs", parse_service_accounts(&c.send(c.api.build_list_service_accounts(&at, &org.id))))
            .service_accounts
            .len(),
        1
    );
    let sa = ok("get SA", parse_service_account(&c.send(c.api.build_get_service_account(&at, sa_id))));
    assert_eq!(sa.master_key.as_deref(), Some(b64u(b"m").as_str()));
    let body = UpdateServiceAccountRequest { name: Some("ci-2".into()), ..Default::default() };
    ok("update SA", parse_service_account(&c.send(c.api.build_update_service_account(&at, sa_id, &body))));
    ok("issue secret", parse_empty(&c.send(c.api.build_issue_sa_secret(&at, sa_id, &new_secret("s2")))));
    assert_eq!(ok("secrets", parse_sa_secrets(&c.send(c.api.build_list_sa_secrets(&at, sa_id)))).secrets.len(), 2);
    ok(
        "update secret",
        parse_sa_secret(&c.send(c.api.build_update_sa_secret(&at, sa_id, "s2", Some("2030-01-01T00:00:00Z")))),
    );
    ok("revoke secret", parse_empty(&c.send(c.api.build_revoke_sa_secret(&at, sa_id, "s2"))));
    let body = ServiceAccountExchangeRequest { sa_id: sa_id.into(), secret: b64u(&secret) };
    let ex = ok("SA exchange", parse_service_account_exchange(&c.send(c.api.build_service_account_exchange(&body))));
    let claims = ov_crypto::jwt::decode_jwt(&ex.access_token).unwrap().claims;
    assert_eq!((claims.sub, claims.org), (format!("sa:{sa_id}"), Some(org.id.clone())));

    // ---- share links
    let body = CreateShareRequest { vault_id: None, expires_in: 3600, max_opens: Some(1), kdf: None, auth: None };
    let share = ok("create share", parse_share(&c.send(c.api.build_create_share(&at, &body))));
    let mut ct = vec![0u8; 41 + 512];
    ct[0] = 1;
    let up = UploadShareRequest { ct: b64u(&ct), reference: b64u(b"ref") };
    assert_eq!(
        ok("upload share", parse_share(&c.send(c.api.build_upload_share(&at, &share.id, &up)))).status,
        ShareStatus::Active
    );
    assert_eq!(ok("shares", parse_shares(&c.send(c.api.build_list_shares(&at)))).shares.len(), 1);
    ok("public share", parse_public_share(&c.send(c.api.build_public_share(&share.id))));
    let opened =
        ok("open share", parse_open_share(&c.send(c.api.build_open_share(&share.id, &OpenShareRequest::default()))));
    assert_eq!(opened.opens_left, Some(0));
    assert_eq!(
        parse_public_share(&c.send(c.api.build_public_share(&share.id))).unwrap_err().code,
        OvErrorCode::NotFound
    );
    ok("revoke share", parse_empty(&c.send(c.api.build_revoke_share(&at, &share.id))));

    // ---- billing, audit
    let el = ok("eligibility", parse_apple_eligibility(&c.send(c.api.build_apple_eligibility(&at, None))));
    assert!(el.eligible);
    ok("apple", parse_apple_transaction(&c.send(c.api.build_report_apple_transaction(&at, "a.b.c"))));
    let page = ok("audit", parse_audit(&c.send(c.api.build_audit(&at, &org.id, None, Some(2)))));
    assert_eq!(page.events.len(), 2);
    assert!(page.next.is_some());

    // ---- deletion (bob: scheduled, then cancelled)
    let preview = ok("deletion preview", parse_deletion_preview(&c.send(c.api.build_deletion_preview(&bt))));
    assert!(!preview.blocked);
    let sched = ok("delete me", parse_schedule_deletion(&c.send(c.api.build_schedule_deletion(&bt, bob_email))));
    assert_eq!(parse_me(&c.send(c.api.build_me(&bt))).unwrap_err().code, OvErrorCode::Unauthorized, "signed out");
    let bt2 = c.session(bob_email, "bob password").access_token;
    let claims = ov_crypto::jwt::decode_jwt(&bt2).unwrap().claims;
    assert_eq!(claims.del.as_deref(), Some(sched.scheduled_for.as_str()));
    assert_eq!(parse_vaults(&c.send(c.api.build_list_vaults(&bt2))).unwrap_err().code, OvErrorCode::Forbidden);
    ok("cancel deletion", parse_empty(&c.send(c.api.build_cancel_deletion(&bt2))));

    // ---- clean-up routes
    let v3 = "44444444-4444-4444-8444-444444444444";
    let body = CreateVaultRequest {
        id: v3.into(),
        org_id: None,
        encrypted_name: b64u(b"x"),
        grants: vec![grant(&alice_pr, VaultRole::Manage, 1)],
    };
    ok("create vault", parse_vault(&c.send(c.api.build_create_vault(&at, &body))));
    ok("delete vault", parse_empty(&c.send(c.api.build_delete_vault(&at, v3))));
    let st = ok("refresh", parse_refresh(&c.send(c.api.build_refresh(&pair.refresh_token))));
    ok(
        "delete blob",
        parse_blob_delete(&c.send(c.sync.build_blob_delete(&BlobPath::vault(v2), Some(&st.access_token), None))),
    );
    ok(
        "put again",
        parse_blob_put(&c.send(c.sync.build_blob_put(
            &BlobPath::vault(v2),
            Some(&st.access_token),
            vec![7],
            &PutCondition::Create,
        ))),
    );
    ok("delete SA", parse_empty(&c.send(c.api.build_delete_service_account(&at, sa_id))));
    ok("remove member", parse_empty(&c.send(c.api.build_remove_member(&at, &org.id, &bob.user.id))));
    ok("delete org", parse_empty(&c.send(c.api.build_delete_org(&at, &org.id))));
    ok("logout", parse_empty(&c.send(c.api.build_logout(&bt2, false))));

    // ---- recovery (SPEC §18): reset alice, then restore the archived grant of v2
    let token = s.approve_reset("alice@example.com", 0);
    let info = ok("recover info", parse_recover_info(&c.send(c.api.build_recover_info(&token))));
    assert_eq!(info.archives.personal_vaults, Some(1));
    let (new_ks, _) = keyset(9);
    let tok = token.clone();
    let (sid, record) = c.registration("alice@example.com", "after reset", |c, request| {
        c.send(c.api.build_recover_start(&RecoverStartRequest { token: tok, request }))
    });
    let body = RecoverFinishRequest { session_id: sid, record, kdf: kdf(), keyset: new_ks.clone(), device: device() };
    let rs = ok("recover finish", parse_session(&c.send(c.api.build_recover_finish(&body))));
    let rt = rs.access_token;
    assert!(ok("recovery status", parse_recovery_status(&c.send(c.api.build_recovery_status(&rt)))).archived);
    let tok = rt.clone();
    let (sid, auth_u) = c
        .opaque_login("alice@example.com", alice_pw, |c, ke1| {
            let r = ok(
                "restore start",
                parse_restore_start(&c.send(c.api.build_restore_start(&tok, &RestoreStartRequest { ke1 }))),
            );
            assert_eq!(r.email.as_deref(), Some("alice@example.com"));
            (r.session_id, r.ke2)
        })
        .unwrap();
    let verified = ok(
        "restore verify",
        parse_restore_verify(
            &c.send(c.api.build_restore_verify(&rt, &RestoreVerifyRequest { session_id: sid, auth_u })),
        ),
    );
    assert_eq!(verified.grants.iter().map(|g| g.vault_id.as_str()).collect::<Vec<_>>(), [v2]);
    let key32 = |s: &str| <[u8; 32]>::try_from(ov_crypto::encoding::from_b64u(s).unwrap()).unwrap();
    let proof =
        ov_crypto::restore::restore_proof(&alice_seed, &alice.user.id, &key32(&new_ks.enc_pk), &key32(&new_ks.sign_pk));
    let body = RestoreFinishRequest { session_id: verified.session_id, grants: verified.grants, proof: b64u(&proof) };
    ok("restore finish", parse_empty(&c.send(c.api.build_restore_finish(&rt, &body))));
    assert_eq!(ok("vaults", parse_vaults(&c.send(c.api.build_list_vaults(&rt)))).vaults.len(), 1);

    // ---- every contract operation answered with success
    let answered: BTreeSet<String> = s
        .requests()
        .into_iter()
        .filter(|r| r.status.is_some_and(|st| (200..400).contains(&st)))
        .filter_map(|r| r.route)
        .map(|r| r.replace("sync HEAD ", "sync GET "))
        .collect();
    let missing: Vec<String> = contract_ops().into_iter().filter(|op| !answered.contains(op)).collect();
    assert!(missing.is_empty(), "contract operations without a successful answer: {missing:#?}");
    assert_eq!(contract_ops().len(), 79);
    assert!(s.requests().iter().all(|r| r.status != Some(404) || r.route.is_some()), "no unknown routes");
}

#[test]
fn faults_offline_and_skew() {
    let s = servers();
    let c = Client::new(&s);
    s.set_offline(true);
    assert_eq!(block_on(s.http().send(c.sync.build_health())).unwrap_err(), TransportError::Offline);
    s.set_offline(false);
    s.fail_next(FaultRule::new(Fault::Status(503)).server(Server::Sync).path("/health").times(2));
    s.fail_next(FaultRule::new(Fault::RateLimited { retry_after: 7 }).method(Method::Get));
    for _ in 0..2 {
        assert_eq!(parse_health(&c.send(c.sync.build_health())).unwrap_err().code, OvErrorCode::ServerError);
    }
    let e = parse_health(&c.send(c.sync.build_health())).unwrap_err();
    assert_eq!((e.code, e.retry_after), (OvErrorCode::RateLimited, Some(7)));
    ok("health", parse_health(&c.send(c.sync.build_health())));
    s.fail_next(FaultRule::new(Fault::Transport(TransportError::Timeout)));
    assert_eq!(block_on(s.http().send(c.sync.build_health())).unwrap_err(), TransportError::Timeout);
    assert_eq!(
        block_on(s.http().send(HttpRequest { url: "https://elsewhere.test/".into(), ..c.sync.build_health() }))
            .unwrap_err(),
        TransportError::Offline
    );
    s.set_server_clock_skew_ms(-120_000);
    let res = c.send(c.sync.build_health());
    assert_eq!(server_time_ms(&res), Some(NOW - 120_000));
}

/// Sync scenarios ov-sync needs: another device between GET and PUT, rollback, lost database,
/// live access, token expiry on the stream.
#[test]
fn sync_scenarios() {
    let s = servers();
    let mut c = Client::new(&s);
    let (ks, _) = keyset(1);
    let a = c.register("a@example.com", "pw", &ks);
    let pr = format!("user:{}", a.user.id);
    let v = "55555555-5555-4555-8555-555555555555";
    let body = CreateVaultRequest {
        id: v.into(),
        org_id: None,
        encrypted_name: b64u(b"n"),
        grants: vec![grant(&pr, VaultRole::Manage, 1)],
    };
    ok("create vault", parse_vault(&c.send(c.api.build_create_vault(&a.access_token, &body))));
    let blob = BlobPath::vault(v);
    // The registration token's vlt predates the vault.
    let e =
        parse_blob_put(&c.send(c.sync.build_blob_put(&blob, Some(&a.access_token), vec![1], &PutCondition::Create)));
    assert_eq!(e.unwrap_err().code, OvErrorCode::Forbidden);
    s.set_live_access(true);
    ok(
        "put",
        parse_blob_put(&c.send(c.sync.build_blob_put(&blob, Some(&a.access_token), vec![1], &PutCondition::Create))),
    );
    s.set_live_access(false);
    let t = ok("refresh", parse_refresh(&c.send(c.api.build_refresh(&a.refresh_token)))).access_token;

    s.set_after_get(Some(Arc::new(|s: &TestServers, id: &str| s.put_vault_blob(id, b"other device"))));
    let GetResult::Ok { version, .. } =
        ok("get", parse_blob_get(&c.send(c.sync.build_blob_get(&blob, Some(&t), None))))
    else {
        panic!()
    };
    s.set_after_get(None);
    let e =
        parse_blob_put(&c.send(c.sync.build_blob_put(&blob, Some(&t), vec![2], &PutCondition::IfMatch(version.etag))));
    assert_eq!(e.unwrap_err().code, OvErrorCode::PreconditionFailed);
    assert_eq!(s.vault_blob(v).unwrap().revision, 2);
    s.put_vault_blob(v, b"three");
    s.rollback_vault(v, 1);
    assert_eq!((s.vault_blob(v).unwrap().revision, s.vault_history(v).len()), (1, 1));
    s.lose_vault(v);
    assert_eq!(ok("get", parse_blob_get(&c.send(c.sync.build_blob_get(&blob, Some(&t), None)))), GetResult::NotFound);

    // The stream ends at the token's exp.
    let stream = block_on(s.http().open_stream(c.sync.build_events(Some(&t)))).unwrap();
    assert_eq!(block_on(stream.next_chunk()).unwrap().as_deref(), Some(&b": connected\n\n"[..]));
    s.clock().advance(600_000);
    s.end_expired_streams();
    assert_eq!(block_on(stream.next_chunk()).unwrap(), None);
    // ... and the expired token is refused (60 s skew allowed).
    s.clock().advance(61_000);
    let e = parse_list_vaults(&c.send(c.sync.build_list_vaults(&t))).unwrap_err();
    assert_eq!(e.code, OvErrorCode::Unauthorized);
    // An unauthorized stream is a stream of the error body.
    let stream = block_on(s.http().open_stream(c.sync.build_events(Some(&t)))).unwrap();
    assert_eq!(stream.status(), 401);
}
