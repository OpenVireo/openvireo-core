//! Facade tests that need no full server: token refresh (`token-manager.ts` cases from the SDK's
//! `auth.test.ts`), sessions on a shared device (SPEC §21), discovery with the offline copy, local
//! vault editing, share payloads and TOTP. The flows against the W2-E servers are in the gated files.

mod support;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ov_core::api::*;
use ov_core::host::{HttpResponse, TransportError};
use ov_core::OvErrorCode;
use serde_json::json;
use support::*;

const USER: &str = "5a0b7c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d";

fn session_json(rt: &str) -> Vec<u8> {
    json!({"issuer": "https://auth.example", "userId": USER, "email": "a@example.com", "deviceId": "d1", "refreshToken": rt})
        .to_string()
        .into_bytes()
}

async fn seed_session(d: &TestDevice, rt: &str) {
    use ov_core::host::SecureStore;
    d.store.set("ov:session", &session_json(rt)).await.unwrap();
}

fn stored_rt(d: &TestDevice) -> Option<String> {
    let m = d.store.0.lock().unwrap();
    m.get("ov:session")
        .map(|v| serde_json::from_slice::<serde_json::Value>(v).unwrap()["refreshToken"].as_str().unwrap().to_owned())
}

fn refresher(count: Arc<AtomicU32>) -> Handler {
    Box::new(move |req| {
        if req.url.ends_with("/auth/refresh") {
            let n = count.fetch_add(1, Ordering::SeqCst) + 1;
            return json(
                200,
                json!({"access_token": jwt(json!({"sub": "user:x", "exp": 9_999_999_999i64})), "refresh_token": format!("ov_rt_{n}"), "expires_in": 600}),
            );
        }
        json(404, json!({"error": "nope"}))
    })
}

async fn connect(d: &TestDevice, offline: bool) -> Account {
    OvClient::new(client_config(offline, Some(server_config())), d.host.clone())
        .connect("https://auth.example".into(), CancelToken::new())
        .await
        .unwrap()
}

#[tokio::test]
async fn refreshes_and_rotates_the_stored_refresh_token() {
    let count = Arc::new(AtomicU32::new(0));
    let d = device(refresher(count.clone()));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    assert!(a.is_signed_in());
    assert_eq!(a.user_id().as_deref(), Some(USER));
    a.verify_session(CancelToken::new()).await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(stored_rt(&d).as_deref(), Some("ov_rt_1"));
    assert_eq!(d.http.calls(), vec!["POST /api/v1/auth/refresh"]);
}

#[tokio::test]
async fn does_one_refresh_for_concurrent_callers() {
    let count = Arc::new(AtomicU32::new(0));
    let d = device(refresher(count.clone()));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    // Three callers that all need a token: one refresh, the others reuse it.
    let (r1, r2, r3) = tokio::join!(a.plan(CancelToken::new()), a.plan(CancelToken::new()), a.plan(CancelToken::new()));
    for r in [r1, r2, r3] {
        assert_eq!(r.unwrap_err().code, OvErrorCode::NotFound);
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn signs_out_when_the_server_reports_token_reuse() {
    let d = device(Box::new(|req| {
        if req.url.ends_with("/auth/refresh") {
            return json(401, json!({"error": "reused", "code": "token_reused"}));
        }
        json(404, json!({}))
    }));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    let watcher = {
        let a = a.clone();
        tokio::spawn(async move { a.signed_out(CancelToken::new()).await })
    };
    tokio::task::yield_now().await;
    let e = a.verify_session(CancelToken::new()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::SignedOut);
    assert_eq!(watcher.await.unwrap().unwrap(), SignedOutReason::TokenReused);
    assert!(!a.is_signed_in());
    assert_eq!(stored_rt(&d), None);
}

#[tokio::test]
async fn keeps_the_session_on_network_errors() {
    let d = device(Box::new(|_| Err(TransportError::Offline)));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    // verify_session does nothing while unreachable; a real call reports network_error.
    a.verify_session(CancelToken::new()).await.unwrap();
    assert_eq!(a.plan(CancelToken::new()).await.unwrap_err().code, OvErrorCode::NetworkError);
    assert!(a.is_signed_in());
    assert_eq!(stored_rt(&d).as_deref(), Some("ov_rt_0"));
}

#[tokio::test]
async fn a_cancelled_call_is_aborted() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    let c = CancelToken::new();
    c.cancel();
    assert_eq!(a.plan(c).await.unwrap_err().code, OvErrorCode::Aborted);
    assert!(d.http.calls().is_empty());
}

#[tokio::test]
async fn parks_and_resumes_sessions() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    let client = OvClient::new(client_config(false, Some(server_config())), d.host.clone());
    assert_eq!(client.session_state("https://auth.example".into(), USER.into()).await.unwrap(), SessionState::Active);
    assert!(a.park_session().await.unwrap());
    assert!(!a.is_signed_in());
    assert_eq!(client.session_state("https://auth.example".into(), USER.into()).await.unwrap(), SessionState::Parked);
    assert_eq!(a.check_parked_session(USER.into(), CancelToken::new()).await.unwrap(), ParkedCheck::Valid);
    assert!(a.resume_session(USER.into()).await.unwrap());
    assert!(a.is_signed_in());
    // The parked refresh rotated the token where it was kept, and it moved back.
    assert_eq!(stored_rt(&d).as_deref(), Some("ov_rt_1"));
    assert!(!a.resume_session("someone-else".into()).await.is_ok());
}

#[tokio::test]
async fn a_crash_mid_move_leaves_the_active_session_in_charge() {
    use ov_core::host::SecureStore;
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    seed_session(&d, "ov_rt_0").await;
    let parked = "ov:parked_session:auth.example:".to_owned() + USER;
    d.store.set(&parked, &session_json("ov_rt_old")).await.unwrap();
    let client = OvClient::new(client_config(false, Some(server_config())), d.host.clone());
    assert_eq!(client.session_state("https://auth.example".into(), USER.into()).await.unwrap(), SessionState::Active);
    assert!(d.store.0.lock().unwrap().get(&parked).is_none());
}

#[tokio::test]
async fn remembers_accounts_most_recent_first() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    let c = OvClient::new(client_config(false, Some(server_config())), d.host.clone());
    c.remember_account("a@example.com".into(), "https://auth.example".into(), "u1".into()).await.unwrap();
    d.clock.advance(1000);
    c.remember_account("b@example.com".into(), "https://auth.example".into(), "u2".into()).await.unwrap();
    c.set_remembered_deletion("https://auth.example".into(), "u1".into(), Some("2026-12-15T00:00:00Z".into()))
        .await
        .unwrap();
    let list = c.remembered_accounts().await.unwrap();
    assert_eq!(list.iter().map(|a| a.user_id.as_str()).collect::<Vec<_>>(), ["u2", "u1"]);
    assert_eq!(list[1].deletion_scheduled_for.as_deref(), Some("2026-12-15T00:00:00Z"));
    // Remembering again keeps the deletion date and moves it to the front.
    d.clock.advance(1000);
    c.remember_account("a2@example.com".into(), "https://auth.example".into(), "u1".into()).await.unwrap();
    let list = c.remembered_accounts().await.unwrap();
    assert_eq!((list[0].email.as_str(), list[0].deletion_scheduled_for.is_some()), ("a2@example.com", true));
    c.forget_remembered("https://auth.example".into(), "u2".into()).await.unwrap();
    assert_eq!(c.remembered_accounts().await.unwrap().len(), 1);
}

#[test]
fn knows_when_a_remembered_pending_account_can_go() {
    let at = "2026-11-15T00:00:00Z".to_owned();
    let t = 1_794_700_800_000i64; // 2026-11-15T00:00:00Z
    assert!(!deletion_expired(None, t));
    assert!(!deletion_expired(Some(at.clone()), t + 23 * 3_600_000));
    assert!(deletion_expired(Some(at), t + 25 * 3_600_000));
    assert!(!deletion_expired(Some("garbage".into()), t));
}

#[tokio::test]
async fn falls_back_to_the_cached_discovery_document_offline() {
    let doc = json!({
        "issuer": "https://auth.example", "api": "https://auth.example/api/v1", "sync": "https://sync.example/api/v1",
        "jwks_uri": "https://auth.example/.well-known/jwks.json", "opaque": {"ids": "auth.example", "context": "ov-opaque-v1"}
    });
    let d = device(Box::new(move |_| json(200, doc.clone())));
    let client = OvClient::new(client_config(true, None), d.host.clone());
    let a = client.connect("https://auth.example".into(), CancelToken::new()).await.unwrap();
    assert!(!a.is_offline());
    d.http.set(Box::new(|_| Err(TransportError::Offline)));
    let a = client.connect("https://auth.example".into(), CancelToken::new()).await.unwrap();
    assert!(a.is_offline());
    assert_eq!(a.server_config().sync, "https://sync.example/api/v1");
    // Without the offline cache there's nothing to fall back to.
    let strict = OvClient::new(client_config(false, None), d.host.clone());
    assert_eq!(
        strict.connect("https://auth.example".into(), CancelToken::new()).await.unwrap_err().code,
        OvErrorCode::NetworkError
    );
}

#[tokio::test]
async fn refuses_plain_http_servers() {
    let d = device(Box::new(|_| json(500, json!({}))));
    let client = OvClient::new(client_config(false, None), d.host.clone());
    assert_eq!(
        client.connect("http://auth.example".into(), CancelToken::new()).await.unwrap_err().code,
        OvErrorCode::InsecureUrl
    );
    assert!(d.http.calls().is_empty());
}

#[tokio::test]
async fn logs_out_on_unload_with_a_keepalive_request() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    assert!(a.sign_out_on_unload().is_none(), "no access token in hand yet");
    a.verify_session(CancelToken::new()).await.unwrap();
    let req = a.sign_out_on_unload().unwrap();
    assert!(req.keepalive);
    assert_eq!(req.url, "https://auth.example/api/v1/auth/logout");
}

#[tokio::test]
async fn locked_accounts_refuse_key_operations() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    seed_session(&d, "ov_rt_0").await;
    let a = connect(&d, false).await;
    assert!(!a.is_unlocked());
    assert_eq!(a.fingerprint().unwrap_err().code, OvErrorCode::SignedOut);
    assert_eq!(a.unlocked_keyset_secret().unwrap_err().code, OvErrorCode::SignedOut);
    assert_eq!(a.secret_key().await.unwrap_err().code, OvErrorCode::SignedOut);
    assert_eq!(a.vaults(CancelToken::new()).await.unwrap_err().code, OvErrorCode::SignedOut);
    // No Secret Key on this device: unlock says so before any KDF.
    let e = a.unlock(b"pw".to_vec(), None, CancelToken::new()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidSecretKey);
}

#[tokio::test]
async fn upgrade_url_stays_on_the_auth_site() {
    let d = device(refresher(Arc::new(AtomicU32::new(0))));
    let a = connect(&d, false).await;
    let e = ov_core::OvError::new(OvErrorCode::PlanLimit, "limit")
        .with_details(r#"{"upgradeUrl":"https://auth.example/subscription/upgrade"}"#);
    assert_eq!(a.upgrade_url(e).as_deref(), Some("https://auth.example/subscription/upgrade"));
    let e = ov_core::OvError::new(OvErrorCode::PlanLimit, "limit")
        .with_details(r#"{"upgradeUrl":"https://evil.example/subscription/x"}"#);
    assert_eq!(a.upgrade_url(e).as_deref(), Some("https://auth.example/subscription/pricing"));
    assert_eq!(a.share_base().as_deref(), Some("https://app.example/s"));
}

// ------------------------------------------------------------------------- local vaults

fn creds() -> KdbxCredentials {
    KdbxCredentials { password: Some(b"local pw".to_vec()), key_file: None, password_hash: None }
}

fn field(name: &str, value: &str) -> FieldInput {
    FieldInput { name: name.into(), value: value.as_bytes().to_vec(), protected: None }
}

#[tokio::test]
async fn edits_a_local_database_and_saves_it() {
    let v = Vault::create_local("Personal".into(), creds(), CancelToken::new()).await.unwrap();
    assert_eq!(v.name(), "Personal");
    assert!(v.info().is_none());
    let root = v.root_group_id();
    let g = v.add_group(None, "Work".into()).unwrap();
    assert_eq!(v.group_id_at("Work".into()).as_deref(), Some(g.as_str()));
    let e = v
        .add_entry(
            g.clone(),
            EntryInput {
                fields: vec![
                    field("title", "Mail"),
                    field("username", "me"),
                    field("password", "s3cret"),
                    field("PIN", "1234"),
                ],
                ..Default::default()
            },
        )
        .unwrap();
    let rec = v.entry(e.clone()).unwrap();
    assert_eq!(rec.group_path, vec!["Work".to_owned()]);
    let pin = rec.fields.iter().find(|f| f.name == "PIN").unwrap();
    assert!(pin.protected, "custom fields are protected by default");
    assert!(!rec.fields.iter().find(|f| f.name == "UserName").unwrap().protected);

    v.edit_entry(
        e.clone(),
        EntryInput { fields: vec![field("password", "n3w")], remove_fields: vec!["PIN".into()], ..Default::default() },
    )
    .unwrap();
    let rec = v.entry(e.clone()).unwrap();
    assert_eq!(rec.history_count, 1);
    assert!(rec.fields.iter().all(|f| f.name != "PIN"));
    assert_eq!(v.history(e.clone()).unwrap()[0].fields.iter().find(|f| f.name == "Password").unwrap().value, b"s3cret");

    v.set_attachment(e.clone(), "a.txt".into(), b"hello".to_vec()).unwrap();
    assert_eq!(v.attachment(e.clone(), "a.txt".into()).unwrap(), b"hello");
    assert_eq!(v.entry(e.clone()).unwrap().attachments[0].size, 5);

    v.delete_entry(e.clone()).unwrap();
    assert!(v.is_in_recycle_bin(e.clone()));
    assert!(v.entries(false).is_empty());
    assert_eq!(v.entries(true).len(), 1);
    v.restore_from_recycle_bin(e.clone()).unwrap();
    assert!(!v.is_in_recycle_bin(e.clone()));

    let csv = String::from_utf8(v.export_plain(ExportFormat::Csv, None).unwrap()).unwrap();
    assert!(csv.starts_with("Folder,Title,Username,Password,URL,Notes\n"));
    // The restored entry is back in its group (contract-v1.8: PreviousParentGroup on every version).
    assert_eq!(v.entry(e.clone()).unwrap().group_id, g);
    assert!(csv.contains("\"Work\",\"Mail\",\"me\",\"n3w\""), "{csv}");

    let bytes = v.save_local(CancelToken::new()).await.unwrap();
    let back = Vault::open_local(bytes.clone(), creds(), CancelToken::new()).await.unwrap();
    assert_eq!(back.entry(e.clone()).unwrap().fields, v.entry(e.clone()).unwrap().fields);
    assert_eq!(back.root_group_id(), root);
    let wrong = KdbxCredentials { password: Some(b"nope".to_vec()), key_file: None, password_hash: None };
    assert_eq!(
        Vault::open_local(bytes, wrong, CancelToken::new()).await.unwrap_err().code,
        OvErrorCode::VaultKeyMismatch
    );

    let exported = v.export_kdbx(creds(), None, CancelToken::new()).await.unwrap();
    let ex = Vault::open_local(exported, creds(), CancelToken::new()).await.unwrap();
    assert_eq!(ex.entries(false).len(), 1);
    assert_eq!(v.sync(SyncOptions::default(), CancelToken::new()).await.unwrap_err().code, OvErrorCode::InvalidRequest);
}

#[tokio::test]
async fn moves_groups_but_not_into_themselves() {
    let v = Vault::create_local("DB".into(), creds(), CancelToken::new()).await.unwrap();
    let a = v.add_group(None, "A".into()).unwrap();
    let b = v.add_group(Some(a.clone()), "B".into()).unwrap();
    assert_eq!(v.move_group(a.clone(), b.clone()).unwrap_err().code, OvErrorCode::InvalidRequest);
    let c = v.ensure_group("X/Y".into()).unwrap();
    assert_eq!(v.group_id_at("X/Y".into()), Some(c));
    v.move_group(b.clone(), v.root_group_id()).unwrap();
    assert_eq!(v.groups().iter().find(|g| g.id == b).unwrap().parent_id, Some(v.root_group_id()));
}

#[test]
fn builds_share_payloads_and_totp() {
    let entry = EntryRecord {
        id: "00".repeat(16),
        group_id: "11".repeat(16),
        group_path: vec![],
        fields: vec![
            FieldRecord { name: "Title".into(), value: b"Mail".to_vec(), protected: false },
            FieldRecord { name: "UserName".into(), value: b"me".to_vec(), protected: false },
            FieldRecord { name: "Password".into(), value: b"pw".to_vec(), protected: true },
            FieldRecord {
                name: "otp".into(),
                value: b"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_vec(),
                protected: true,
            },
        ],
        tags: vec![],
        icon_id: 0,
        custom_icon: None,
        foreground_color: String::new(),
        background_color: String::new(),
        override_url: String::new(),
        created_at: 0,
        modified_at: 0,
        expires_at: None,
        attachments: vec![],
        history_count: 0,
        quality_check: true,
        last_access_at: None,
        usage_count: 0,
    };
    assert_eq!(default_share_fields(), ["UserName", "Password", "URL"]);
    let names: Vec<String> = shareable_fields(entry.clone()).into_iter().map(|f| f.name).collect();
    assert!(names.contains(&"UserName".to_owned()) && names.contains(&"otp".to_owned()));
    let p = item_share_payload(entry.clone(), default_share_fields(), Some("Ann".into()));
    assert_eq!((p.kind.as_str(), p.title.as_deref(), p.shared_by.as_deref()), ("entry", Some("Mail"), Some("Ann")));
    assert_eq!(p.fields.iter().map(|f| f.k.as_str()).collect::<Vec<_>>(), ["username", "password"]);
    let t = text_share_payload(b"hello".to_vec(), None, None);
    assert_eq!((t.kind.as_str(), t.fields[0].value.as_slice()), ("text", b"hello".as_slice()));

    let uri = entry_totp_uri(entry.fields.clone(), "Mail".into()).unwrap();
    let params = parse_totp_uri(uri).unwrap();
    // RFC 6238 SHA-1 at T = 59 s: 94287082 → 287082 with 6 digits.
    assert_eq!(totp_code(params, 59_000).code, b"287082");
    assert_eq!(parse_totp_uri(b"nope".to_vec()).unwrap_err().code, OvErrorCode::InvalidTotp);
}

#[allow(dead_code)]
fn _unused(_: HttpResponse) {}
