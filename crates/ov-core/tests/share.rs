//! SDK `share.test.ts` end-to-end cases (SPEC §22) against the W2-E servers. The crypto vectors are
//! ov-share's.

mod servers_common;

use ov_core::api::*;
use ov_core::OvErrorCode;
use servers_common::*;

fn options(passcode: Option<&str>) -> ShareOptions {
    ShareOptions {
        expires_in: 3600,
        max_opens: Some(2),
        passcode: passcode.map(|p| p.as_bytes().to_vec()),
        vault_id: None,
        entry_id: None,
    }
}

#[tokio::test]
async fn create_open_without_an_account_list_revoke() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let api = a.server_config().api;
    let payload = text_share_payload(b"the secret".to_vec(), Some("Note".into()), None);
    let created = a.create_share(payload, options(None), nc()).await.unwrap();
    assert!(String::from_utf8(created.url.clone()).unwrap().contains('#'));

    let anon = device(&s, false);
    let info = anon.share_info(api.clone(), created.id.clone(), nc()).await.unwrap();
    assert_eq!((info.opens_left, info.kdf.is_none()), (Some(2), true));
    let opened = anon.open_share(api.clone(), created.url.clone(), None, Some(info), nc()).await.unwrap();
    assert_eq!(opened.payload.fields[0].value, b"the secret");
    assert_eq!(opened.opens_left, Some(1));

    let list = a.list_shares(nc()).await.unwrap();
    assert_eq!(list[0].reference.as_ref().unwrap().title, "Note");
    assert_eq!(list[0].opens, 1);
    a.revoke_share(created.id.clone(), nc()).await.unwrap();
    assert_eq!(anon.share_info(api, created.id, nc()).await.unwrap_err().code, OvErrorCode::NotFound);
}

#[tokio::test]
async fn passcode() {
    let s = servers();
    let a = connect(&device(&s, false), &s).await;
    register(&a, "alice@example.com", "pw").await;
    let api = a.server_config().api;
    let created =
        a.create_share(text_share_payload(b"x".to_vec(), None, None), options(Some("1234")), nc()).await.unwrap();
    let anon = device(&s, false);
    let e = anon.open_share(api.clone(), created.url.clone(), None, None, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::PasscodeRequired);
    let e = anon.open_share(api.clone(), created.url.clone(), Some(b"0000".to_vec()), None, nc()).await.unwrap_err();
    assert_eq!(e.code, OvErrorCode::InvalidPasscode);
    let ok = anon.open_share(api, created.url, Some(b"1234".to_vec()), None, nc()).await.unwrap();
    assert_eq!(ok.payload.fields[0].value, b"x");
}
