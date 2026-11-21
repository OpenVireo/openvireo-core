//! The fuzz targets' bodies, so `cargo test` can replay seeds and regressions on stable-style test
//! builds, plus KDBX envelope builders: a valid KDBX 4 or 3.1 file around fuzzed bytes, so the
//! fuzzer reaches the inner header, the gzip layer, the XML tree, the model reader and the inner
//! stream behind the header hash and the HMAC blocks (which random mutation can't forge).
//!
//! Each target only uses the crates' public APIs. A target panics only where the crate broke a
//! promise (a panic inside a crate, or a property that must hold, such as "what ov-kdbx wrote
//! reads back").

#![forbid(unsafe_code)]

use aes::cipher::{BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use ov_kdbx::model::Kdf;
use ov_kdbx::CompositeKey;
use sha2::{Digest, Sha256, Sha512};
use std::io::Write as _;

/// The password of every file the builders make.
pub const PASSWORD: &str = "fuzz";
/// "Now" for the merge and TOTP steps: 2026-11-15T12:00:00Z.
pub const NOW: i64 = 1_794_744_000;

const SIG1: u32 = 0x9AA2_D903;
const SIG2: u32 = 0xB54B_FB67;
const CIPHER_AES256: [u8; 16] = 0x31c1f2e6_bf71_4350_be58_05216afc5aff_u128.to_be_bytes();
const CIPHER_CHACHA20: [u8; 16] = 0xd6038a2b_8b6f_4cb5_a524_339a31dbb59a_u128.to_be_bytes();
const KDF_AES: [u8; 16] = 0xc9d9f39a_628a_4460_bf74_0d08c18a4fea_u128.to_be_bytes();
const MASTER_SEED: [u8; 32] = [1; 32];
const KDF_SEED: [u8; 32] = [2; 32];
/// The inner stream key of [`kdbx_xml`]'s fixed inner header (KDBX 4) and of KDBX 3.1 files.
const STREAM_KEY: [u8; 32] = [4; 32];
const STREAM_START: [u8; 32] = [6; 32];

/// The key of every file the builders make.
pub fn key() -> CompositeKey {
    CompositeKey::new().with_password(PASSWORD)
}

/// AES-KDF with one round over SHA-256(SHA-256(password)), as ov-kdbx derives it.
fn transformed_key() -> [u8; 32] {
    let raw: [u8; 32] = Sha256::digest(Sha256::digest(PASSWORD.as_bytes())).into();
    let cipher = aes::Aes256::new_from_slice(&KDF_SEED).expect("32-byte seed");
    let mut blocks = [aes::Block::clone_from_slice(&raw[..16]), aes::Block::clone_from_slice(&raw[16..])];
    cipher.encrypt_blocks(&mut blocks);
    let mut h = Sha256::new();
    h.update(blocks[0]);
    h.update(blocks[1]);
    h.finalize().into()
}

fn payload_key() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(MASTER_SEED);
    h.update(transformed_key());
    h.finalize().into()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).expect("in-memory gzip");
    e.finish().expect("in-memory gzip")
}

/// The payload cipher of a KDBX 4 file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// AES-256-CBC.
    Aes,
    /// ChaCha20.
    ChaCha20,
}

/// How a KDBX 4 payload is compressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gzip {
    /// Compression flag off.
    None,
    /// Compression flag on; the builder compresses the plaintext.
    Compress,
    /// Compression flag on; the plaintext is used as the gzip stream itself.
    Raw,
}

fn encrypt(cipher: Cipher, plain: &[u8]) -> (Vec<u8>, Vec<u8>) {
    match cipher {
        Cipher::Aes => {
            let iv = vec![3u8; 16];
            let e = cbc::Encryptor::<aes::Aes256>::new_from_slices(&payload_key(), &iv).expect("key and IV");
            (iv, e.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(plain))
        }
        Cipher::ChaCha20 => {
            let iv = vec![3u8; 12];
            let mut out = plain.to_vec();
            chacha20::ChaCha20::new_from_slices(&payload_key(), &iv).expect("key and IV").apply_keystream(&mut out);
            (iv, out)
        }
    }
}

fn block_mac(index: u64, base: &[u8; 64]) -> Hmac<Sha256> {
    let mut h = Sha512::new();
    h.update(index.to_le_bytes());
    h.update(base);
    <Hmac<Sha256> as Mac>::new_from_slice(&h.finalize()).expect("any key length")
}

/// A KDBX 4.1 file whose decrypted payload is `plaintext` (inner header, then XML), with a
/// one-round AES-KDF and the password [`PASSWORD`].
pub fn kdbx4_file(plaintext: &[u8], cipher: Cipher, gz: Gzip) -> Vec<u8> {
    let payload = match gz {
        Gzip::Compress => gzip(plaintext),
        Gzip::None | Gzip::Raw => plaintext.to_vec(),
    };
    let (iv, ciphertext) = encrypt(cipher, &payload);

    let mut header = Vec::new();
    header.extend_from_slice(&SIG1.to_le_bytes());
    header.extend_from_slice(&SIG2.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&4u16.to_le_bytes());
    let mut field = |id: u8, value: &[u8]| {
        header.push(id);
        header.extend_from_slice(&(value.len() as u32).to_le_bytes());
        header.extend_from_slice(value);
    };
    field(2, if cipher == Cipher::Aes { &CIPHER_AES256 } else { &CIPHER_CHACHA20 });
    field(3, &u32::from(gz != Gzip::None).to_le_bytes());
    field(4, &MASTER_SEED);
    field(7, &iv);
    let mut kdf = vec![0x00, 0x01];
    let mut item = |ty: u8, k: &str, v: &[u8]| {
        kdf.push(ty);
        kdf.extend_from_slice(&(k.len() as u32).to_le_bytes());
        kdf.extend_from_slice(k.as_bytes());
        kdf.extend_from_slice(&(v.len() as u32).to_le_bytes());
        kdf.extend_from_slice(v);
    };
    item(0x42, "$UUID", &KDF_AES);
    item(0x05, "R", &1u64.to_le_bytes());
    item(0x42, "S", &KDF_SEED);
    kdf.push(0);
    field(11, &kdf);
    field(0, b"\r\n\r\n");

    let mut base_h = Sha512::new();
    base_h.update(MASTER_SEED);
    base_h.update(transformed_key());
    base_h.update([1u8]);
    let base: [u8; 64] = base_h.finalize().into();

    let mut out = header.clone();
    out.extend_from_slice(&Sha256::digest(&header));
    let mut m = block_mac(u64::MAX, &base);
    m.update(&header);
    out.extend_from_slice(&m.finalize().into_bytes());
    for (index, block) in [&ciphertext[..], &[][..]].into_iter().enumerate() {
        let index = index as u64;
        let size = (block.len() as u32).to_le_bytes();
        let mut m = block_mac(index, &base);
        m.update(&index.to_le_bytes());
        m.update(&size);
        m.update(block);
        out.extend_from_slice(&m.finalize().into_bytes());
        out.extend_from_slice(&size);
        out.extend_from_slice(block);
    }
    out
}

/// A KDBX 4 inner header: ChaCha20 inner stream with [`STREAM_KEY`] and two attachments.
pub fn inner_header() -> Vec<u8> {
    let mut out = Vec::new();
    let mut field = |id: u8, value: &[u8]| {
        out.push(id);
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value);
    };
    field(1, &3u32.to_le_bytes());
    field(2, &STREAM_KEY);
    field(3, b"\x00plain attachment");
    field(3, b"\x01protected attachment");
    field(0, &[]);
    out
}

/// A KDBX 3.1 file (AES-256-CBC, AES-KDF one round, Salsa20 inner stream) holding `xml`.
pub fn kdbx31_file(xml: &[u8], gz: bool) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(&SIG1.to_le_bytes());
    header.extend_from_slice(&SIG2.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&3u16.to_le_bytes());
    let iv = [3u8; 16];
    let mut field = |id: u8, value: &[u8]| {
        header.push(id);
        header.extend_from_slice(&(value.len() as u16).to_le_bytes());
        header.extend_from_slice(value);
    };
    field(2, &CIPHER_AES256);
    field(3, &u32::from(gz).to_le_bytes());
    field(4, &MASTER_SEED);
    field(5, &KDF_SEED);
    field(6, &1u64.to_le_bytes());
    field(7, &iv);
    field(8, &STREAM_KEY);
    field(9, &STREAM_START);
    field(10, &2u32.to_le_bytes());
    field(0, b"\r\n\r\n");

    let body = if gz { gzip(xml) } else { xml.to_vec() };
    let mut plain = STREAM_START.to_vec();
    plain.extend_from_slice(&0u32.to_le_bytes());
    plain.extend_from_slice(&Sha256::digest(&body));
    plain.extend_from_slice(&(body.len() as u32).to_le_bytes());
    plain.extend_from_slice(&body);
    plain.extend_from_slice(&1u32.to_le_bytes());
    plain.extend_from_slice(&[0u8; 32]);
    plain.extend_from_slice(&0u32.to_le_bytes());
    let e = cbc::Encryptor::<aes::Aes256>::new_from_slices(&payload_key(), &iv).expect("key and IV");
    let ciphertext = e.encrypt_padded_vec_mut::<cbc::cipher::block_padding::Pkcs7>(&plain);

    let mut out = header;
    out.extend_from_slice(&ciphertext);
    out
}

/// Whether running `kdf` is cheap enough to fuzz through (one exec must stay well under a
/// millisecond or two). A file's KDF cost is the file's choice in KDBX: a costly one is slow by
/// design, not a bug, so the whole-file target only reads the header of such files.
pub fn kdf_is_cheap(kdf: &Kdf) -> bool {
    match kdf {
        Kdf::AesKdf { rounds, .. } => *rounds <= 1000,
        Kdf::Argon2 { memory, iterations, parallelism, .. } => {
            *memory <= 1024 * 1024 && *iterations <= 2 && *parallelism <= 4
        }
        Kdf::Other(_) => true,
    }
}

/// After a successful read: writing must succeed or fail cleanly, what ov-kdbx wrote must read
/// back, and the sync merge must run over the two copies.
fn round_trip(db: &ov_kdbx::model::Database, key: &CompositeKey) {
    if !kdf_is_cheap(&db.header.kdf) {
        return;
    }
    let Ok(bytes) = ov_kdbx::write(db, key) else { return };
    let again = match ov_kdbx::read(&bytes, key) {
        Ok(d) => d,
        Err(e) => panic!("ov-kdbx can't read back what it wrote: {e}"),
    };
    let _ = ov_merge::merge(Some(db), db, &again, NOW);
    let _ = ov_merge::merge(None, &again, db, NOW);
}

// ------------------------------------------------------------------------------------- targets

/// `kdbx_header`: the outer header, read without a key.
pub fn kdbx_header(data: &[u8]) {
    if let Ok(h) = ov_kdbx::peek_header(data) {
        let _ = kdf_is_cheap(&h.kdf);
    }
}

/// `kdbx_open`: a whole file, opened with [`key`] when its KDF is cheap.
pub fn kdbx_open(data: &[u8]) {
    let Ok(h) = ov_kdbx::peek_header(data) else { return };
    if kdf_is_cheap(&h.kdf) {
        let _ = ov_kdbx::read(data, &key());
    }
}

/// `kdbx_inner`: the decrypted KDBX 4 payload (inner header + XML). The first byte picks the
/// cipher (bit 0: AES) and compression (bits 1-2: none, compressed by the builder, raw gzip).
pub fn kdbx_inner(data: &[u8]) {
    let Some((&flags, plaintext)) = data.split_first() else { return };
    let cipher = if flags & 1 != 0 { Cipher::Aes } else { Cipher::ChaCha20 };
    let gz = match (flags >> 1) & 3 {
        1 => Gzip::Compress,
        2 => Gzip::Raw,
        _ => Gzip::None,
    };
    let file = kdbx4_file(plaintext, cipher, gz);
    let key = key();
    if let Ok(db) = ov_kdbx::read(&file, &key) {
        round_trip(&db, &key);
    }
}

/// `kdbx_xml`: the XML document, in a KDBX 4 file with [`inner_header`] (bit 0 of the first byte
/// clear) or a KDBX 3.1 file (set); bit 1 compresses it.
pub fn kdbx_xml(data: &[u8]) {
    let Some((&flags, xml)) = data.split_first() else { return };
    let gz = flags & 2 != 0;
    let file = if flags & 1 != 0 {
        kdbx31_file(xml, gz)
    } else {
        let mut plain = inner_header();
        plain.extend_from_slice(xml);
        kdbx4_file(&plain, Cipher::ChaCha20, if gz { Gzip::Compress } else { Gzip::None })
    };
    let key = key();
    if let Ok(db) = ov_kdbx::read(&file, &key) {
        round_trip(&db, &key);
    }
}

/// `kdbx_keyfile`: a key file (XML 1.0/2.0, 32 raw bytes, 64 hex characters, anything else).
pub fn kdbx_keyfile(data: &[u8]) {
    let k = CompositeKey::new().with_key_file(data);
    let _ = k.is_empty();
    let _ = ov_kdbx::vault::password_credentials(Some(&String::from_utf8_lossy(data)), Some(data));
}

const SHARE_KEY: [u8; 32] = [9; 32];
const SHARE_ID: &str = "NV00OunMUMpHjQ03oooedw";
const NONCE: [u8; 24] = [8; 24];

/// `share_link`: the first byte picks what the rest is. 0: link text (link, hash, base64url,
/// TOTP URI, base32); 1: a decrypted share payload (JSON); 2: a decrypted share reference (JSON).
pub fn share_link(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else { return };
    match mode % 3 {
        0 => {
            let text = String::from_utf8_lossy(rest);
            if let Ok(parts) = ov_share::parse_share_link(&text) {
                assert_eq!(parts.id.len(), ov_share::SHARE_ID_CHARS);
                // share_link drops trailing slashes from the base; the rest must survive
                let relinked = ov_share::share_link(&parts.base, &parts.id, &parts.key);
                let again = ov_share::parse_share_link(&relinked).expect("a link share_link made parses");
                assert_eq!(again.id, parts.id);
                assert!(again.key == parts.key, "the key changes on share_link + parse_share_link");
                assert_eq!(again.base, parts.base.trim_end_matches('/'));
            }
            let _ = ov_share::share_key_from_hash(&text);
            if let Ok(open) = ov_share::ShareOpen::from_link(&text, None, None) {
                let _ = open.request_body();
                let _ = open.decrypt_b64u(&text);
            }
            let _ = ov_share::from_b64u(&text);
            if let Ok(p) = ov_share::parse_totp_uri(&text) {
                let _ = ov_share::totp_code(&p, NOW * 1000);
            }
            let _ = ov_share::base32_decode(&text);
            let _ = ov_share::unpad_share(rest);
        }
        1 => {
            let content = ov_share::share_content_key(&SHARE_KEY, None);
            let ct = ov_crypto::envelope::wrap_with_nonce(
                &content,
                &ov_share::pad_share(rest),
                &ov_share::share_aad(SHARE_ID),
                &NONCE,
            );
            let Ok(payload) = ov_share::decrypt_share_payload(&SHARE_KEY, SHARE_ID, &ct, None) else { return };
            // What a client re-shares from an opened payload opens to the same payload
            if let Ok(ct2) = ov_share::encrypt_share_payload_with_nonce(&SHARE_KEY, SHARE_ID, &payload, None, &NONCE) {
                let back = ov_share::decrypt_share_payload(&SHARE_KEY, SHARE_ID, &ct2, None)
                    .expect("a payload ov-share encrypted decrypts");
                assert!(back == payload, "a share payload changes on a re-encrypt round trip");
            }
            let fields: Vec<ov_share::EntryField> =
                payload.fields.iter().map(|f| ov_share::EntryField::new(&*f.label, &*f.value, f.protected)).collect();
            let _ = ov_share::shareable_fields(&fields);
            let names: Vec<String> = fields.iter().map(|f| f.name.to_string()).collect();
            let _ = ov_share::item_share_payload(&fields, &names, payload.shared_by.as_deref());
            if let Some(uri) = ov_share::entry_totp_uri(&fields, payload.title.as_deref().unwrap_or("")) {
                if let Ok(p) = ov_share::parse_totp_uri(&uri) {
                    let _ = ov_share::totp_code(&p, NOW * 1000);
                }
            }
        }
        _ => {
            let enc_sk = [7u8; 32];
            let k = ov_share::share_ref_key(&enc_sk);
            let ct = ov_crypto::envelope::wrap_with_nonce(&k, rest, &ov_share::share_ref_aad(SHARE_ID), &NONCE);
            let _ = ov_share::decrypt_share_ref(&enc_sk, SHARE_ID, &ov_share::b64u(&ct));
        }
    }
}

/// `sse`: an event stream fed in chunks (sizes from the first byte). The events must not depend
/// on where the chunks split, and each one is typed.
pub fn sse(data: &[u8]) {
    use ov_protocol::sse::{to_sync_event, SseParser};
    let Some((&seed, stream)) = data.split_first() else { return };
    let mut whole = SseParser::new();
    let all = whole.feed(stream);
    let mut chunked = SseParser::new();
    let mut evs = Vec::new();
    let mut rest = stream;
    let mut step = usize::from(seed % 17) + 1;
    while !rest.is_empty() {
        let n = step.min(rest.len());
        evs.extend(chunked.feed(&rest[..n]));
        rest = &rest[n..];
        step = step * 7 % 23 + 1;
    }
    assert_eq!(all, evs, "the events depend on how the stream was chunked");
    assert_eq!(whole.retry, chunked.retry, "retry depends on how the stream was chunked");
    for e in &all {
        let _ = to_sync_event(e);
    }
}

/// Splits `Name: value` lines.
fn headers(text: &str) -> Vec<(String, String)> {
    text.lines().filter_map(|l| l.split_once(':')).map(|(k, v)| (k.trim().to_string(), v.trim().to_string())).collect()
}

/// Deserialises `body` as `T`; when it is, the value must survive a serialise + deserialise.
fn json_rt<T: serde::de::DeserializeOwned + serde::Serialize>(body: &[u8]) {
    if let Ok(v) = serde_json::from_slice::<T>(body) {
        let text = serde_json::to_string(&v).expect("a typed body serialises");
        if let Err(e) = serde_json::from_str::<T>(&text) {
            panic!("{} doesn't read back its own JSON: {e}\n{text}", std::any::type_name::<T>());
        }
    }
}

/// `protocol_json`: an HTTP response for the ov-protocol parsers, and the JSON bodies for the wire
/// types. Layout: selector, status (2 bytes BE), header length, `Name: value` lines, body.
pub fn protocol_json(data: &[u8]) {
    use ov_protocol::types::*;
    use ov_protocol::{auth, discovery, sync};
    if data.len() < 4 {
        return;
    }
    let sel = data[0];
    let status = u16::from_be_bytes([data[1], data[2]]);
    let hlen = usize::from(data[3]).min(data.len() - 4);
    let headers = headers(&String::from_utf8_lossy(&data[4..4 + hlen]));
    let body = &data[4 + hlen..];
    let res = ov_protocol::HttpResponse { status, headers, body: body.to_vec() };
    let text = String::from_utf8_lossy(body);

    macro_rules! types {
        ($($t:ty),* $(,)?) => {{
            let all: &[fn(&[u8])] = &[$(json_rt::<$t>),*];
            all
        }};
    }
    let types = types![
        AcceptInvitationRequest,
        AppleEligibility,
        AppleTransactionRecorded,
        AppleTransactionRequest,
        AuditPage,
        Billing,
        BlobHistory,
        BlobList,
        BlobMeta,
        ConfirmMemberRequest,
        CreateOrgRequest,
        CreateServiceAccountRequest,
        CreateShareRequest,
        CreateVaultRequest,
        DeleteAccountRequest,
        DeletionPreview,
        DeletionScheduled,
        DeviceInfo,
        DeviceList,
        EmailChangeRequest,
        EmailCodeSent,
        EmailFinishRequest,
        EmailStartRequest,
        ErrorBody,
        Grant,
        GrantAccessRequest,
        Invitation,
        InvitationList,
        InviteRequest,
        ov_protocol::types::Kdf,
        LoginFinishRequest,
        LoginFinishResponse,
        LoginMfaRequest,
        LoginStartRequest,
        LoginStartResponse,
        Me,
        Member,
        MemberList,
        MemberStatus,
        NewSaSecret,
        OpaqueRegistrationResponse,
        OpenedShare,
        OpenShareRequest,
        discovery::OpenVireoConfiguration,
        Org,
        OrgRole,
        PasswordFinishRequest,
        PasswordStartRequest,
        Plan,
        PlanLimitBody,
        Platform,
        Principal,
        PublicKeys,
        PublicPrincipal,
        PublicShareInfo,
        RecoverFinishRequest,
        RecoverStartRequest,
        RecoveryArchive,
        RecoveryReset,
        RefreshRequest,
        RegisterFinishRequest,
        RegisterStartRequest,
        RegisterStartResponse,
        RenameVaultRequest,
        RestoreFinishRequest,
        RestoreStartRequest,
        RestoreStartResponse,
        RestoreVerified,
        RestoreVerifyRequest,
        SaMasterGrant,
        SaSecret,
        SaSecretList,
        ServiceAccount,
        ServiceAccountExchange,
        ServiceAccountExchangeRequest,
        ServiceAccountList,
        Session,
        SetMemberRoleRequest,
        Share,
        ShareList,
        StartRotationRequest,
        TokenPair,
        TotpCodeRequest,
        TotpEnrolment,
        TransferVaultRequest,
        UpdateOrgRequest,
        UpdateSaSecretRequest,
        UpdateServiceAccountRequest,
        UploadShareRequest,
        Vault,
        VaultAccessList,
        VaultGrant,
        VaultList,
        VaultRole,
        WebSession,
        WrappedKeyset,
    ];
    let parsers: &[fn(&ov_protocol::HttpResponse)] = &[
        |r| drop(auth::parse_register_start(r)),
        |r| drop(auth::parse_session(r)),
        |r| drop(auth::parse_login_start(r)),
        |r| drop(auth::parse_login_finish(r)),
        |r| drop(auth::parse_refresh(r)),
        |r| drop(auth::parse_service_account_exchange(r)),
        |r| drop(auth::parse_recover_info(r)),
        |r| drop(auth::parse_opaque_registration(r)),
        |r| drop(auth::parse_me(r)),
        |r| drop(auth::parse_deletion_preview(r)),
        |r| drop(auth::parse_schedule_deletion(r)),
        |r| drop(auth::parse_recovery_status(r)),
        |r| drop(auth::parse_restore_start(r)),
        |r| drop(auth::parse_restore_verify(r)),
        |r| drop(auth::parse_web_session(r)),
        |r| drop(auth::parse_totp_start(r)),
        |r| drop(auth::parse_public_principal(r)),
        |r| drop(auth::parse_devices(r)),
        |r| drop(auth::parse_org(r)),
        |r| drop(auth::parse_members(r)),
        |r| drop(auth::parse_member(r)),
        |r| drop(auth::parse_invitations(r)),
        |r| drop(auth::parse_invitation(r)),
        |r| drop(auth::parse_vaults(r)),
        |r| drop(auth::parse_vault(r)),
        |r| drop(auth::parse_access(r)),
        |r| drop(auth::parse_service_accounts(r)),
        |r| drop(auth::parse_service_account(r)),
        |r| drop(auth::parse_sa_secrets(r)),
        |r| drop(auth::parse_sa_secret(r)),
        |r| drop(auth::parse_share(r)),
        |r| drop(auth::parse_shares(r)),
        |r| drop(auth::parse_public_share(r)),
        |r| drop(auth::parse_open_share(r)),
        |r| drop(auth::parse_audit(r)),
        |r| drop(auth::parse_apple_eligibility(r)),
        |r| drop(auth::parse_apple_transaction(r)),
        |r| drop(auth::parse_email_request(r)),
        |r| drop(discovery::parse_discovery(r)),
        |r| drop(discovery::parse_jwks(r)),
        |r| drop(sync::parse_blob_head(r)),
        |r| drop(sync::parse_blob_get(r)),
        |r| drop(sync::parse_blob_put(r)),
        |r| drop(sync::parse_blob_delete(r)),
        |r| drop(sync::parse_history(r)),
        |r| drop(sync::parse_revision(r)),
        |r| drop(sync::parse_list_vaults(r)),
        |r| drop(sync::parse_list_databases(r)),
        |r| drop(sync::parse_health(r)),
        |r| drop(sync::parse_pairing_code(r)),
        |r| drop(sync::parse_pairing_claim(r)),
        |r| {
            let _ = sync::server_time_ms(r);
        },
        |r| drop(ov_protocol::error_from_response(r)),
        |r| drop(ov_protocol::check_status(r)),
        |r| drop(ov_protocol::sse::classify_stream_status(r)),
    ];

    let n = types.len() + parsers.len() + 1;
    match usize::from(sel) % n {
        i if i < types.len() => types[i](body),
        i if i < types.len() + parsers.len() => parsers[i - types.len()](&res),
        _ => {
            // Strings clients read from servers, caches and users
            let _ = sync::parse_http_date(&text);
            let _ = sync::is_pairing_code(&text);
            let _ = ov_protocol::url::require_secure_url(&text, "fuzz");
            let _ = ov_crypto::jwt::decode_jwt(&text);
            let _ = ov_crypto::secret_key::parse_secret_key(&text);
            if let Ok(state) = ov_sync::deserialize_sync_state(&text) {
                let json = ov_sync::serialize_sync_state(&state);
                ov_sync::deserialize_sync_state(&json).expect("a sync state reads back its own JSON");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const XML: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><Generator>fuzz</Generator><DatabaseName>Fuzz</DatabaseName></Meta>
<Root><Group><UUID>AAAAAAAAAAAAAAAAAAAAAQ==</UUID><Name>Root</Name>
<Entry><UUID>AAAAAAAAAAAAAAAAAAAAAg==</UUID>
<String><Key>Title</Key><Value>GitHub</Value></String>
<String><Key>Password</Key><Value Protected="True">AAAA</Value></String>
</Entry></Group></Root></KeePassFile>"#;

    #[test]
    fn the_builders_make_files_ov_kdbx_opens() {
        let mut plain = inner_header();
        plain.extend_from_slice(XML.as_bytes());
        for cipher in [Cipher::Aes, Cipher::ChaCha20] {
            for gz in [Gzip::None, Gzip::Compress] {
                let db = ov_kdbx::read(&kdbx4_file(&plain, cipher, gz), &key()).expect("KDBX 4");
                assert_eq!(db.root.entries[0].title(), "GitHub");
                assert_eq!(db.binaries.len(), 2);
            }
        }
        for gz in [false, true] {
            let db = ov_kdbx::read(&kdbx31_file(XML.as_bytes(), gz), &key()).expect("KDBX 3.1");
            assert_eq!(db.root.entries[0].title(), "GitHub");
        }
    }

    /// The KDBX seeds open, so the fuzzer starts from documents that reach the model reader.
    #[test]
    fn the_kdbx_seeds_open() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("seeds");
        for (seed, v31) in [("kdbx_xml/v4", false), ("kdbx_xml/v31", true)] {
            let data = std::fs::read(root.join(seed)).unwrap();
            let file = if v31 {
                kdbx31_file(&data[1..], false)
            } else {
                let mut plain = inner_header();
                plain.extend_from_slice(&data[1..]);
                kdbx4_file(&plain, Cipher::ChaCha20, Gzip::None)
            };
            let db = ov_kdbx::read(&file, &key()).unwrap_or_else(|e| panic!("{seed}: {e}"));
            assert!(!db.root.entries.is_empty(), "{seed}");
        }
        for seed in ["kdbx_inner/chacha", "kdbx_inner/aes-gzip"] {
            let data = std::fs::read(root.join(seed)).unwrap();
            let gz = if data[0] & 2 != 0 { Gzip::Compress } else { Gzip::None };
            let cipher = if data[0] & 1 != 0 { Cipher::Aes } else { Cipher::ChaCha20 };
            ov_kdbx::read(&kdbx4_file(&data[1..], cipher, gz), &key()).unwrap_or_else(|e| panic!("{seed}: {e}"));
        }
    }

    /// Every committed seed and regression input still runs through its target without a panic.
    #[test]
    fn seeds_and_regressions_replay() {
        let targets: &[(&str, fn(&[u8]))] = &[
            ("kdbx_header", kdbx_header),
            ("kdbx_open", kdbx_open),
            ("kdbx_inner", kdbx_inner),
            ("kdbx_xml", kdbx_xml),
            ("kdbx_keyfile", kdbx_keyfile),
            ("share_link", share_link),
            ("sse", sse),
            ("protocol_json", protocol_json),
        ];
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut ran = 0;
        for (name, f) in targets {
            for dir in ["seeds", "regressions"] {
                let Ok(files) = std::fs::read_dir(root.join(dir).join(name)) else { continue };
                for file in files {
                    let path = file.unwrap().path();
                    f(&std::fs::read(&path).unwrap());
                    ran += 1;
                }
            }
        }
        assert!(ran > 0, "no seeds found");
    }
}
