//! Share links (SPEC §22) and TOTP over `ov-share`: the content crypto, link parsing, payload
//! builders, opening a link, and RFC 6238 codes. In both modules (shared with
//! `bindings/ov-wasm-lite`), so the public share page needs only the small module.
//!
//! Values that are secret in the SDK's types (field values, TOTP secrets and codes, links) are
//! `Uint8Array` (UTF-8) here, as in the facade records; text secret inputs also accept a string.

use js_sys::Uint8Array;
use ov_crypto::auk::{KdfMin, KdfParams};
use ov_error::OvError;
use ov_share::{EntryField, ShareField, ShareLinkParts, SharePayload, ShareRef, TotpAlgorithm, TotpCode, TotpParams};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::convert::{arg, array, bad, field, fixed, obj, out, record, set, unit_enum, FromJs, SecretText, ToJs};
use crate::error::{arg_err, js, to_js};
use crate::primitives::bytes_out;

// ----------------------------------------------------------------------------------- records

record!(KdfParams => KdfParams { alg: alg ": string", salt: salt ": string", m: m ": number", t: t ": number", p: p ": number" });
record!(KdfMin => KdfMin { m: m ": number", t: t ": number" });
record!(ShareRef => ShareRef { vault: vault "?: string", entry: entry "?: string", title: title ": string" });
unit_enum!(TotpAlgorithm => TotpAlgorithm { Sha1 => "SHA1", Sha256 => "SHA256", Sha512 => "SHA512" });

#[wasm_bindgen(typescript_custom_section)]
const SHARE_TS: &str = "\
/** What a share link holds (SPEC §22). Field values are UTF-8. */
export interface SharePayload { v: number; kind: string; title?: string; sharedBy?: string; fields: ShareField[] }
/** `k`: `username`, `password`, `url`, `notes`, `totp`, `custom` or `text` (open set). */
export interface ShareField { k: string; label: string; value: Uint8Array; protected: boolean }
/** A field an entry can share (`name` is the entry field, `kind` the share kind it becomes). */
export interface ShareableField { name: string; kind: string; label: string; value: Uint8Array; protected: boolean }
/** One string field of an entry. */
export interface FieldRecord { name: string; value: Uint8Array; protected: boolean }
/** A parsed share link: `base` (the page), the share `id` and the 32-byte `key` from the fragment. */
export interface ShareLinkParts { base: string; id: string; key: Uint8Array }
/** Steam Guard codes: `encoder: \"steam\"` (the facade's spelling) or `steam: true` (the SDK's); both are set on output. */
export interface TotpParams { secret: Uint8Array; digits: number; period: number; algorithm: TotpAlgorithm; encoder?: string; steam?: boolean }
/** The code (UTF-8 digits) and the seconds it stays valid. */
export interface TotpCode { code: Uint8Array; remaining: number }
";

fn text_to_js(s: &str) -> JsValue {
    out(s.as_bytes()).into()
}

fn text_from_js(v: &JsValue, path: &str) -> Result<String, OvError> {
    let mut t = SecretText::from_js(v, path)?;
    Ok(std::mem::take(&mut *t.0))
}

impl ToJs for ShareField {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "k", self.k.to_js());
        set(&o, "label", self.label.to_js());
        set(&o, "value", text_to_js(&self.value));
        set(&o, "protected", self.protected.to_js());
        o.into()
    }
}
impl FromJs for ShareField {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(ShareField {
            k: field(v, "k", path)?,
            label: field(v, "label", path)?,
            value: text_from_js(&crate::convert::get(v, "value", path)?, &format!("{path}.value"))?,
            protected: field::<Option<bool>>(v, "protected", path)?.unwrap_or(false),
        })
    }
}
impl crate::convert::Elem for ShareField {}

impl ToJs for SharePayload {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "v", self.v.to_js());
        set(&o, "kind", self.kind.to_js());
        set(&o, "title", self.title.to_js());
        set(&o, "sharedBy", self.shared_by.to_js());
        set(&o, "fields", self.fields.to_js());
        o.into()
    }
}
impl FromJs for SharePayload {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        Ok(SharePayload {
            v: field::<Option<u32>>(v, "v", path)?.unwrap_or(1),
            kind: field(v, "kind", path)?,
            title: field(v, "title", path)?,
            shared_by: field(v, "sharedBy", path)?,
            fields: field(v, "fields", path)?,
        })
    }
}

/// `{ name, value, protected }` → `EntryField`.
impl FromJs for EntryField {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let name: String = field(v, "name", path)?;
        let value = text_from_js(&crate::convert::get(v, "value", path)?, &format!("{path}.value"))?;
        Ok(EntryField::new(name, value, field::<Option<bool>>(v, "protected", path)?.unwrap_or(false)))
    }
}
impl ToJs for EntryField {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "name", self.name.to_js());
        set(&o, "value", text_to_js(&self.value));
        set(&o, "protected", self.protected.to_js());
        o.into()
    }
}
impl crate::convert::Elem for EntryField {}

impl ToJs for ov_share::ShareableField {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "name", self.name.to_js());
        set(&o, "kind", self.field.k.to_js());
        set(&o, "label", self.field.label.to_js());
        set(&o, "value", text_to_js(&self.field.value));
        set(&o, "protected", self.field.protected.to_js());
        o.into()
    }
}
impl FromJs for ov_share::ShareableField {
    fn from_js(_: &JsValue, path: &str) -> Result<Self, OvError> {
        Err(bad(path, "no ShareableField input"))
    }
}
impl crate::convert::Elem for ov_share::ShareableField {}

impl ToJs for ShareLinkParts {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "base", self.base.to_js());
        set(&o, "id", self.id.to_js());
        set(&o, "key", self.key.to_js());
        o.into()
    }
}

impl ToJs for TotpParams {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "secret", out(&self.secret).into());
        set(&o, "digits", self.digits.to_js());
        set(&o, "period", self.period.to_js());
        set(&o, "algorithm", self.algorithm.to_js());
        if self.steam {
            set(&o, "encoder", "steam".to_string().to_js());
            set(&o, "steam", true.to_js());
        }
        o.into()
    }
}
impl FromJs for TotpParams {
    fn from_js(v: &JsValue, path: &str) -> Result<Self, OvError> {
        let mut secret: Zeroizing<Vec<u8>> = field(v, "secret", path)?;
        let encoder: Option<String> = field(v, "encoder", path)?;
        Ok(TotpParams {
            secret: std::mem::take(&mut *secret),
            algorithm: field(v, "algorithm", path)?,
            digits: field(v, "digits", path)?,
            period: field(v, "period", path)?,
            steam: encoder.is_some_and(|e| e.eq_ignore_ascii_case("steam"))
                || field::<Option<bool>>(v, "steam", path)?.unwrap_or(false),
        })
    }
}

impl ToJs for TotpCode {
    fn to_js(&self) -> JsValue {
        let o = obj();
        set(&o, "code", self.code.to_js());
        set(&o, "remaining", self.remaining.to_js());
        o.into()
    }
}

/// An entry's fields from `{ fields: FieldRecord[] }` (an `EntryRecord` will do) or a `FieldRecord[]`.
fn entry_fields(entry: &JsValue, path: &str) -> Result<Vec<EntryField>, OvError> {
    if js_sys::Array::is_array(entry) {
        return arg(entry, path);
    }
    field(entry, "fields", path)
}

fn key32(v: Vec<u8>, path: &str) -> Result<Zeroizing<[u8; 32]>, JsValue> {
    let v = Zeroizing::new(v);
    fixed::<32>(&v, path).map_err(arg_err)
}

fn opt_key32(v: Option<Vec<u8>>, path: &str) -> Result<Option<Zeroizing<[u8; 32]>>, JsValue> {
    v.map(|v| key32(v, path)).transpose()
}

fn nonce24(v: Option<Vec<u8>>) -> Result<Option<[u8; 24]>, JsValue> {
    v.map(|n| array::<24>(&n, "nonce").map_err(arg_err)).transpose()
}

// -------------------------------------------------------------------------------- content crypto

/// Pads share content to a multiple of 512 bytes (`0x80` then zeroes).
#[wasm_bindgen(js_name = padShare)]
pub fn pad_share(data: Vec<u8>) -> Uint8Array {
    let data = Zeroizing::new(data);
    out(&ov_share::pad_share(&data))
}

/// Removes the padding; `decryption_failed` when it is malformed.
#[wasm_bindgen(js_name = unpadShare)]
pub fn unpad_share(padded: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let padded = Zeroizing::new(padded);
    bytes_out(ov_share::unpad_share(&padded))
}

/// A fresh 32-byte link key.
#[wasm_bindgen(js_name = newShareKey)]
pub fn new_share_key() -> Result<Uint8Array, JsValue> {
    bytes_out(ov_share::new_share_key())
}

/// Argon2id of the NFKC passcode with the share's `kdf` (SPEC §22). `weak_kdf` below the SPEC §3
/// minimum unless `allowWeak` (test vectors only).
#[wasm_bindgen(js_name = sharePasscodeKey)]
pub fn share_passcode_key(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] passcode: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KdfParams")] kdf: JsValue,
    allow_weak: Option<bool>,
) -> Result<Uint8Array, JsValue> {
    let passcode: SecretText = arg(&passcode, "passcode").map_err(arg_err)?;
    let kdf: KdfParams = arg(&kdf, "kdf").map_err(arg_err)?;
    bytes_out(ov_share::share_passcode_key(&passcode, &kdf, allow_weak.unwrap_or(false)))
}

/// HKDF(key, salt = passcodeKey or empty, "ov-share-v1"): the content key.
#[wasm_bindgen(js_name = shareContentKey)]
pub fn share_content_key(key: Vec<u8>, passcode_key: Option<Vec<u8>>) -> Result<Uint8Array, JsValue> {
    let key = key32(key, "key")?;
    let pk = opt_key32(passcode_key, "passcodeKey")?;
    Ok(out(&ov_share::share_content_key(&key, pk.as_deref())[..]))
}

/// The `auth` value a passcode share's open request sends: HKDF(passcodeKey, "ov-share-auth-v1").
#[wasm_bindgen(js_name = shareAuth)]
pub fn share_auth(passcode_key: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let pk = key32(passcode_key, "passcodeKey")?;
    Ok(out(&ov_share::share_auth(&pk)[..]))
}

/// SHA-256 of `auth` (what the server stores).
#[wasm_bindgen(js_name = shareAuthHash)]
pub fn share_auth_hash(auth: Vec<u8>) -> Uint8Array {
    let auth = Zeroizing::new(auth);
    out(&ov_share::share_auth_hash(&auth))
}

/// Encrypts a payload under the link key (and passcode key): the share's `ct` bytes. `nonce` is
/// for test vectors only. `too_large` past 64 KiB.
#[wasm_bindgen(js_name = encryptSharePayload)]
pub fn encrypt_share_payload(
    key: Vec<u8>,
    id: &str,
    #[wasm_bindgen(unchecked_param_type = "SharePayload")] payload: JsValue,
    passcode_key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
) -> Result<Uint8Array, JsValue> {
    let key = key32(key, "key")?;
    let pk = opt_key32(passcode_key, "passcodeKey")?;
    let nonce = nonce24(nonce)?;
    let payload: SharePayload = arg(&payload, "payload").map_err(arg_err)?;
    let r = match nonce {
        Some(n) => ov_share::encrypt_share_payload_with_nonce(&key, id, &payload, pk.as_deref(), &n),
        None => ov_share::encrypt_share_payload(&key, id, &payload, pk.as_deref()),
    };
    bytes_out(r)
}

/// Decrypts a share's `ct` bytes; `decryption_failed` for a wrong key, passcode or id.
#[wasm_bindgen(js_name = decryptSharePayload, unchecked_return_type = "SharePayload")]
pub fn decrypt_share_payload(
    key: Vec<u8>,
    id: &str,
    ct: &[u8],
    passcode_key: Option<Vec<u8>>,
) -> Result<JsValue, JsValue> {
    let key = key32(key, "key")?;
    let pk = opt_key32(passcode_key, "passcodeKey")?;
    js(ov_share::decrypt_share_payload(&key, id, ct, pk.as_deref()))
}

/// HKDF(encSk, "ov-share-ref-v1"): the owner's key for share references.
#[wasm_bindgen(js_name = shareRefKey)]
pub fn share_ref_key(enc_sk: Vec<u8>) -> Uint8Array {
    let sk = Zeroizing::new(enc_sk);
    out(&ov_share::share_ref_key(&sk)[..])
}

/// Encrypts the owner's reference (`{vault, entry, title}`) to base64url. `nonce` for test vectors only.
#[wasm_bindgen(js_name = encryptShareRef)]
pub fn encrypt_share_ref(
    enc_sk: Vec<u8>,
    id: &str,
    #[wasm_bindgen(unchecked_param_type = "ShareRef")] reference: JsValue,
    nonce: Option<Vec<u8>>,
) -> Result<String, JsValue> {
    let sk = Zeroizing::new(enc_sk);
    let nonce = nonce24(nonce)?;
    let r: ShareRef = arg(&reference, "ref").map_err(arg_err)?;
    match nonce {
        Some(n) => ov_share::encrypt_share_ref_with_nonce(&sk, id, &r, &n),
        None => ov_share::encrypt_share_ref(&sk, id, &r),
    }
    .map_err(|e| to_js(&e))
}

/// Decrypts an owner's reference.
#[wasm_bindgen(js_name = decryptShareRef, unchecked_return_type = "ShareRef")]
pub fn decrypt_share_ref(enc_sk: Vec<u8>, id: &str, reference: &str) -> Result<JsValue, JsValue> {
    let sk = Zeroizing::new(enc_sk);
    js(ov_share::decrypt_share_ref(&sk, id, reference))
}

// ------------------------------------------------------------------------------------- links

/// `<base>/<id>#<base64url key>` (UTF-8).
#[wasm_bindgen(js_name = shareLink)]
pub fn share_link(base: &str, id: &str, key: Vec<u8>) -> Result<Uint8Array, JsValue> {
    let key = key32(key, "key")?;
    Ok(out(ov_share::share_link(base, id, &key).as_bytes()))
}

/// Splits a share link; `invalid_link` when it isn't a complete one.
#[wasm_bindgen(js_name = parseShareLink, unchecked_return_type = "ShareLinkParts")]
pub fn parse_share_link(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] link: JsValue,
) -> Result<JsValue, JsValue> {
    let link: SecretText = arg(&link, "link").map_err(arg_err)?;
    js(ov_share::parse_share_link(&link))
}

/// The link key from a URL fragment (`#…` or without the `#`).
#[wasm_bindgen(js_name = shareKeyFromHash)]
pub fn share_key_from_hash(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] hash: JsValue,
) -> Result<Uint8Array, JsValue> {
    let hash: SecretText = arg(&hash, "hash").map_err(arg_err)?;
    bytes_out(ov_share::share_key_from_hash(&hash))
}

/// A share link being opened (the TS `openShare` minus HTTP): built from the link, the share's
/// public `kdf` (when it has a passcode) and the passcode, so the Argon2 work happens once. Send
/// `requestBody()` to `POST {api}/public/shares/{id}/open`, then `decrypt` the returned `ct`.
/// `free()` wipes the keys.
#[wasm_bindgen(js_name = ShareOpen)]
pub struct ShareOpenJs(ov_share::ShareOpen);

#[wasm_bindgen(js_class = ShareOpen)]
impl ShareOpenJs {
    /// `passcode_required` when the share has a `kdf` and no passcode is given, `weak_kdf` below the
    /// SPEC minimum, `invalid_link` for a bad link.
    #[wasm_bindgen(constructor)]
    pub fn new(
        #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] link: JsValue,
        #[wasm_bindgen(unchecked_optional_param_type = "KdfParams")] kdf: Option<JsValue>,
        #[wasm_bindgen(unchecked_optional_param_type = "string | Uint8Array")] passcode: Option<JsValue>,
    ) -> Result<ShareOpenJs, JsValue> {
        let kdf = kdf.unwrap_or(JsValue::UNDEFINED);
        let passcode = passcode.unwrap_or(JsValue::UNDEFINED);
        let link: SecretText = arg(&link, "link").map_err(arg_err)?;
        let kdf: Option<KdfParams> = arg(&kdf, "kdf").map_err(arg_err)?;
        let passcode: Option<SecretText> = arg(&passcode, "passcode").map_err(arg_err)?;
        ov_share::ShareOpen::from_link(&link, kdf.as_ref(), passcode.as_deref()).map(ShareOpenJs).map_err(|e| to_js(&e))
    }

    /// The share id.
    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.0.id().to_string()
    }

    /// The link's base (the share page).
    #[wasm_bindgen(getter)]
    pub fn base(&self) -> String {
        self.0.link().base.clone()
    }

    /// `auth` (base64url) when the share has a passcode.
    #[wasm_bindgen(getter, unchecked_return_type = "Uint8Array | undefined")]
    pub fn auth(&self) -> JsValue {
        self.0.auth().map_or(JsValue::UNDEFINED, |a| out(a.as_bytes()).into())
    }

    /// The JSON body of the open request (UTF-8): `{"auth":"…"}` or `{}`.
    #[wasm_bindgen(js_name = requestBody)]
    pub fn request_body(&self) -> Uint8Array {
        out(self.0.request_body().as_bytes())
    }

    /// Decrypts the share's `ct` (bytes, or base64url as the server sends it).
    #[wasm_bindgen(unchecked_return_type = "SharePayload")]
    pub fn decrypt(
        &self,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array | string")] ct: JsValue,
    ) -> Result<JsValue, JsValue> {
        match ct.as_string() {
            Some(s) => js(self.0.decrypt_b64u(&s)),
            None => {
                let b: Vec<u8> = arg(&ct, "ct").map_err(arg_err)?;
                js(self.0.decrypt(&b))
            }
        }
    }
}

/// Opens a share in one step from its link, `kdf`, passcode and the fetched `ct` (base64url).
#[wasm_bindgen(js_name = openShareContent, unchecked_return_type = "SharePayload")]
pub fn open_share_content(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] link: JsValue,
    #[wasm_bindgen(unchecked_param_type = "KdfParams | undefined")] kdf: Option<JsValue>,
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array | undefined")] passcode: Option<JsValue>,
    ct: &str,
) -> Result<JsValue, JsValue> {
    let kdf = kdf.unwrap_or(JsValue::UNDEFINED);
    let passcode = passcode.unwrap_or(JsValue::UNDEFINED);
    let link: SecretText = arg(&link, "link").map_err(arg_err)?;
    let kdf: Option<KdfParams> = arg(&kdf, "kdf").map_err(arg_err)?;
    let passcode: Option<SecretText> = arg(&passcode, "passcode").map_err(arg_err)?;
    js(ov_share::open_share(&link, kdf.as_ref(), passcode.as_deref(), ct))
}

// ---------------------------------------------------------------------------------- payloads

/// The fields an item share includes by default.
#[wasm_bindgen(js_name = defaultShareFields)]
pub fn default_share_fields() -> Vec<String> {
    ov_share::default_share_fields()
}

/// The fields of an entry that can be shared (standard ones first, then the TOTP code source, then
/// custom fields). `entry` is `{ fields: FieldRecord[] }` (an `EntryRecord`) or a `FieldRecord[]`.
#[wasm_bindgen(js_name = shareableFields, unchecked_return_type = "ShareableField[]")]
pub fn shareable_fields(
    #[wasm_bindgen(unchecked_param_type = "{ fields: FieldRecord[] } | FieldRecord[]")] entry: JsValue,
) -> Result<JsValue, JsValue> {
    let fields = entry_fields(&entry, "entry").map_err(arg_err)?;
    Ok(ov_share::shareable_fields(&fields).to_js())
}

/// The payload of an item share with the named fields.
#[wasm_bindgen(js_name = itemSharePayload, unchecked_return_type = "SharePayload")]
pub fn item_share_payload(
    #[wasm_bindgen(unchecked_param_type = "{ fields: FieldRecord[] } | FieldRecord[]")] entry: JsValue,
    names: Vec<String>,
    shared_by: Option<String>,
) -> Result<JsValue, JsValue> {
    let fields = entry_fields(&entry, "entry").map_err(arg_err)?;
    Ok(ov_share::item_share_payload(&fields, &names, shared_by.as_deref()).to_js())
}

/// The payload of a text share.
#[wasm_bindgen(js_name = textSharePayload, unchecked_return_type = "SharePayload")]
pub fn text_share_payload(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] text: JsValue,
    title: Option<String>,
    shared_by: Option<String>,
) -> Result<JsValue, JsValue> {
    let text: SecretText = arg(&text, "text").map_err(arg_err)?;
    Ok(ov_share::text_share_payload(&text, title.as_deref(), shared_by.as_deref()).to_js())
}

// -------------------------------------------------------------------------------------- TOTP

/// Parses an `otpauth://totp/` URI (KeePassXC's `otp` field).
#[wasm_bindgen(js_name = parseTotpUri, unchecked_return_type = "TotpParams")]
pub fn parse_totp_uri(
    #[wasm_bindgen(unchecked_param_type = "string | Uint8Array")] uri: JsValue,
) -> Result<JsValue, JsValue> {
    let uri: SecretText = arg(&uri, "uri").map_err(arg_err)?;
    js(ov_share::parse_totp_uri(&uri))
}

/// The TOTP code at `nowMs` (Unix milliseconds).
#[wasm_bindgen(js_name = totpCode, unchecked_return_type = "TotpCode")]
pub fn totp_code(
    #[wasm_bindgen(unchecked_param_type = "TotpParams")] params: JsValue,
    now_ms: f64,
) -> Result<JsValue, JsValue> {
    let params: TotpParams = arg(&params, "params").map_err(arg_err)?;
    let now =
        crate::convert::int(&JsValue::from_f64(now_ms), "nowMs", -crate::convert::MAX_SAFE, crate::convert::MAX_SAFE)
            .map_err(arg_err)?;
    #[allow(clippy::cast_possible_truncation)]
    Ok(ov_share::totp_code(&params, now as i64).to_js())
}

/// An entry's TOTP URI from its fields (`otp`, or KeePass's `TOTP Seed`/`TOTP Settings`).
#[wasm_bindgen(js_name = entryTotpUri, unchecked_return_type = "Uint8Array | undefined")]
pub fn entry_totp_uri(
    #[wasm_bindgen(unchecked_param_type = "{ fields: FieldRecord[] } | FieldRecord[]")] fields: JsValue,
    label: String,
) -> Result<JsValue, JsValue> {
    let fields = entry_fields(&fields, "fields").map_err(arg_err)?;
    Ok(ov_share::entry_totp_uri(&fields, &label).to_js())
}
