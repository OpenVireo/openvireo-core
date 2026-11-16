//! The [`Host`] the core runs on, built from a JS object (`interface Host` in the `.d.ts`).
//!
//! The package ships ready-made pieces in `host/`: `fetchTransport()`, `indexedDbCache()`,
//! `memoryCache()`, `memoryStore()`, `systemClock`, `consoleLog`. Apps pass their own for
//! anything else (e.g. the web app's WebCrypto-wrapped IndexedDB secure store).
//!
//! JS values can't cross threads, so these adapters exist only on wasm32 (where the Host traits
//! drop `Send + Sync`). On other targets [`from_js`] fails; the crate still builds there so
//! `cargo test` and clippy cover the rest.

use ov_core::host::Host;
use ov_error::OvError;
use wasm_bindgen::JsValue;

#[wasm_bindgen::prelude::wasm_bindgen(typescript_custom_section)]
const HOST_TS: &str = r#"
/** Why a request failed without a response; `fetchTransport` rejects with these. */
export interface TransportFailure { kind: "offline" | "timeout" | "tls" | "cancelled" | "other"; message?: string }
/** An open server-sent events body. */
export interface ByteStream { readonly status: number; nextChunk(): Promise<Uint8Array | null | undefined>; close(): void }
/** HTTP. Must not follow redirects, add cookies or log header values. Rejects with a `TransportFailure` (or a `TypeError` = offline, `AbortError` = cancelled). */
export interface HttpTransport { send(req: HttpRequest): Promise<HttpResponse>; openStream(req: HttpRequest): Promise<ByteStream> }
/** Small persistent secrets (sessions, Secret Keys). Keys are short ASCII strings. */
export interface SecureStore { get(key: string): Promise<Uint8Array | null | undefined>; set(key: string, value: Uint8Array): Promise<void>; delete(key: string): Promise<void> }
/** The offline cache (SPEC §20), keyed by user and vault. Everything in it is ciphertext or public. */
export interface BlobCache {
  load(userId: string, vaultId: string): Promise<CachedVault | null | undefined>;
  save(userId: string, vaultId: string, v: CachedVault): Promise<void>;
  remove(userId: string, vaultId: string): Promise<void>;
  list(userId: string): Promise<string[]>;
  loadMeta(userId: string, name: string): Promise<Uint8Array | null | undefined>;
  saveMeta(userId: string, name: string, value: Uint8Array): Promise<void>;
  clearUser(userId: string): Promise<void>;
}
export interface Clock { nowUnixMs(): number }
export interface LogSink { log(level: LogLevel, target: string, msg: string): void }
/** The platform services the core runs on. */
export interface Host { http: HttpTransport; store: SecureStore; cache: BlobCache; clock: Clock; log: LogSink }
"#;

/// Builds a [`Host`] from the JS `Host` object.
#[cfg(target_arch = "wasm32")]
pub(crate) fn from_js(v: &JsValue) -> Result<Host, OvError> {
    imp::from_js(v)
}

/// Not available off wasm32.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn from_js(_: &JsValue) -> Result<Host, OvError> {
    Err(OvError::internal("the JS Host is only available on wasm32"))
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use std::sync::Arc;

    use js_sys::{Function, Promise, Reflect, Uint8Array};
    use ov_core::host::{
        BlobCache, ByteStream, CachedVault, Clock, Host, HttpRequest, HttpResponse, HttpTransport, Level, LogSink,
        SecureStore, TransportError,
    };
    use ov_error::OvError;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use zeroize::Zeroizing;

    use crate::convert::{bad, get, FromJs, ToJs};

    pub(super) fn from_js(v: &JsValue) -> Result<Host, OvError> {
        let part = |name: &str, methods: &[&str]| -> Result<JsObj, OvError> {
            let o = get(v, name, "host")?;
            for m in methods {
                if !get(&o, m, &format!("host.{name}"))?.is_function() {
                    return Err(bad(&format!("host.{name}.{m}"), "a function"));
                }
            }
            Ok(JsObj(o))
        };
        Ok(Host {
            http: Arc::new(JsHttp(part("http", &["send", "openStream"])?)),
            store: Arc::new(JsStore(part("store", &["get", "set", "delete"])?)),
            cache: Arc::new(JsCache(part(
                "cache",
                &["load", "save", "remove", "list", "loadMeta", "saveMeta", "clearUser"],
            )?)),
            clock: Arc::new(JsClock(part("clock", &["nowUnixMs"])?)),
            log: Arc::new(JsLog(part("log", &["log"])?)),
        })
    }

    /// A JS object whose methods we call.
    struct JsObj(JsValue);

    impl JsObj {
        /// `this.name(...args)`; a throw comes back as `Err(thrown value)`.
        fn call(&self, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
            let f: Function = Reflect::get(&self.0, &JsValue::from_str(name))?.dyn_into()?;
            f.apply(&self.0, &args.iter().collect())
        }

        /// Calls an async method and awaits its promise.
        async fn call_async(&self, name: &str, args: &[JsValue]) -> Result<JsValue, JsValue> {
            let r = self.call(name, args)?;
            JsFuture::from(Promise::resolve(&r)).await
        }

        /// [`call_async`](Self::call_async) for storage: a failure is `internal` (the store or
        /// cache couldn't be used), with the JS error's text.
        async fn storage(&self, what: &str, name: &str, args: &[JsValue]) -> Result<JsValue, OvError> {
            self.call_async(name, args)
                .await
                .map_err(|e| OvError::internal(format!("{what}.{name} failed: {}", describe(&e))))
        }
    }

    /// The text of a thrown JS value (never includes request headers: we only throw these
    /// ourselves or get them from the platform).
    fn describe(e: &JsValue) -> String {
        if let Some(err) = e.dyn_ref::<js_sys::Error>() {
            return String::from(err.message());
        }
        if let Ok(m) = Reflect::get(e, &"message".into()) {
            if let Some(m) = m.as_string() {
                return m;
            }
        }
        e.as_string().unwrap_or_else(|| "unknown error".into())
    }

    /// A rejection from the JS transport as a [`TransportError`].
    fn transport_error(e: &JsValue) -> TransportError {
        let msg = describe(e);
        let kind = Reflect::get(e, &"kind".into()).ok().and_then(|k| k.as_string());
        let name = Reflect::get(e, &"name".into()).ok().and_then(|k| k.as_string());
        match (kind.as_deref(), name.as_deref()) {
            (Some("offline"), _) | (None, Some("TypeError")) => TransportError::Offline,
            (Some("timeout"), _) | (None, Some("TimeoutError")) => TransportError::Timeout,
            (Some("tls"), _) => TransportError::Tls(msg),
            (Some("cancelled"), _) | (None, Some("AbortError")) => TransportError::Cancelled,
            _ => TransportError::Other(msg),
        }
    }

    fn other(e: OvError) -> TransportError {
        TransportError::Other(e.message)
    }

    struct JsHttp(JsObj);

    #[async_trait::async_trait(?Send)]
    impl HttpTransport for JsHttp {
        async fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
            let r = self.0.call_async("send", &[req.to_js()]).await.map_err(|e| transport_error(&e))?;
            HttpResponse::from_js(&r, "HttpResponse").map_err(other)
        }

        async fn open_stream(&self, req: HttpRequest) -> Result<Box<dyn ByteStream>, TransportError> {
            let r = self.0.call_async("openStream", &[req.to_js()]).await.map_err(|e| transport_error(&e))?;
            let status =
                u16::from_js(&get(&r, "status", "ByteStream").map_err(other)?, "ByteStream.status").map_err(other)?;
            Ok(Box::new(JsStream { obj: JsObj(r), status }))
        }
    }

    struct JsStream {
        obj: JsObj,
        status: u16,
    }

    #[async_trait::async_trait(?Send)]
    impl ByteStream for JsStream {
        fn status(&self) -> u16 {
            self.status
        }

        async fn next_chunk(&self) -> Result<Option<Vec<u8>>, TransportError> {
            let r = self.obj.call_async("nextChunk", &[]).await.map_err(|e| transport_error(&e))?;
            Option::<Vec<u8>>::from_js(&r, "ByteStream.nextChunk()").map_err(other)
        }

        fn close(&self) {
            let _ = self.obj.call("close", &[]);
        }
    }

    struct JsStore(JsObj);

    #[async_trait::async_trait(?Send)]
    impl SecureStore for JsStore {
        async fn get(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, OvError> {
            let r = self.0.storage("store", "get", &[key.into()]).await?;
            if r.is_undefined() || r.is_null() {
                return Ok(None);
            }
            let a = r.dyn_ref::<Uint8Array>().ok_or_else(|| bad("store.get()", "a Uint8Array"))?;
            Ok(Some(Zeroizing::new(a.to_vec())))
        }

        async fn set(&self, key: &str, value: &[u8]) -> Result<(), OvError> {
            // The store gets its own copy; the core wipes its side.
            self.0.storage("store", "set", &[key.into(), Uint8Array::from(value).into()]).await.map(drop)
        }

        async fn delete(&self, key: &str) -> Result<(), OvError> {
            self.0.storage("store", "delete", &[key.into()]).await.map(drop)
        }
    }

    struct JsCache(JsObj);

    #[async_trait::async_trait(?Send)]
    impl BlobCache for JsCache {
        async fn load(&self, user_id: &str, vault_id: &str) -> Result<Option<CachedVault>, OvError> {
            let r = self.0.storage("cache", "load", &[user_id.into(), vault_id.into()]).await?;
            Option::<CachedVault>::from_js(&r, "cache.load()")
        }

        async fn save(&self, user_id: &str, vault_id: &str, v: &CachedVault) -> Result<(), OvError> {
            self.0.storage("cache", "save", &[user_id.into(), vault_id.into(), v.to_js()]).await.map(drop)
        }

        async fn remove(&self, user_id: &str, vault_id: &str) -> Result<(), OvError> {
            self.0.storage("cache", "remove", &[user_id.into(), vault_id.into()]).await.map(drop)
        }

        async fn list(&self, user_id: &str) -> Result<Vec<String>, OvError> {
            let r = self.0.storage("cache", "list", &[user_id.into()]).await?;
            Vec::<String>::from_js(&r, "cache.list()")
        }

        async fn load_meta(&self, user_id: &str, name: &str) -> Result<Option<Vec<u8>>, OvError> {
            let r = self.0.storage("cache", "loadMeta", &[user_id.into(), name.into()]).await?;
            Option::<Vec<u8>>::from_js(&r, "cache.loadMeta()")
        }

        async fn save_meta(&self, user_id: &str, name: &str, value: &[u8]) -> Result<(), OvError> {
            let args = [user_id.into(), name.into(), Uint8Array::from(value).into()];
            self.0.storage("cache", "saveMeta", &args).await.map(drop)
        }

        async fn clear_user(&self, user_id: &str) -> Result<(), OvError> {
            self.0.storage("cache", "clearUser", &[user_id.into()]).await.map(drop)
        }
    }

    struct JsClock(JsObj);

    impl Clock for JsClock {
        #[allow(clippy::cast_possible_truncation)]
        fn now_unix_ms(&self) -> i64 {
            // A broken clock adapter falls back to the JS clock rather than failing every call.
            match self.0.call("nowUnixMs", &[]).ok().and_then(|v| v.as_f64()) {
                Some(n) if n.is_finite() => n as i64,
                _ => js_sys::Date::now() as i64,
            }
        }
    }

    struct JsLog(JsObj);

    impl LogSink for JsLog {
        fn log(&self, level: Level, target: &str, msg: &str) {
            let _ = self.0.call("log", &[level.to_js(), target.into(), msg.into()]);
        }
    }
}
