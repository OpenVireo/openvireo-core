//! Wire types for `openapi.yaml` and `sync-openapi.yaml`, pure request builders and response
//! parsers, the HTTP status → `OvError` mapping, the SSE parser and discovery (SPEC §9-§11).
//!
//! No async and no Host: each route is a `build_*` function that returns an [`HttpRequest`] and a
//! `parse_*` function that reads the [`HttpResponse`]. Callers send the requests through
//! `ov_core::host::HttpTransport` (whose request and response types are these, from `ov-http`).
//!
//! - [`auth`]: every client route of the auth server (`{api}`), on [`auth::AuthApi`].
//! - [`sync`]: the sync server's blob, list, history, pairing and event routes, on [`sync::SyncApi`].
//! - [`sse`]: the `text/event-stream` parser, the event types and the reconnect policy.
//! - [`discovery`]: `/.well-known/openvireo-configuration` and the JWKS.
//! - [`error`]: status + body → `OvError`, as `http/request.ts` does it.
//! - [`types`]: the JSON bodies.
//!
//! `cargo xtask openapi` checks that every request and response of the contract round-trips
//! through the types here (`tests/openapi.rs`).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod discovery;
pub mod error;
pub mod http;
pub mod types;
pub mod url;

pub use error::{check_status, error_from_response, parse_empty, parse_json};
pub use http::{HttpRequest, HttpResponse, Method};
