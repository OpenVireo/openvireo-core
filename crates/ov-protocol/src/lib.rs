//! Wire types for `openapi.yaml` and `sync-openapi.yaml`, pure request builders and response
//! parsers, the HTTP status → `OvError` mapping, the SSE parser and discovery (SPEC §9-§11).
//!
//! No async and no Host: callers send the built requests through `ov_core::host::HttpTransport`.
//! Filled in by W1-P.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
