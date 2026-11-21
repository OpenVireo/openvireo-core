//! The vault sync state machine (SPEC §11, §20), ported from the TS SDK's `sync/engine.ts` and
//! `sync/events.ts`: download, merge, conditional upload with retries, deletions, rollback and
//! lost-database detection, the offline cache and the clock-skew check.
//!
//! - [`client`]: [`SyncClient`] and [`Blob`] send ov-protocol's requests through
//!   [`ov_host::HttpTransport`], with the bearer token from a [`TokenSource`] (one retry with a
//!   fresh token after a 401) and the clock offset from the `Date` header.
//! - [`engine`]: [`sync_kdbx`] (TS `syncKdbx`): HEAD/GET → open → three-way merge with the base
//!   (ov-merge) → conditional PUT → on 412 download, merge and retry; `server_rolled_back`,
//!   `server_lost_database`, `too_many_conflicts`; [`is_clock_skewed`].
//! - [`state`]: [`SyncState`] and its JSON, identical to the TS SDK's so stored states carry over.
//! - [`offline`]: [`VaultSession`] (TS `AccountVault`): the working copy, pending edits kept in the
//!   [`ov_host::BlobCache`] while offline, and opening the cached copy offline.
//! - [`events`]: [`EventStream`], the `{sync}/events` stream with reconnects and backoff, pulled by
//!   the caller (the Host has no timer).
//!
//! The crate is portable (no threads, no timers, no I/O of its own) and doesn't depend on ov-core.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod client;
pub mod engine;
pub mod events;
pub mod offline;
pub mod state;

pub use client::{Blob, StaticToken, SyncClient, TokenSource};
pub use engine::{
    is_clock_skewed, open_with, sync_kdbx, BaseCache, BeforeUpload, Cancel, Progress, SyncOptions, SyncOutcome,
    SyncResult, SyncStep, CLOCK_SKEW_WARNING_MS,
};
pub use events::{EventStream, EventStreamOptions, StreamItem};
pub use offline::{SessionSyncOptions, VaultCache, VaultSession};
pub use ov_merge::{ConflictKind, MergeChange, SyncConflict};
pub use ov_protocol::sse::{AccessChange, SyncEvent};
pub use state::{deserialize_sync_state, serialize_sync_state, SyncState};
