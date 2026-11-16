import type { BlobCache, Clock, HttpTransport, LogLevel, LogSink, SecureStore } from "../gen/ov_wasm.js";

export interface FetchTransportOptions {
  /** The `fetch` to use (default `globalThis.fetch`). */
  fetch?: typeof fetch;
  /** Abort a request after this many ms (`timeout`); default none. */
  timeoutMs?: number;
}

/** HTTP over `fetch`: `redirect: "error"`, `credentials: "omit"`, `cache: "no-store"`; SSE through the response body. */
export function fetchTransport(opts?: FetchTransportOptions): HttpTransport;

export interface IndexedDbCacheOptions {
  /** Database name (default `"openvireo-core-cache"`). */
  name?: string;
  /** The `IDBFactory` (default `globalThis.indexedDB`). */
  indexedDB?: IDBFactory;
}

/** The offline cache in IndexedDB (ciphertext and public data only). */
export function indexedDbCache(opts?: IndexedDbCacheOptions): BlobCache & { close(): void };

/** An in-memory offline cache (tests, Node). */
export function memoryCache(): BlobCache;

/** An in-memory secure store for tests: nothing persists, values are wiped on delete and overwrite. */
export function memoryStore(): SecureStore & { readonly size: number };

export const systemClock: Clock;
export function consoleLog(minLevel?: LogLevel): LogSink;
