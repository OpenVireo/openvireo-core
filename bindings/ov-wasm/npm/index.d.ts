// The handle classes implement `[Symbol.dispose]` (wasm-bindgen): TypeScript users need
// `"lib": [..., "esnext.disposable"]` (or `esnext`).
import type * as Glue from "./gen/ov_wasm.js";

// Every record, enum, handle class and Host interface, as types. The values come from `loadCore()`.
export type * from "./gen/ov_wasm.js";

/** The core's API: the handle classes (`OvClient`, `Account`, `Vault`, …) and free functions. */
export type Core = Omit<typeof Glue, "default" | "initSync" | "__install"> & {
  /** Whether a panic has made this instance unusable (load a fresh one). */
  readonly poisoned: boolean;
};

export interface OvErrorOptions {
  status?: number;
  retryAfter?: number;
  details?: Record<string, unknown> | string;
  serverCode?: string;
  cause?: unknown;
}

/** The one error type of the core. `code` is the stable wire string (`"plan_limit"`, `"internal"`, …). */
export class OvError extends Error {
  constructor(code: string, message: string, opts?: OvErrorOptions);
  readonly name: "OvError";
  /** The wire code: an `OvErrorCode` string, or an untyped server code. */
  code: string;
  status?: number;
  retryAfter?: number;
  /** The SDK's camelCase details object. */
  details?: Record<string, unknown> | string;
  /** A server code the core has no variant for (then `code` holds it too). */
  serverCode?: string;
  /** Network error or 502/503/504 (the SDK's `isUnreachable`). */
  readonly isUnreachable: boolean;
}

export interface LoadOptions {
  /** The .wasm to use instead of the embedded copy: bytes, a compiled module, a URL or a Response. */
  wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response>;
  /** A new, separate instance (after a panic poisoned the old one). */
  fresh?: boolean;
}

/** Loads the module once and returns the API; rejects with `OvError("internal")` if it can't load. */
export function loadCore(opts?: LoadOptions): Promise<Core>;
