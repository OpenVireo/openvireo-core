// The handle classes implement `[Symbol.dispose]` (wasm-bindgen): TypeScript users need
// `"lib": [..., "esnext.disposable"]` (or `esnext`).
import type * as Glue from "./gen/ov_wasm.js";
export { OvError, type OvErrorOptions } from "./error.js";

// Every record, enum, handle class and Host interface, as types. The values come from `loadCore()`.
export type * from "./gen/ov_wasm.js";

/** Glue exports that aren't part of the API. */
type Hidden = "default" | "initSync" | "__install" | "__scrubStack" | "__testPanic" | "__testPanicAsync";

/** The full module's API: the handle classes (`OvClient`, `Account`, `Vault`, `Kdbx`, …) and free functions. */
export type Core = Omit<typeof Glue, Hidden> & {
  /** Whether a panic has made this instance unusable (load a fresh one). */
  readonly poisoned: boolean;
};

export interface LoadOptions {
  /** The .wasm to use instead of the embedded copy: bytes, a compiled module, a URL or a Response. */
  wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response>;
  /** A new, separate instance (after a panic poisoned the old one). Node, Bun or unbundled ESM only. */
  fresh?: boolean;
}

/** Loads the full module once and returns the API; rejects with `OvError("internal")` if it can't load. */
export function loadCore(opts?: LoadOptions): Promise<Core>;
