import type * as Glue from "./gen/lite/ov_wasm_lite.js";
export { OvError, type OvErrorOptions } from "./error.js";

// The lite module's records (`SharePayload`, `TotpParams`, `KdfParams`, …) and the `ShareOpen` class, as types.
export type * from "./gen/lite/ov_wasm_lite.js";

type Hidden = "default" | "initSync" | "__install" | "__scrubStack" | "__testPanic";

/** The lite module's API: primitives, share links and TOTP. */
export type LiteCore = Omit<typeof Glue, Hidden> & {
  /** Whether a panic has made this instance unusable. */
  readonly poisoned: boolean;
};

export interface LiteLoadOptions {
  /** The .wasm to use instead of the embedded copy: bytes, a compiled module, a URL or a Response. */
  wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response>;
}

/** Loads the lite module once; rejects with `OvError("internal")` if it can't load. */
export function loadLite(opts?: LiteLoadOptions): Promise<LiteCore>;
