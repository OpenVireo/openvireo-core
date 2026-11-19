import type { Core } from "./index.js";
export type * from "./index.js";
export { OvError, type OvErrorOptions } from "./error.js";

export interface SyncLoadOptions {
  /** The .wasm bytes or compiled module to use instead of the embedded copy. */
  wasm?: BufferSource | WebAssembly.Module;
}

/** The full module, instantiated synchronously on the first call (then cached); throws `OvError("internal")` if it can't load. */
export function loadCoreSync(opts?: SyncLoadOptions): Core;
