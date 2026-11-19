import type { LiteCore } from "./lite.js";
export type * from "./lite.js";
export { OvError, type OvErrorOptions } from "./error.js";

/** The lite module, instantiated synchronously on the first call (then cached). */
export function loadLiteSync(opts?: { wasm?: BufferSource | WebAssembly.Module }): LiteCore;
