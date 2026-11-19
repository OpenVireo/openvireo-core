// @openvireo/core-wasm/sync: the full module, loaded synchronously (no top-level await), for
// libraries whose public functions are synchronous.
//
//   import { loadCoreSync } from "@openvireo/core-wasm/sync";
//   const core = loadCoreSync(); // compiles and instantiates on the first call, then cached
//
// This entry imports the embedded module statically, so a bundle that imports it carries the whole
// .wasm (as base64) up front. It shares its instance with `loadCore()` from the main entry.
//
// Synchronous compilation (`new WebAssembly.Module`) is fine in Node, Bun, Deno and workers. Browsers
// may refuse to compile a large module synchronously on the main thread; there, call `loadCore()`
// once at startup and the synchronous functions after it resolves.

import * as glue from "./gen/ov_wasm.js";
import b64 from "./gen/wasm-base64.js";
import { OvError } from "./error.js";
import { decodeBase64, loadError, wrap } from "./internal.js";

export { OvError };

let api = null;

/**
 * The full module's API, instantiated synchronously on first use.
 * @param {{ wasm?: BufferSource | WebAssembly.Module }} [opts] the .wasm to use instead of the embedded copy
 */
export function loadCoreSync(opts = {}) {
  if (api !== null) return api;
  try {
    glue.initSync({ module: opts.wasm ?? decodeBase64(b64) });
  } catch (e) {
    throw loadError(e);
  }
  api = wrap(glue);
  return api;
}
