// @openvireo/core-wasm/lite-sync: the lite module, loaded synchronously (no top-level await). Shares
// its instance with `loadLite()`. The lite module is small enough to compile synchronously anywhere.

import * as glue from "./gen/lite/ov_wasm_lite.js";
import b64 from "./gen/lite/wasm-base64.js";
import { OvError } from "./error.js";
import { decodeBase64, loadError, wrap } from "./internal.js";

export { OvError };

let api = null;

/**
 * The lite module's API, instantiated synchronously on first use.
 * @param {{ wasm?: BufferSource | WebAssembly.Module }} [opts] the .wasm to use instead of the embedded copy
 */
export function loadLiteSync(opts = {}) {
  if (api !== null) return api;
  try {
    glue.initSync({ module: opts.wasm ?? decodeBase64(b64) });
  } catch (e) {
    throw loadError(e);
  }
  api = wrap(glue);
  return api;
}
