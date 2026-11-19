// @openvireo/core-wasm/lite: the lite module (primitives, share links, TOTP), loaded asynchronously.
// Its exports behave exactly like the full module's exports of the same names.
//
//   import { loadLite } from "@openvireo/core-wasm/lite";
//   const lite = await loadLite();
//   const payload = new lite.ShareOpen(link, info.kdf, passcode).decrypt(ct);

import { OvError } from "./error.js";
import { decodeBase64, loadError, wrap } from "./internal.js";

export { OvError };

let instance = null;

/**
 * Loads the lite module once.
 * @param {{ wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response> }} [opts]
 */
export function loadLite(opts = {}) {
  if (instance !== null && opts.wasm === undefined) return instance;
  instance = (async () => {
    let glue;
    try {
      glue = await import("./gen/lite/ov_wasm_lite.js");
      const module_or_path = opts.wasm ?? decodeBase64((await import("./gen/lite/wasm-base64.js")).default);
      await glue.default({ module_or_path });
    } catch (e) {
      throw loadError(e);
    }
    return wrap(glue);
  })().catch((e) => {
    instance = null;
    throw e;
  });
  return instance;
}
