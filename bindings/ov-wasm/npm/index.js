// @openvireo/core-wasm: openvireo-core (the shared Rust core) as WebAssembly. This entry loads the
// full module asynchronously.
//
//   import { loadCore, OvError } from "@openvireo/core-wasm";
//   const core = await loadCore();
//
// Other entries: "@openvireo/core-wasm/sync" (`loadCoreSync()`, no await: for synchronous APIs),
// "@openvireo/core-wasm/lite" and "/lite-sync" (the small primitives + share-link + TOTP module),
// "@openvireo/core-wasm/host" (JS Host adapters for the facade's OvClient).
//
// By default the module comes from gen/wasm-base64.js (the .wasm as base64, imported lazily),
// which works unchanged in Node, browsers, bundlers and Bun. Pass `{ wasm }` (bytes, a
// WebAssembly.Module, a URL or a Response) to load the .wasm file instead, e.g.
// `loadCore({ wasm: new URL("@openvireo/core-wasm/ov_wasm_bg.wasm", import.meta.url) })`.
//
// Every import path below is a literal, so bundlers (webpack, Turbopack, esbuild, Rollup/Vite)
// include the glue and the embedded module. The one exception is `fresh: true` (see loadCore).

import { OvError } from "./error.js";
import { decodeBase64, loadError, wrap } from "./internal.js";

export { OvError };

let defaultInstance = null;
let freshCount = 0;

/**
 * Loads the full module (once; later calls return the same instance unless `fresh` is set).
 * @param {{ wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response>, fresh?: boolean }} [opts]
 */
export function loadCore(opts = {}) {
  if (opts.fresh) {
    // A new copy of the glue module gets its own wasm instance and memory. The specifier has to be
    // computed, so bundlers can't follow it: use `fresh` in Node, Bun or unbundled ESM only.
    const spec = `./gen/ov_wasm.js?instance=${++freshCount}`;
    return instantiate(opts.wasm, () => import(/* @vite-ignore */ /* webpackIgnore: true */ /* turbopackIgnore: true */ spec));
  }
  if (opts.wasm === undefined) {
    defaultInstance ??= instantiate(undefined, () => import("./gen/ov_wasm.js")).catch((e) => {
      defaultInstance = null;
      throw e;
    });
    return defaultInstance;
  }
  defaultInstance = instantiate(opts.wasm, () => import("./gen/ov_wasm.js"));
  return defaultInstance;
}

async function instantiate(wasm, importGlue) {
  let glue;
  try {
    glue = await importGlue();
    const module_or_path = wasm ?? decodeBase64((await import("./gen/wasm-base64.js")).default);
    await glue.default({ module_or_path });
  } catch (e) {
    throw loadError(e);
  }
  return wrap(glue);
}
