// @openvireo/core-wasm: loads openvireo-core's WebAssembly module and returns its API.
//
//   import { loadCore, OvError } from "@openvireo/core-wasm";
//   import { fetchTransport, indexedDbCache, memoryStore, systemClock, consoleLog } from "@openvireo/core-wasm/host";
//   const core = await loadCore();
//   const client = new core.OvClient(config, { http: fetchTransport(), store, cache: indexedDbCache(), clock: systemClock, log: consoleLog() });
//
// By default the module comes from gen/wasm-base64.js (the .wasm as base64, imported lazily),
// which works unchanged in Node, browsers, bundlers and Bun, as the SDK's OPAQUE module does.
// Pass `{ wasm }` (bytes, a WebAssembly.Module, a URL or a Response) to load the .wasm file
// instead, e.g. `loadCore({ wasm: new URL("@openvireo/core-wasm/ov_wasm_bg.wasm", import.meta.url) })`.
//
// Panics (rust-core-tasks.md §2.3): wasm32 can't unwind, so a Rust panic traps. Every export is
// wrapped so that a panic surfaces as `OvError { code: "internal" }`: thrown for a synchronous
// call, and as a rejection of every pending promise for an asynchronous one (the panic hook tells
// us before the trap). An async panic traps inside a microtask, so the trap itself is an uncaught
// error: we swallow that one `RuntimeError` (a one-shot `uncaughtException` listener in Node, which
// would otherwise exit; `preventDefault` on the window `error` event in browsers), since it was
// already delivered as the rejections. The instance is then poisoned: each later call throws `internal`, and the
// app loads a fresh instance with `loadCore({ fresh: true })` and makes new handles.

/** The one error type of the core. `code` is the stable wire string (`"plan_limit"`, `"internal"`, …). */
export class OvError extends Error {
  constructor(code, message, opts = {}) {
    super(message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "OvError";
    this.code = code;
    if (opts.status !== undefined) this.status = opts.status;
    if (opts.retryAfter !== undefined) this.retryAfter = opts.retryAfter;
    if (opts.details !== undefined) this.details = opts.details;
    if (opts.serverCode !== undefined) this.serverCode = opts.serverCode;
  }

  /** Whether the server couldn't be reached (network error or 502/503/504), as the SDK's `isUnreachable`. */
  get isUnreachable() {
    return this.code === "network_error" || this.status === 502 || this.status === 503 || this.status === 504;
  }
}

let defaultInstance = null;
let freshCount = 0;

/**
 * Loads the module (once; later calls return the same instance unless `fresh` is set).
 * @param {{ wasm?: BufferSource | WebAssembly.Module | URL | string | Response | Promise<Response>, fresh?: boolean }} [opts]
 */
export function loadCore(opts = {}) {
  if (!opts.fresh && opts.wasm === undefined) {
    defaultInstance ??= instantiate(undefined, "./gen/ov_wasm.js").catch((e) => {
      defaultInstance = null;
      throw e;
    });
    return defaultInstance;
  }
  // A new copy of the glue module gets its own wasm instance and memory.
  const spec = opts.fresh ? `./gen/ov_wasm.js?instance=${++freshCount}` : "./gen/ov_wasm.js";
  const p = instantiate(opts.wasm, spec);
  if (!opts.fresh) defaultInstance = p;
  return p;
}

async function instantiate(wasm, spec) {
  let glue;
  try {
    glue = await import(/* @vite-ignore */ spec);
    const module_or_path = wasm ?? (await embeddedWasm());
    await glue.default({ module_or_path });
  } catch (e) {
    throw new OvError("internal", "could not load the openvireo-core WebAssembly module", { cause: e });
  }
  return wrap(glue);
}

async function embeddedWasm() {
  const { default: b64 } = await import("./gen/wasm-base64.js");
  if (typeof Uint8Array.fromBase64 === "function") return Uint8Array.fromBase64(b64);
  if (typeof Buffer === "function") return new Uint8Array(Buffer.from(b64, "base64"));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Swallows the one uncaught `RuntimeError` an async panic's trap raises (see the top comment). */
function swallowNextTrap() {
  const g = globalThis;
  if (typeof g.addEventListener === "function" && typeof g.removeEventListener === "function" && typeof g.document === "object") {
    const onError = (ev) => {
      if (ev.error instanceof WebAssembly.RuntimeError) {
        ev.preventDefault();
        g.removeEventListener("error", onError);
      }
    };
    g.addEventListener("error", onError);
  }
  if (typeof g.process?.once === "function") {
    g.process.once("uncaughtException", (e) => {
      // Anything else is not ours: rethrow it so it keeps its default handling.
      if (!(e instanceof WebAssembly.RuntimeError)) g.process.nextTick(() => { throw e; });
    });
  }
}

const HIDDEN = new Set(["default", "initSync", "__install"]);

/** The glue's exports, each one guarded against panics. */
function wrap(glue) {
  const state = { poisoned: null, pending: new Set(), depth: 0 };

  const poisonedError = () =>
    new OvError("internal", `openvireo-core is unusable after an earlier panic (${state.poisoned}); load a fresh instance`);

  const onPanic = (message) => {
    state.poisoned ??= String(message);
    const err = new OvError("internal", String(message));
    for (const reject of state.pending) reject(err);
    state.pending.clear();
    // Not inside a synchronous call: the trap that follows is thrown from a microtask.
    if (state.depth === 0) swallowNextTrap();
  };

  const convert = (e) => {
    if (e instanceof WebAssembly.RuntimeError) {
      const message = state.poisoned ?? `the core trapped: ${e.message}`;
      state.poisoned ??= message;
      return new OvError("internal", message, { cause: e });
    }
    return e;
  };

  const track = (promise) =>
    new Promise((resolve, reject) => {
      state.pending.add(reject);
      promise.then(
        (v) => {
          state.pending.delete(reject);
          resolve(v);
        },
        (e) => {
          state.pending.delete(reject);
          reject(convert(e));
        },
      );
    });

  const guard = (fn) =>
    function guarded(...args) {
      if (state.poisoned !== null) throw poisonedError();
      let r;
      state.depth++;
      try {
        r = fn.apply(this, args);
      } catch (e) {
        throw convert(e);
      } finally {
        state.depth--;
      }
      return r instanceof Promise ? track(r) : r;
    };

  const guardMethods = (obj) => {
    for (const key of Reflect.ownKeys(obj)) {
      if (key === "constructor" || key === "prototype" || key === "length" || key === "name") continue;
      const d = Object.getOwnPropertyDescriptor(obj, key);
      if (d && typeof d.value === "function") Object.defineProperty(obj, key, { ...d, value: guard(d.value) });
    }
  };

  glue.__install(OvError, onPanic);

  const api = {};
  for (const [name, value] of Object.entries(glue)) {
    if (HIDDEN.has(name)) continue;
    const isClass = typeof value === "function" && value.prototype && typeof value.prototype.free === "function";
    if (isClass) {
      guardMethods(value.prototype);
      guardMethods(value);
      api[name] = new Proxy(value, {
        construct(target, args, newTarget) {
          if (state.poisoned !== null) throw poisonedError();
          state.depth++;
          try {
            return Reflect.construct(target, args, newTarget === api[name] ? target : newTarget);
          } catch (e) {
            throw convert(e);
          } finally {
            state.depth--;
          }
        },
      });
    } else if (typeof value === "function") {
      api[name] = guard(value);
    } else {
      api[name] = value;
    }
  }
  /** Whether a panic has made this instance unusable. */
  Object.defineProperty(api, "poisoned", { get: () => state.poisoned !== null, enumerable: true });
  return Object.freeze(api);
}
