// Shared by the package's loaders: base64 decoding and the panic guard around a module's exports.
// Not a public entry point.
//
// Panics (rust-core-tasks.md §2.3): wasm32 can't unwind, so a Rust panic traps. Every export is
// wrapped so that a panic surfaces as `OvError { code: "internal" }`: thrown for a synchronous
// call, and as a rejection of every pending promise for an asynchronous one (the panic hook tells
// us before the trap). An async panic traps inside a microtask, so the trap itself is an uncaught
// error: we swallow that one `RuntimeError` (a one-shot `uncaughtException` listener in Node, which
// would otherwise exit; `preventDefault` on the window `error` event in browsers), since it was
// already delivered as the rejections. The instance is then poisoned: each later call throws
// `internal`, and the app loads a fresh instance (`loadCore({ fresh: true })`) and makes new handles.

import { OvError } from "./error.js";

/** A base64 string as bytes (Node, Bun, browsers). */
export function decodeBase64(b64) {
  if (typeof Uint8Array.fromBase64 === "function") return Uint8Array.fromBase64(b64);
  if (typeof Buffer === "function") return new Uint8Array(Buffer.from(b64, "base64"));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The error a loader throws when the module can't be instantiated. */
export function loadError(cause) {
  return new OvError("internal", "could not load the openvireo-core WebAssembly module", { cause });
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

/** Glue exports that aren't part of the API. */
const HIDDEN = new Set(["default", "initSync", "__install", "__scrubStack", "__testPanic", "__testPanicAsync"]);

/** Test hooks (`__testPanic`, `__testPanicAsync`), guarded like the API, under this symbol. */
export const TEST_HOOKS = Symbol.for("@openvireo/core-wasm/test-hooks");

/** One guarded API per glue module, so the async and the sync loader share an instance's state. */
const wrapped = new WeakMap();

/** The glue's exports, each one guarded against panics. The glue must be initialised. */
export function wrap(glue) {
  let api = wrapped.get(glue);
  if (api === undefined) {
    api = build(glue);
    wrapped.set(glue, api);
  }
  return api;
}

function build(glue) {
  const state = { poisoned: null, pending: new Set(), depth: 0 };

  // Zeroes the dead shadow stack after a call returns or an async call settles (see the Rust
  // `wipe` module). Skipped once poisoned: the instance must not run again.
  const scrub = () => {
    if (state.depth === 0 && state.poisoned === null) glue.__scrubStack();
  };

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
          scrub();
          resolve(v);
        },
        (e) => {
          state.pending.delete(reject);
          scrub();
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
        scrub();
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
            scrub();
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
  const hooks = {};
  for (const name of ["__testPanic", "__testPanicAsync"]) if (typeof glue[name] === "function") hooks[name] = guard(glue[name]);
  Object.defineProperty(api, TEST_HOOKS, { value: Object.freeze(hooks) });
  return Object.freeze(api);
}
