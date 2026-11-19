// @vitest-environment node
import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { loadCore, OvError } from "../pkg/index.js";
import { consoleLog, memoryCache, memoryStore, systemClock } from "../pkg/host/index.js";
import { bytes, fromHex, hex, SHA256_ABC } from "./helpers.js";

const config = { device: { name: "vitest", platform: "web" }, offline: false };
const host = () => ({
  http: { send: async () => ({ status: 500, headers: [], body: new Uint8Array() }), openStream: async () => ({ status: 500, nextChunk: async () => null, close() {} }) },
  store: memoryStore(),
  cache: memoryCache(),
  clock: systemClock,
  log: consoleLog("error"),
});

describe("@openvireo/core-wasm in Node", () => {
  it("loads from the embedded base64 and reports the version", async () => {
    const core = await loadCore();
    expect(core.version()).toBe("0.0.0");
    expect(await loadCore()).toBe(core);
  });

  it("runs a primitive: sha256", async () => {
    const core = await loadCore();
    expect(hex(core.sha256(bytes("abc")))).toBe(SHA256_ABC);
  });

  it("round-trips XChaCha20-Poly1305 and maps errors to OvError", async () => {
    const core = await loadCore();
    const key = new Uint8Array(32).fill(7);
    const nonce = new Uint8Array(24).fill(9);
    const ct = core.aeadEncrypt(key, nonce, bytes("secret"), bytes("aad"));
    expect(new TextDecoder().decode(core.aeadDecrypt(key, nonce, ct, bytes("aad")))).toBe("secret");
    const err = (() => {
      try {
        core.aeadDecrypt(key, nonce, ct, bytes("other"));
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(OvError);
    expect(err.code).toBe("decryption_failed");
    expect(() => core.aeadEncrypt(new Uint8Array(3), nonce, bytes("x"), bytes(""))).toThrow(/key: expected 32 bytes/);
  });

  it("runs HKDF against RFC 5869 A.1", async () => {
    const core = await loadCore();
    const okm = core.hkdfSha256(fromHex("0b".repeat(22)), fromHex("000102030405060708090a0b0c"), fromHex("f0f1f2f3f4f5f6f7f8f9"), 42);
    expect(hex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });

  it("builds an OvClient over a JS Host and rejects bad records with invalid_request", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host());
    expect(client.config()).toEqual({ device: { name: "vitest", platform: "web" }, offline: false });
    expect(() => new core.OvClient({ ...config, device: { name: "x", platform: "amiga" } }, host())).toThrow(OvError);
    expect(() => new core.OvClient(config, { ...host(), clock: {} })).toThrow(/host.clock.nowUnixMs: expected a function/);
  });

  it("loads from .wasm bytes as well", async () => {
    const wasm = await readFile(new URL("../pkg/gen/ov_wasm_bg.wasm", import.meta.url));
    const core = await loadCore({ wasm, fresh: true });
    expect(core.version()).toBe("0.0.0");
  });
});

/**
 * Runs `fn` with vitest's own uncaughtException listeners set aside, so the loader's one-shot
 * listener is the only one, as in a plain Node process; then checks that it consumed the trap.
 */
async function asPlainNode(fn) {
  const saved = process.listeners("uncaughtException");
  process.removeAllListeners("uncaughtException");
  try {
    const r = await fn();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(process.listenerCount("uncaughtException")).toBe(0);
    return r;
  } finally {
    for (const l of saved) process.on("uncaughtException", l);
  }
}

describe("panics become OvError { code: internal }", () => {
  const hooks = (core) => core[Symbol.for("@openvireo/core-wasm/test-hooks")];

  it("synchronous: a panic throws internal, then the instance is poisoned", async () => {
    const core = await loadCore({ fresh: true });
    let err;
    try {
      hooks(core).__testPanic("not yet implemented");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(OvError);
    expect(err.code).toBe("internal");
    expect(err.message).toMatch(/the core panicked: not yet implemented/);
    expect(core.poisoned).toBe(true);
    expect(() => core.version()).toThrow(/unusable after an earlier panic/);
    // A fresh instance works again.
    expect((await loadCore({ fresh: true })).version()).toBe("0.0.0");
  });

  it("asynchronous: a panic inside a future rejects the pending promise with internal", async () => {
    const core = await loadCore({ fresh: true });
    const err = await asPlainNode(() => hooks(core).__testPanicAsync("not yet implemented").catch((e) => e));
    expect(err).toBeInstanceOf(OvError);
    expect(err.code).toBe("internal");
    expect(err.message).toMatch(/not yet implemented/);
    expect(core.poisoned).toBe(true);
  });

  it("an aborted AbortSignal is accepted by async calls", async () => {
    const core = await loadCore({ fresh: true });
    const client = new core.OvClient(config, host());
    const ac = new AbortController();
    ac.abort();
    // The call settles (aborted, or the host's failing transport) instead of hanging.
    const err = await client.connect("https://accounts.example", ac.signal).catch((e) => e);
    expect(err).toBeInstanceOf(OvError);
  });
});
