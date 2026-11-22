// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { loadCore, OvError } from "../pkg/index.js";
import { loadLite } from "../pkg/lite.js";
import { loadLiteSync } from "../pkg/lite-sync.js";
import { PKG_VERSION, SHA256_ABC, hex } from "./helpers.js";

describe("@openvireo/core-wasm in a browser-like environment (jsdom)", () => {
  it("runs in a DOM environment", () => {
    expect(typeof window).toBe("object");
    expect(typeof document.createElement).toBe("function");
  });

  it("loads and reports the version", async () => {
    const core = await loadCore();
    expect(core.version()).toBe(PKG_VERSION);
  });

  it("runs a primitive: sha256 and randomBytes (crypto.getRandomValues)", async () => {
    const core = await loadCore();
    expect(hex(core.sha256(new Uint8Array([0x61, 0x62, 0x63])))).toBe(SHA256_ABC);
    const r = core.randomBytes(32);
    expect(r).toBeInstanceOf(Uint8Array);
    expect(r.length).toBe(32);
    expect(() => core.argon2id(new Uint8Array([1]), new Uint8Array(16), 1, 1, 1)).toThrow(OvError);
  });

  it("loads the lite module, async and sync", async () => {
    const lite = await loadLite();
    expect(lite).toBe(loadLiteSync());
    expect(lite.version()).toBe(PKG_VERSION);
    expect(hex(lite.sha256(new Uint8Array([0x61, 0x62, 0x63])))).toBe(SHA256_ABC);
    expect(lite.randomBytes(8).length).toBe(8);
  });
});
