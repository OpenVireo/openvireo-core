// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import { loadCore, OvError } from "../pkg/index.js";
import { SHA256_ABC, hex } from "./helpers.js";

describe("@openvireo/core-wasm in a browser-like environment (jsdom)", () => {
  it("runs in a DOM environment", () => {
    expect(typeof window).toBe("object");
    expect(typeof document.createElement).toBe("function");
  });

  it("loads and reports the version", async () => {
    const core = await loadCore();
    expect(core.version()).toBe("0.0.0");
  });

  it("runs a primitive: sha256 and randomBytes (crypto.getRandomValues)", async () => {
    const core = await loadCore();
    expect(hex(core.sha256(new Uint8Array([0x61, 0x62, 0x63])))).toBe(SHA256_ABC);
    const r = core.randomBytes(32);
    expect(r).toBeInstanceOf(Uint8Array);
    expect(r.length).toBe(32);
    expect(() => core.argon2id(new Uint8Array([1]), new Uint8Array(16), 1, 1, 1)).toThrow(OvError);
  });
});
