// @vitest-environment node
// Secrets don't stay in the module's linear memory after a call: the exports wipe what they own,
// the allocator zeroes every freed block, and the loaders scrub the dead stack (src/wipe.rs).
import { describe, expect, it } from "vitest";
import * as fullGlue from "../pkg/gen/ov_wasm.js";
import * as liteGlue from "../pkg/gen/lite/ov_wasm_lite.js";
import { loadCoreSync } from "../pkg/sync.js";
import { loadLiteSync } from "../pkg/lite-sync.js";
import { bytes, vectorFile, vectors } from "./helpers.js";

/** How often `pattern` occurs in the instance's memory. */
function occurrences(memory, pattern) {
  const m = new Uint8Array(memory.buffer);
  let n = 0;
  outer: for (let i = m.indexOf(pattern[0]); i !== -1 && i + pattern.length <= m.length; i = m.indexOf(pattern[0], i + 1)) {
    for (let j = 1; j < pattern.length; j++) if (m[i + j] !== pattern[j]) continue outer;
    n++;
  }
  return n;
}

const unique = (seed) => Uint8Array.from({ length: 32 }, (_, i) => (seed * 31 + i * 7 + 1) & 255);

describe("no secret copies left in linear memory", () => {
  it("lite: AEAD key and plaintext, passcode, link key, derived keys", () => {
    const lite = loadLiteSync();
    const { memory } = liteGlue.initSync({ module: new Uint8Array() }); // already initialised: returns the exports
    const key = unique(1), plain = bytes("plaintext secret 0123456789");
    lite.aeadEncrypt(key.slice(), new Uint8Array(24), plain.slice(), bytes("aad"));
    const passcode = "passcode secret QQQ-42";
    const kdf = { alg: "argon2id", salt: "AAAAAAAAAAAAAAAAAAAAAA", m: 1024, t: 2, p: 1 };
    const pk = lite.sharePasscodeKey(passcode, kdf, true);
    const linkKey = unique(2);
    const link = lite.shareLink("https://share.example", "AAAAAAAAAAAAAAAAAAAAAA", linkKey.slice());
    const parts = lite.parseShareLink(link);
    const content = lite.shareContentKey(parts.key, pk);
    for (const secret of [key, plain, bytes(passcode), pk, linkKey, link, content]) expect(occurrences(memory, secret)).toBe(0);
  });

  it("full: AUK derivation, OPAQUE password, KDBX password and decrypted entries", () => {
    const core = loadCoreSync();
    const { memory } = fullGlue.initSync({ module: new Uint8Array() });
    const V = vectors();
    const a = V.auk[0];
    const auk = core.deriveAuk(a.password, a.kdf, Uint8Array.from(Buffer.from(a.secret_key_hex, "hex")), { allowWeak: true });
    const pw = "opaque password secret ✓";
    const start = core.opaqueStartLogin(pw);
    const db = core.Kdbx.read(vectorFile("kdbx/desktop-kdbx4-argon2d.kdbx"), { password: "desktop pw ✓" });
    const written = db.write();
    db.free();
    for (const secret of [auk, bytes(a.password), bytes(pw), start.state.subarray(0, 32), bytes("desktop pw ✓")]) expect(occurrences(memory, secret)).toBe(0);
    expect(written.length).toBeGreaterThan(0);
  }, 30_000);
});
