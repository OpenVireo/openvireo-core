// @vitest-environment node
// The shared exports (primitives, share links, TOTP) in both modules: the lite module must give
// exactly what the full module gives, and both must match the SPEC share vectors.
import { describe, expect, it } from "vitest";
import { loadCore, OvError } from "../pkg/index.js";
import { loadCoreSync } from "../pkg/sync.js";
import { loadLite } from "../pkg/lite.js";
import { loadLiteSync } from "../pkg/lite-sync.js";
import { b64u, bytes, fromB64u, fromHex, hex, SHA256_ABC, text, vectors } from "./helpers.js";

const V = vectors();
const RFC6238_URI = "otpauth://totp/ACME:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30&algorithm=SHA1";

/** The SDK's JSON payload (snake_case, string values) → the binding's `SharePayload`. */
const toPayload = (json) => {
  const p = JSON.parse(json);
  return { v: p.v, kind: p.kind, title: p.title, sharedBy: p.shared_by, fields: p.fields.map((f) => ({ ...f, value: bytes(f.value), protected: !!f.protected })) };
};
const plain = (p) => ({ ...p, fields: p.fields.map((f) => ({ ...f, value: text(f.value) })) });

describe.each([
  ["lite", () => loadLiteSync()],
  ["full", () => loadCoreSync()],
])("%s module", (_, load) => {
  const m = load();

  it("primitives", () => {
    expect(hex(m.sha256(bytes("abc")))).toBe(SHA256_ABC);
    const okm = m.hkdfSha256(fromHex("0b".repeat(22)), fromHex("000102030405060708090a0b0c"), fromHex("f0f1f2f3f4f5f6f7f8f9"), 42);
    expect(hex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    const key = new Uint8Array(32).fill(7), nonce = new Uint8Array(24).fill(9);
    expect(text(m.aeadDecrypt(key, nonce, m.aeadEncrypt(key, nonce, bytes("s"), bytes("a")), bytes("a")))).toBe("s");
    const a = V.auk[0];
    expect(hex(m.argon2id(fromHex(a.password_nfkc_hex), fromB64u(a.kdf.salt), a.kdf.m, a.kdf.t, a.kdf.p))).toBe(a.argon2id_hex);
    expect(m.randomBytes(5).length).toBe(5);
  });

  it("share content crypto against the share vectors", () => {
    for (const c of V.share.cases) {
      const key = fromB64u(c.key);
      const pk = c.passcode ? m.sharePasscodeKey(c.passcode, c.kdf, true) : undefined;
      if (c.passcode) {
        expect(hex(pk)).toBe(c.passcode_key_hex);
        expect(b64u(m.shareAuth(pk))).toBe(c.auth);
        expect(hex(m.shareAuthHash(m.shareAuth(pk)))).toBe(c.auth_sha256_hex);
        expect(() => m.sharePasscodeKey(c.passcode, c.kdf)).toThrow(expect.objectContaining({ code: "weak_kdf" }));
      }
      expect(hex(m.shareContentKey(key, pk))).toBe(c.content_key_hex);
      expect(hex(m.padShare(bytes(c.payload)))).toBe(c.padded_hex);
      expect(text(m.unpadShare(fromHex(c.padded_hex)))).toBe(c.payload);
      const ct = m.encryptSharePayload(key, c.id, toPayload(c.payload), pk, fromHex(c.nonce_hex));
      expect(b64u(ct)).toBe(c.ct);
      expect(plain(m.decryptSharePayload(key, c.id, fromB64u(c.ct), pk))).toEqual(plain(toPayload(c.payload)));
      expect(() => m.decryptSharePayload(key, "AAAAAAAAAAAAAAAAAAAAAA", fromB64u(c.ct), pk)).toThrow(expect.objectContaining({ code: "decryption_failed" }));
      // Links
      expect(text(m.shareLink("https://share.openvireo.example/", c.id, key))).toBe(c.link);
      const parts = m.parseShareLink(c.link);
      expect([parts.base, parts.id, b64u(parts.key)]).toEqual(["https://share.openvireo.example", c.id, c.key]);
      expect(b64u(m.shareKeyFromHash("#" + c.key))).toBe(c.key);
      // Opening: ShareOpen (as the share page does) and the one-step call. The passcode vector's KDF
      // (m = 1024) is below the SPEC minimum, which opening a link enforces.
      if (c.passcode) {
        expect(() => new m.ShareOpen(c.link, c.kdf, c.passcode)).toThrow(expect.objectContaining({ code: "weak_kdf" }));
        expect(() => new m.ShareOpen(c.link, c.kdf, undefined)).toThrow(expect.objectContaining({ code: "passcode_required" }));
        continue;
      }
      const open = new m.ShareOpen(bytes(c.link), undefined, undefined);
      expect([open.id, open.base, open.auth]).toEqual([c.id, "https://share.openvireo.example", undefined]);
      expect(text(open.requestBody())).toBe("{}");
      expect(plain(open.decrypt(c.ct))).toEqual(plain(toPayload(c.payload)));
      expect(plain(open.decrypt(fromB64u(c.ct)))).toEqual(plain(toPayload(c.payload)));
      open.free();
      expect(plain(m.openShareContent(c.link, undefined, undefined, c.ct))).toEqual(plain(toPayload(c.payload)));
    }
    expect(() => m.parseShareLink("https://x/abc")).toThrow(expect.objectContaining({ code: "invalid_link" }));
    expect(m.newShareKey().length).toBe(32);
  }, 30_000);

  it("share references against the ref vector", () => {
    const r = V.share.ref;
    const sk = fromHex(r.owner_enc_sk_hex);
    expect(hex(m.shareRefKey(sk))).toBe(r.ref_key_hex);
    const ref = JSON.parse(r.plaintext);
    expect(m.encryptShareRef(sk, r.share_id, ref, fromHex(r.nonce_hex))).toBe(r.ref);
    expect(m.decryptShareRef(sk, r.share_id, r.ref)).toEqual(ref);
  });

  it("payload builders", () => {
    const entry = {
      fields: [
        { name: "Title", value: bytes("Office Wi-Fi"), protected: false },
        { name: "UserName", value: bytes("guest"), protected: false },
        { name: "Password", value: bytes("pw"), protected: true },
        { name: "otp", value: bytes(RFC6238_URI), protected: true },
        { name: "Room", value: bytes("4.2"), protected: false },
      ],
    };
    expect(m.defaultShareFields()).toEqual(["UserName", "Password", "URL"]);
    const fields = m.shareableFields(entry);
    expect(fields.map((f) => [f.name, f.kind, f.label, f.protected])).toEqual([
      ["UserName", "username", "Username", false],
      ["Password", "password", "Password", true],
      ["otp", "totp", "One-time code", true],
      ["Room", "custom", "Room", false],
    ]);
    expect(m.shareableFields(entry.fields).length).toBe(4);
    const p = m.itemSharePayload(entry, ["Password", "Room"], "Sam");
    expect(plain(p)).toEqual({ v: 1, kind: "entry", title: "Office Wi-Fi", sharedBy: "Sam", fields: [{ k: "password", label: "Password", value: "pw", protected: true }, { k: "custom", label: "Room", value: "4.2", protected: false }] });
    expect(plain(m.textSharePayload("hi", "", undefined))).toEqual({ v: 1, kind: "text", fields: [{ k: "text", label: "Text", value: "hi", protected: false }] });
  });

  it("TOTP: RFC 6238 SHA-1 at T = 59 s and 1111111109 s", () => {
    const params = m.parseTotpUri(RFC6238_URI);
    expect([text(params.secret), params.digits, params.period, params.algorithm]).toEqual(["12345678901234567890", 8, 30, "SHA1"]);
    expect(text(m.totpCode(params, 59_000).code)).toBe("94287082");
    expect(text(m.totpCode({ ...params, encoder: undefined, steam: true, digits: 5 }, 59_000).code)).toMatch(/^[2-9B-DF-HJ-NP-TV-Y]{5}$/);
    const c = m.totpCode(params, 1_111_111_109_000);
    expect([text(c.code), c.remaining]).toEqual(["07081804", 1]);
    expect(text(m.entryTotpUri([{ name: "otp", value: bytes(RFC6238_URI), protected: true }], "x"))).toBe(RFC6238_URI);
    expect(m.entryTotpUri({ fields: [] }, "x")).toBeUndefined();
    expect(() => m.parseTotpUri("otpauth://hotp/x?secret=AA")).toThrow(OvError);
  });
});

describe("loaders", () => {
  it("async and sync loaders share one instance per module", async () => {
    expect(await loadLite()).toBe(loadLiteSync());
    expect(await loadCore()).toBe(loadCoreSync());
    expect(loadLiteSync()).not.toBe(loadCoreSync());
  });

  it("the lite module has no facade, OPAQUE, KDBX or account crypto", () => {
    const lite = loadLiteSync();
    for (const name of ["OvClient", "Kdbx", "opaqueStartLogin", "seal", "x25519PublicKey", "deriveAuk"]) expect(lite[name]).toBeUndefined();
    const full = loadCoreSync();
    for (const name of Object.keys(lite)) expect(typeof full[name]).toBe(typeof lite[name]);
  });
});
