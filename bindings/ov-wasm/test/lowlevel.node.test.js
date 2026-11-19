// @vitest-environment node
// Every low-level export of the full module, against vectors/ (SPEC test vectors, OPAQUE
// transcripts, the KDBX fixtures) or a second implementation where the vectors have no case.
import { describe, expect, it } from "vitest";
import { OvError } from "../pkg/index.js";
import { loadCoreSync } from "../pkg/sync.js";
import { b64u, bytes, errorOf, fromB64u, fromHex, hex, opaqueTranscripts, text, vectorFile, vectors } from "./helpers.js";

const core = loadCoreSync();
const V = vectors();

describe("primitives", () => {
  it("argon2: d/i/id with variable output length (cross-checked with hash-wasm 4.x)", () => {
    // hash-wasm argon2{d,i,id}({ password: "password", salt: "somesalt12345678", iterations: 2, parallelism: 1, memorySize: 256, hashLength })
    const want = {
      argon2d: ["511f1e239484b47f9b0108718098a2b6ff7d6ed1c5a54d675c9138eb89446d1a", "53a1dd74fa768e39b70ae83cbd1492d77db31bc4ef9157046c888f4c00cae8f8766b09d7163f18a1ac7700db3a2fd393844b13dfcaed234a8d720534fa88057f"],
      argon2i: ["68cc9ef39741ef7b870f472cb937102affe9cdba89c754b5a7c72a725038f3a0", "45cb5b83e321c91317062113eeae9848c6392c97e5586dd793d7b65759700cd2492b28055f46957e70dfcb69cb4618b78da9e948c82723cadfd371bc40706826"],
      argon2id: ["8110e1165eb0e1114ee37d5ff017573ba0084b8366b4108db44749954b8d9871", "1047bd6d1c92c7a3c8ddbeaf5f12ad5cdec043274291a61432b4b8f0d3678e0270d2e0b6fd3a16add1c898df8375462972b8c4f511a716d123839f87c3d2a4d3"],
    };
    for (const [type, [h32, h64]] of Object.entries(want)) {
      const p = { type, password: bytes("password"), salt: bytes("somesalt12345678"), m: 256, t: 2, p: 1 };
      expect(hex(core.argon2({ ...p, dkLen: 32 }))).toBe(h32);
      expect(hex(core.argon2({ ...p, dkLen: 64 }))).toBe(h64);
    }
    // The SPEC §3 stretch vector through the generic call.
    const a = V.auk[0];
    expect(hex(core.argon2({ type: "argon2id", password: fromHex(a.password_nfkc_hex), salt: fromB64u(a.kdf.salt), m: a.kdf.m, t: a.kdf.t, p: a.kdf.p, dkLen: 32 }))).toBe(a.argon2id_hex);
  }, 30_000);

  it("argon2 refuses bad parameters and types", async () => {
    expect((await errorOf(() => core.argon2({ type: "argon2id", password: bytes("x"), salt: new Uint8Array(16), m: 1, t: 1, p: 1, dkLen: 32 }))).code).toBe("weak_kdf");
    expect((await errorOf(() => core.argon2({ type: "argon3", password: bytes("x"), salt: new Uint8Array(16), m: 64, t: 1, p: 1, dkLen: 32 }))).code).toBe("invalid_request");
  });

  it("X25519/Ed25519 against the keyset and seal vectors", () => {
    for (const k of [V.keyset, { ...V.public_keys[0], public: V.public_keys[0] }]) {
      const encSk = fromHex(k.enc_sk_hex), seed = fromHex(k.sign_seed_hex);
      expect(b64u(core.x25519PublicKey(encSk))).toBe(k.public.enc_pk);
      expect(b64u(core.ed25519PublicKey(seed))).toBe(k.public.sign_pk);
      const msg = new Uint8Array([...bytes("ov-pubkeys-v1"), ...fromB64u(k.public.enc_pk), ...fromB64u(k.public.sign_pk)]);
      expect(b64u(core.ed25519Sign(msg, seed))).toBe(k.public.sig);
      expect(core.ed25519Verify(fromB64u(k.public.sig), msg, fromB64u(k.public.sign_pk))).toBe(true);
      expect(core.ed25519Verify(fromB64u(k.public.sig), bytes("other"), fromB64u(k.public.sign_pk))).toBe(false);
    }
    const s = V.seal[0];
    expect(hex(core.x25519PublicKey(fromHex(s.ephemeral_sk_hex)))).toBe(s.ephemeral_pk_hex);
    const shared = core.x25519Shared(fromHex(s.ephemeral_sk_hex), fromB64u(s.recipient_enc_pk));
    expect(hex(core.x25519Shared(fromHex(s.recipient_enc_sk_hex), fromHex(s.ephemeral_pk_hex)))).toBe(hex(shared));
    const salt = new Uint8Array([...fromHex(s.ephemeral_pk_hex), ...fromB64u(s.recipient_enc_pk)]);
    expect(hex(core.hkdfSha256(shared, salt, bytes("ov-seal-v1"), 32))).toBe(s.derived_key_hex);
    expect(core.x25519RandomSecret().length).toBe(32);
    expect(() => core.x25519Shared(new Uint8Array(32).fill(1), new Uint8Array(32))).toThrow(OvError);
  });
});

describe("secret key and AUK", () => {
  it("formats and parses the Secret Key vectors", () => {
    for (const v of V.secret_key) {
      expect(text(core.formatSecretKey(fromHex(v.raw_hex)))).toBe(v.display);
      expect(hex(core.parseSecretKey(v.display))).toBe(v.raw_hex);
      expect(hex(core.parseSecretKey(bytes(v.display.toLowerCase())))).toBe(v.raw_hex);
    }
    expect(core.generateSecretKey().length).toBe(16);
    expect(() => core.parseSecretKey("K1-nope")).toThrow(expect.objectContaining({ code: "invalid_secret_key" }));
  });

  it("derives the AUK vectors (NFKC, Argon2id, HKDF)", () => {
    for (const a of V.auk) {
      expect(hex(core.passwordBytes(a.password))).toBe(a.password_nfkc_hex);
      const opts = { allowWeak: true };
      expect(hex(core.stretchPassword(a.password, a.kdf, opts))).toBe(a.argon2id_hex);
      expect(hex(core.deriveAuk(bytes(a.password), a.kdf, fromHex(a.secret_key_hex), opts))).toBe(a.auk_hex);
    }
  }, 60_000);

  it("checks KDF parameters and makes new ones", async () => {
    const weak = V.auk[0].kdf;
    expect((await errorOf(() => core.stretchPassword("pw", weak))).code).toBe("weak_kdf");
    expect((await errorOf(() => core.stretchPassword("pw", V.auk[2].kdf, { kdfMin: { m: 131072, t: 3 } }))).code).toBe("weak_kdf");
    expect((await errorOf(() => core.checkKdfParams(weak))).code).toBe("weak_kdf");
    expect(core.checkKdfParams(V.auk[2].kdf)).toBeUndefined();
    expect((await errorOf(() => core.checkKdfParams(V.auk[2].kdf, { m: 131072, t: 3 }))).code).toBe("weak_kdf");
    const k = core.newKdfParams();
    expect([k.alg, k.m, k.t, k.p, fromB64u(k.salt).length]).toEqual(["argon2id", 65536, 3, 1, 16]);
    expect(core.newKdfParams({ m: 19456, t: 2 })).toMatchObject({ m: 19456, t: 2, p: 1 });
  });
});

describe("envelopes", () => {
  it("seals and unseals the seal vectors (fixed ephemeral key and nonce)", () => {
    for (const s of V.seal) {
      const opts = { ephemeralSecretKey: fromHex(s.ephemeral_sk_hex), nonce: fromHex(s.nonce_hex) };
      expect(b64u(core.seal(fromB64u(s.recipient_enc_pk), fromHex(s.plaintext_hex), s.aad, opts))).toBe(s.sealed);
      expect(hex(core.unseal(fromHex(s.recipient_enc_sk_hex), fromB64u(s.sealed), s.aad))).toBe(s.plaintext_hex);
      expect(hex(core.sealDerivedKey(fromHex(s.recipient_enc_sk_hex), fromB64u(s.sealed)))).toBe(s.derived_key_hex);
      if (s.aad.startsWith("ov-vault-key|")) {
        const id = s.aad.slice("ov-vault-key|".length);
        expect(b64u(core.sealVaultKey(fromB64u(s.recipient_enc_pk), id, fromHex(s.plaintext_hex), opts))).toBe(s.sealed);
        expect(hex(core.unsealVaultKey(fromHex(s.recipient_enc_sk_hex), id, fromB64u(s.sealed)))).toBe(s.plaintext_hex);
      }
    }
  });

  it("rejects the seal_negative cases", () => {
    for (const n of V.seal_negative) {
      expect(() => core.unseal(fromHex(n.recipient_enc_sk_hex), fromB64u(n.sealed), n.aad)).toThrow(OvError);
    }
  });

  it("wraps and unwraps (the wrapped keyset is a wrap under the AUK)", () => {
    const k = V.keyset;
    const plain = new Uint8Array([...fromHex(k.enc_sk_hex), ...fromHex(k.sign_seed_hex)]);
    const w = core.wrap(fromHex(k.auk_hex), plain, k.aad, fromHex(k.nonce_hex));
    expect(b64u(w)).toBe(k.wrapped);
    expect(hex(core.unwrap(fromHex(k.auk_hex), w, k.aad))).toBe(hex(plain));
    const r = core.wrap(new Uint8Array(32).fill(3), bytes("hi"), "aad");
    expect(text(core.unwrap(new Uint8Array(32).fill(3), r, "aad"))).toBe("hi");
    expect(() => core.unwrap(new Uint8Array(32).fill(3), r, "other")).toThrow(expect.objectContaining({ code: "decryption_failed" }));
  });
});

describe("keysets, vault names", () => {
  it("rebuilds, wraps and unwraps the keyset vector", () => {
    const k = V.keyset;
    const ks = core.keysetFromSecrets(fromHex(k.enc_sk_hex), fromHex(k.sign_seed_hex));
    expect(core.publicKeysToJson(ks)).toEqual({ enc_pk: k.public.enc_pk, sign_pk: k.public.sign_pk, sig: k.public.sig });
    expect(ks.fingerprint).toBe(k.public.fingerprint);
    expect(core.fingerprint(ks.encPk, ks.signPk)).toBe(k.public.fingerprint);
    expect(core.verifyPublicKeys(ks)).toBe(true);
    const w = core.wrapKeyset(fromHex(k.auk_hex), ks, fromHex(k.nonce_hex));
    expect(w).toEqual({ enc_pk: k.public.enc_pk, sign_pk: k.public.sign_pk, sig: k.public.sig, wrapped: k.wrapped });
    const back = core.unwrapKeyset(fromHex(k.auk_hex), w);
    expect(hex(back.encSk)).toBe(k.enc_sk_hex);
    expect(hex(back.signSeed)).toBe(k.sign_seed_hex);
    expect(core.unwrapKeyset(fromHex(k.auk_hex), core.wrapKeyset(fromHex(k.auk_hex), core.generateKeyset())).encSk.length).toBe(32);
  });

  it("checks public keys from server JSON", () => {
    const p = V.public_keys[0];
    const j = { enc_pk: p.enc_pk, sign_pk: p.sign_pk, sig: p.sig };
    expect(core.trustedPublicKeys(j).fingerprint).toBe(p.fingerprint);
    expect(core.publicKeysFromJson(j).fingerprint).toBe(p.fingerprint);
    const forged = { ...j, enc_pk: V.keyset.public.enc_pk };
    expect(core.verifyPublicKeys(core.publicKeysFromJson(forged))).toBe(false);
    expect(() => core.trustedPublicKeys(forged)).toThrow(expect.objectContaining({ code: "invalid_public_keys" }));
  });

  it("encrypts the vault name vector", () => {
    const v = V.vault_name;
    const vk = fromHex(v.vault_key_hex);
    expect(hex(core.vaultNameKey(vk))).toBe(v.name_key_hex);
    expect(core.encryptVaultName(vk, v.vault_id, v.name, fromHex(v.nonce_hex))).toBe(v.encrypted_name);
    expect(core.decryptVaultName(vk, v.vault_id, v.encrypted_name)).toBe(v.name);
    expect(core.decryptVaultName(vk, v.vault_id, core.encryptVaultName(vk, v.vault_id, "x"))).toBe("x");
  });
});

describe("tokens, JWT, restore", () => {
  it("service account token, secret hash/prefix, master wrap and seal", () => {
    const s = V.service_account;
    const p = core.parseSaToken(s.token);
    expect([p.url, p.saId]).toEqual(["https://accounts.openvireo.example", s.sa_id]);
    expect(text(core.buildSaToken(p))).toBe(s.token);
    expect(core.saSecretHash(p.secret)).toBe(s.secret_hash_hex);
    expect(core.saSecretPrefix(p.secret)).toBe(s.secret_prefix);
    expect(hex(p.kek)).toBe(s.kek_hex);
    expect(core.wrapSaMaster(p.kek, s.sa_id, fromHex(s.master_key_hex), fromHex(s.wrapped_master_nonce_hex))).toBe(s.wrapped_master);
    expect(hex(core.unwrapSaMaster(p.kek, s.sa_id, s.wrapped_master))).toBe(s.master_key_hex);
    const m = s.master_sealed_to_admin;
    const opts = { ephemeralSecretKey: fromHex(m.ephemeral_sk_hex), nonce: fromHex(m.nonce_hex) };
    expect(b64u(core.sealSaMaster(fromB64u(V.keyset.public.enc_pk), s.sa_id, fromHex(s.master_key_hex), opts))).toBe(m.sealed);
    expect(hex(core.unsealSaMaster(fromHex(V.keyset.enc_sk_hex), s.sa_id, fromB64u(m.sealed)))).toBe(s.master_key_hex);
    // The SA's keyset, wrapped under the master key.
    const ks = core.keysetFromSecrets(fromHex(s.keyset_enc_sk_hex), fromHex(s.keyset_sign_seed_hex));
    expect(core.wrapKeyset(fromHex(s.master_key_hex), ks, fromHex(s.wrapped_keyset_nonce_hex)).wrapped).toBe(s.wrapped_keyset);
    expect(() => core.parseSaToken("ov_sa_nope")).toThrow(expect.objectContaining({ code: "invalid_token" }));
  });

  it("new SA secrets and refresh tokens", () => {
    const n = core.newSaSecret({ url: "https://a.example", saId: "sa1", master: new Uint8Array(32).fill(5), secretId: "s1", name: "ci" });
    const p = core.parseSaToken(n.token);
    expect(n.body).toMatchObject({ id: "s1", name: "ci", secret_hash: core.saSecretHash(p.secret), prefix: core.saSecretPrefix(p.secret), expires_at: null });
    expect(hex(core.unwrapSaMaster(p.kek, "sa1", n.body.wrapped_master))).toBe("05".repeat(32));
    expect(core.refreshTokenHash(V.refresh_token.token)).toBe(V.refresh_token.stored_hash_hex);
    expect(text(core.newRefreshToken())).toMatch(/^ov_rt_[A-Za-z0-9_-]{43}$/);
  });

  it("verifies the JWT vectors", async () => {
    const j = V.jwt;
    for (const v of j.valid) {
      const opts = { issuer: v.claims.iss, audience: "ov-sync", now: j.now };
      expect(core.verifyJwt(v.token, j.jwks, opts)).toEqual(v.claims);
      expect(core.isJwt(v.token)).toBe(true);
      expect(core.decodeJwt(v.token).claims).toEqual(v.claims);
      expect(core.decodeJwt(v.token).header.kid).toBe("test-2026-10");
    }
    const opts = { issuer: j.valid[0].claims.iss, audience: "ov-sync", now: j.now };
    for (const bad of j.invalid) {
      const e = await errorOf(() => core.verifyJwt(bad.token, j.jwks, opts));
      expect([bad.case, e.status]).toEqual([bad.case, bad.expect]);
    }
    expect(core.isJwt("a.b")).toBe(false);
  });

  it("restore proofs and the re-seal", () => {
    const r = V.restore_proof, k = V.keyset;
    const current = { encPk: fromB64u(r.new_public.enc_pk), signPk: fromB64u(r.new_public.sign_pk) };
    expect(hex(core.restoreProofMessage(r.user_id, current))).toBe(r.message_hex);
    const proof = core.restoreProof(fromHex(k.sign_seed_hex), r.user_id, current);
    expect(b64u(proof)).toBe(r.proof);
    expect(core.verifyRestoreProof(proof, r.user_id, current, fromB64u(r.old_sign_pk))).toBe(true);
    for (const bad of r.invalid) expect(core.verifyRestoreProof(fromB64u(bad.proof), r.user_id, current, fromB64u(r.old_sign_pk))).toBe(false);
    const re = r.reseal;
    const id = re.aad.slice("ov-vault-key|".length);
    const sealed = core.resealVaultKey(fromHex(k.enc_sk_hex), current.encPk, id, fromB64u(re.archived_sealed_key), { ephemeralSecretKey: fromHex(re.ephemeral_sk_hex), nonce: fromHex(re.nonce_hex) });
    expect(b64u(sealed)).toBe(re.sealed);
  });
});

describe("OPAQUE", () => {
  const T = opaqueTranscripts();
  const seed = (h) => fromHex(h);

  it("replays the opaque-ke transcript: client and test server, byte for byte", () => {
    const t = T.opaque_ke;
    const ids = core.opaqueIds(t.id_u, t.id_s);
    expect(ids).toEqual({ idU: t.id_u, idS: t.id_s });
    expect(core.opaqueIds("  Alice@Example.COM ", "https://accounts.openvireo.example/x")).toEqual({ idU: "alice@example.com", idS: "accounts.openvireo.example" });
    const r = t.registration;
    const start = core.opaqueStartRegistration(t.password, seed(r.client_start_seed_hex));
    expect(hex(start.request)).toBe(r.request_hex);
    const srv = core.opaqueServerRegistrationResponse(start.request, seed(r.server_seed_hex));
    expect(hex(srv.sec)).toBe(r.server_setup_hex);
    expect(hex(srv.response)).toBe(r.response_hex);
    const fin = core.opaqueFinishRegistration(start.state, srv.response, ids, seed(r.client_finish_seed_hex));
    expect(hex(fin.record)).toBe(r.record_hex);
    expect(hex(fin.exportKey)).toBe(r.export_key_hex);
    const stored = core.opaqueServerStoreRecord(srv.sec, fin.record);
    expect(hex(stored)).toBe(r.stored_record_hex);

    const l = t.login;
    const ls = core.opaqueStartLogin(bytes(t.password), seed(l.client_start_seed_hex));
    expect(hex(ls.ke1)).toBe(l.ke1_hex);
    const cr = core.opaqueServerCredentialResponse(ls.ke1, stored, ids, undefined, seed(l.server_seed_hex));
    expect(hex(cr.ke2)).toBe(l.ke2_hex);
    const lf = core.opaqueFinishLogin(ls.state, cr.ke2, ids, t.context, seed(l.client_finish_seed_hex));
    expect(hex(lf.authU)).toBe(l.auth_u_hex);
    expect(hex(lf.sessionKey)).toBe(l.session_key_hex);
    expect(hex(lf.exportKey)).toBe(l.export_key_hex);
    expect(hex(core.opaqueServerUserAuth(cr.sec, lf.authU))).toBe(l.session_key_hex);
    expect(core.opaqueServerUserAuth(cr.sec, new Uint8Array(64))).toBeUndefined();

    const w = t.login_wrong_password;
    const ws = core.opaqueStartLogin(w.password, seed(w.client_start_seed_hex));
    expect(hex(ws.ke1)).toBe(w.ke1_hex);
    const wc = core.opaqueServerCredentialResponse(ws.ke1, stored, ids, t.context, seed(w.server_seed_hex));
    expect(hex(wc.ke2)).toBe(w.ke2_hex);
    const e = (() => { try { core.opaqueFinishLogin(ws.state, wc.ke2, ids, undefined, seed(w.client_finish_seed_hex)); } catch (x) { return x; } })();
    expect([e.code, e.message]).toEqual(["opaque_failed", "wrong password"]);
  }, 60_000);

  it("interoperates with the libopaque transcripts (login and registration)", () => {
    const t = T.libopaque;
    const ids = core.opaqueIds(t.id_u, t.id_s);
    const l = t.login_opaque_ke_client;
    const ls = core.opaqueStartLogin(t.password, seed(l.client_start_seed_hex));
    expect(hex(ls.ke1)).toBe(l.ke1_hex);
    const lf = core.opaqueFinishLogin(ls.state, fromHex(l.ke2_hex), ids, undefined, seed(l.client_finish_seed_hex));
    expect(hex(lf.authU)).toBe(l.expected_auth_u_hex);
    expect(hex(lf.sessionKey)).toBe(l.session_key_hex);
    expect(hex(lf.exportKey)).toBe(l.export_key_hex);
    const r = t.opaque_ke_registration;
    const rs = core.opaqueStartRegistration(t.password, seed(r.client_start_seed_hex));
    expect(hex(rs.request)).toBe(r.request_hex);
    const rf = core.opaqueFinishRegistration(rs.state, fromHex(r.response_hex), ids, seed(r.client_finish_seed_hex));
    expect(hex(rf.record)).toBe(r.record_hex);
    expect(hex(rf.exportKey)).toBe(r.export_key_hex);
  }, 60_000);

  it("runs unseeded and refuses bad state", () => {
    const s = core.opaqueStartLogin("pw");
    expect(s.ke1.length).toBe(32 + 32 + 32);
    expect(() => core.opaqueFinishLogin(bytes("junk"), new Uint8Array(1), { idU: "a", idS: "b" })).toThrow(expect.objectContaining({ code: "opaque_failed" }));
    expect(() => core.opaqueStartLogin("")).toThrow(expect.objectContaining({ code: "opaque_failed" }));
  });
});

describe("KDBX", () => {
  const vk = fromHex(V.vault_kdbx.vault_key_hex);
  const fixture = vectorFile(V.vault_kdbx.file);
  const expectEntry = V.vault_kdbx.expect.entry;
  const DESKTOP_PW = "desktop pw ✓";

  it("reads the vault fixture with its vault key, and peeks its header", () => {
    const h = core.Kdbx.peekHeader(fixture);
    expect(h.kdf).toEqual({ kdf: "argon2id", m: V.vault_kdbx.kdf.m_kib * 1024, t: V.vault_kdbx.kdf.t, p: V.vault_kdbx.kdf.p });
    const db = core.Kdbx.read(fixture, { vaultKey: vk });
    expect(db.name === V.vault_kdbx.expect.root_group || db.groups()[0].name === V.vault_kdbx.expect.root_group).toBe(true);
    const e = db.entries().find((x) => x.title === expectEntry.Title);
    expect([e.username, text(e.passwordValue), e.url]).toEqual([expectEntry.UserName, expectEntry.Password, expectEntry.URL]);
    expect(db.kdfSettings()).toEqual(h.kdf);
    expect(db.rootGroupId).toBe(db.groups()[0].uuid);
    // The vault key is the key-file component: the same key as `keyFile`.
    expect(core.Kdbx.read(fixture, { keyFile: vk }).entries().length).toBe(db.entries().length);
    expect(() => core.Kdbx.read(fixture, { vaultKey: new Uint8Array(32) })).toThrow(expect.objectContaining({ code: "vault_key_mismatch" }));
    expect(() => core.Kdbx.read(bytes("not kdbx"), { vaultKey: vk })).toThrow(expect.objectContaining({ code: "kdbx_error" }));
    db.free();
  });

  it("reads the desktop fixtures (KDBX 4 Argon2d, KDBX 3.1) with a password and a password hash", () => {
    const a = core.Kdbx.read(vectorFile("kdbx/desktop-kdbx4-argon2d.kdbx"), { password: DESKTOP_PW });
    expect(a.kdfSettings().kdf).toBe("argon2d");
    expect(a.entries().some((e) => e.title === "From desktop")).toBe(true);
    const b = core.Kdbx.read(vectorFile("kdbx/desktop-kdbx31.kdbx"), { passwordHash: core.kdbxPasswordHash(bytes(DESKTOP_PW)) });
    expect(core.Kdbx.peekHeader(vectorFile("kdbx/desktop-kdbx31.kdbx")).version).toBe("3.1");
    expect(b.entries().map((e) => e.title)).toEqual(expect.arrayContaining(["Bank", "Server"]));
  });

  it("writes, re-keys, clones and opens with key versions", () => {
    const db = core.Kdbx.read(fixture, { vaultKey: vk });
    const again = core.Kdbx.read(db.write(), { vaultKey: vk });
    expect(again.entries()).toEqual(db.entries());
    const newKey = new Uint8Array(32).fill(9);
    const copy = db.clone();
    copy.rekeyToVaultKey(newKey);
    const rekeyed = copy.write();
    const { db: opened, keyVersion } = core.Kdbx.openWithKeyVersions(rekeyed, [{ version: 1, key: vk }, { version: 2, key: newKey }]);
    expect(keyVersion).toBe(2);
    expect(opened.entries().length).toBe(db.entries().length);
    expect(core.Kdbx.openWithKeyVersions(fixture, [{ version: 1, key: vk }, { version: 2, key: newKey }]).keyVersion).toBe(1);
    expect(() => core.Kdbx.openWithKeyVersions(fixture, [])).toThrow(expect.objectContaining({ code: "no_vault_key" }));
    // Sync generation, settings
    expect(db.syncGeneration()).toBe(0);
    db.setSyncGeneration(7, 1_800_000_000);
    expect(core.Kdbx.read(db.write(), { vaultKey: vk }).syncGeneration()).toBe(7);
    db.dropServerRemotes();
    const fresh = core.Kdbx.create("New", 1_800_000_000);
    expect(() => fresh.write()).toThrow(/no key/);
    fresh.setKey({ password: "pw" });
    expect(core.Kdbx.read(fresh.write(), { password: bytes("pw") }).name).toBe("New");
    const v = core.Kdbx.createVault("Team", newKey, 1_800_000_000);
    expect(core.Kdbx.read(v.write(), { vaultKey: newKey }).kdfSettings().kdf).toBe("argon2id");
  });

  /** A copy of the fixture with the GitHub entry's fields set, through the facade's local Vault. */
  async function edited(base, fields) {
    const vault = await core.Vault.openLocal(base, { keyFile: vk });
    const e = vault.entries().find((x) => x.title === expectEntry.Title);
    vault.editEntry(e.id, { fields: Object.entries(fields).map(([name, value]) => ({ name, value: bytes(value) })), removeFields: [], expiry: { kind: "keep" } });
    return { bytes: await vault.saveLocal(), id: e.id };
  }

  it("merge-fixtures 01 (different fields) on bytes, and a same-field conflict", async () => {
    // 01-different-fields: local changed Notes, remote changed Password: both kept, no conflict.
    const local = await edited(fixture, { Notes: "PIN changed" });
    const remote = await edited(fixture, { Password: "new-password" });
    const m = core.kdbxMerge(local.bytes, remote.bytes, fixture, { vaultKey: vk });
    expect([m.report.conflicts, m.report.remoteChanged, m.report.localChanged]).toEqual([[], true, true]);
    for (const out of [m.local, m.remote]) {
      const e = core.Kdbx.read(out, { vaultKey: vk }).entries().find((x) => x.title === expectEntry.Title);
      expect([e.notes, text(e.passwordValue)]).toEqual(["PIN changed", "new-password"]);
    }
    expect(m.report.updated).toContain(m.report.changes.find((c) => c.change === "modified" && c.subject === "entry").uuid);

    // Both changed Password. The facade's local Vault stamps both edits with the same time (its
    // clock is the open W2-A local-vault clock request), so this is a tie: the conflict is reported,
    // the local copy's value is kept (as in the SDK), and both copies converge. Newer-wins by time is
    // covered by ov-merge's own run of all 14 merge fixtures.
    const older = await edited(fixture, { Password: "older" });
    const newer = await edited(fixture, { Password: "newer" });
    const l = core.Kdbx.read(older.bytes, { vaultKey: vk });
    const r = core.Kdbx.read(newer.bytes, { vaultKey: vk });
    const base = core.Kdbx.read(fixture, { vaultKey: vk });
    const snap = base.snapshot();
    expect(Object.keys(snap)).toEqual(base.entries().filter((e) => true).map((e) => e.uuid).filter((id) => id in snap));
    expect(l.findConflicts(r, snap).map((c) => c.kind)).toEqual(["edited-on-both"]);
    expect(l.needsCommonBase(r, base.snapshot())).toBe(true);
    expect(l.hasPendingDeletions(r)).toBe(false);
    const report = l.mergeWithBase(r, base);
    // Kdbx ids are kdbxweb's (base64); the facade's EntryRecord ids are hex. Both parse as input.
    const id = l.entries().find((x) => x.title === expectEntry.Title).uuid;
    expect(Buffer.from(id, "base64").toString("hex")).toBe(older.id.replace(/-/g, ""));
    expect(report.conflicts.map((c) => [c.uuid, c.fields])).toEqual([[id, ["Password"]]]);
    const pw = (db) => text(db.entries().find((x) => x.title === expectEntry.Title).passwordValue);
    expect([pw(l), pw(r)]).toEqual(["older", "older"]);
    // Without a base only time decides, and equal times replace nothing (desktop Merger rule).
    const l2 = core.Kdbx.read(older.bytes, { vaultKey: vk });
    const r2 = core.Kdbx.read(newer.bytes, { vaultKey: vk });
    expect(l2.merge(r2, 1_900_000_000).conflicts).toEqual([]);
    expect([pw(l2), pw(r2)]).toEqual(["older", "newer"]);
  }, 30_000);

  it("imports (merge by UUID, as copies) and the one-way structure merge", () => {
    const target = core.Kdbx.create("Target", 1_800_000_000);
    const source = core.Kdbx.read(fixture, { vaultKey: vk });
    const n = source.entries().length;
    const s1 = target.importFrom(source);
    expect([s1.added, s1.updated]).toEqual([n, 0]);
    expect(target.importFrom(source)).toMatchObject({ added: 0, updated: 0, unchanged: n });
    const t2 = core.Kdbx.create("Copies", 1_800_000_000);
    const parent = t2.importTargets()[0];
    expect(parent.uuid).toBe(t2.rootGroupId);
    expect(t2.importAsCopies(source, parent.uuid, 1_800_000_000).added).toBe(n);
    expect(t2.entries().map((e) => e.uuid)).not.toContain(source.entries()[0].uuid);
    const t3 = core.Kdbx.create("Into", 1_800_000_000);
    const changes = t3.mergeFrom(source, "synchronize", { skipDatabaseCustomData: true });
    expect(changes.some((c) => c.change === "added" && c.subject === "entry")).toBe(true);
    expect(t3.entries().length).toBe(n);
  });
});
