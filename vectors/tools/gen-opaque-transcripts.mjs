#!/usr/bin/env node
// Writes vectors/opaque-transcripts.json: deterministic OPAQUE (SPEC §8, RFC 9807) runs from
//   1. the TS SDK (@openvireo/sdk/opaque: opaque-ke 4.0.1 compiled to WASM), client and test server, and
//   2. libopaque (the C core behind the Flask auth server and the desktop client), through
//      libopaque-transcript (see libopaque-transcript.c), including the opaque-ke client logging in to an
//      account registered by libopaque.
//
//   node gen-opaque-transcripts.mjs --libopaque-tool BIN [--sdk DIR] [--out FILE]
//
// --sdk is an openvireo-sdk checkout with packages/sdk/dist built (`npm run build`); it is only read.
// Usually run through gen-opaque-transcripts.sh, which builds the libopaque tool first.
//
// Determinism: the SDK draws one 32-byte seed per operation from crypto.getRandomValues (for a ChaCha20
// RNG inside the WASM module). This script replaces getRandomValues with a queue of named seeds, each
// SHA-256(UTF-8 "ov-opaque-transcripts/v1/" ‖ label), and checks that every operation takes exactly one.
// The libopaque tool gets a seed per command the same way.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

const here = dirname(fileURLToPath(import.meta.url));
const { values: args } = parseArgs({
  options: {
    sdk: { type: "string", default: process.env.OV_SDK ?? "/Users/bongani/kpnx/openvireo-sdk" },
    "libopaque-tool": { type: "string", default: process.env.OV_LIBOPAQUE_TOOL },
    out: { type: "string", default: resolve(here, "../opaque-transcripts.json") },
  },
});
if (!args["libopaque-tool"]) throw new Error("--libopaque-tool BIN is required (see build-libopaque-tool.sh)");

const hex = (b) => Buffer.from(b).toString("hex");
const unhex = (s) => new Uint8Array(Buffer.from(s, "hex"));
const utf8 = (s) => new TextEncoder().encode(s);
const nfkcHex = (pw) => hex(utf8(pw.normalize("NFKC")));
const SEED_PREFIX = "ov-opaque-transcripts/v1/";
const seedFor = (label) => new Uint8Array(createHash("sha256").update(SEED_PREFIX + label).digest());
function assert(cond, msg) {
  if (!cond) throw new Error("check failed: " + msg);
}

// Seeded crypto.getRandomValues: hands out queued seeds and fails on anything unexpected.
const queue = [];
Object.defineProperty(globalThis.crypto, "getRandomValues", {
  configurable: true,
  value(arr) {
    const next = queue.shift();
    if (!next) throw new Error("unexpected getRandomValues call (no seed queued)");
    if (arr.byteLength !== next.length) throw new Error(`getRandomValues(${arr.byteLength}), expected 32`);
    new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(next);
    return arr;
  },
});
/** Runs `fn` with one seed queued; returns [result, seedHex]. */
async function seeded(label, fn) {
  const seed = seedFor(label);
  queue.push(seed);
  const r = await fn();
  assert(queue.length === 0, `${label}: the operation did not take its seed`);
  return [r, hex(seed)];
}

const sdkDist = resolve(args.sdk, "packages/sdk/dist/opaque/index.js");
const sdk = await import(pathToFileURL(sdkDist).href);
const { OPAQUE_CONTEXT, opaqueIds, startRegistration, finishRegistration, startLogin, finishLogin } = sdk;
const server = sdk.opaqueServerForTests;
assert(OPAQUE_CONTEXT === "ov-opaque-v1", "SDK context is ov-opaque-v1");
await sdk.loadOpaque();

/** Runs a libopaque-transcript command; arguments are hex, the output is parsed into { name: hex }. */
function libopaque(cmd, ...hexArgs) {
  const out = execFileSync(args["libopaque-tool"], [cmd, ...hexArgs], { encoding: "utf8" });
  return Object.fromEntries(out.trim().split("\n").map((l) => l.split("=")));
}

// ---- 1. TS SDK: opaque-ke client + opaque-ke test server ----

async function opaqueKe() {
  const password = "correct horse battery staple";
  const ids = opaqueIds("alice@example.com", "accounts.openvireo.example");
  const L = (s) => "opaque_ke/" + s;

  const [rs, regStartSeed] = await seeded(L("registration/client_start"), () => startRegistration(password));
  const request = hex(rs.request);
  const [srv, srvSeed] = await seeded(L("registration/server"), () => server.registrationResponse(rs.request));
  const [rf, regFinishSeed] = await seeded(L("registration/client_finish"), () =>
    finishRegistration(rs.state, srv.response, ids),
  );
  const stored = await server.storeRecord(srv.sec, rf.record);

  async function login(prefix, pw) {
    const [ls, startSeed] = await seeded(L(prefix + "/client_start"), () => startLogin(pw));
    const ke1 = hex(ls.ke1);
    const [cr, srvSeed] = await seeded(L(prefix + "/server"), () => server.credentialResponse(ls.ke1, stored, ids));
    const step = {
      client_start_seed_hex: startSeed,
      ke1_hex: ke1,
      server_seed_hex: srvSeed,
      ke2_hex: hex(cr.ke2),
    };
    let fin;
    let finishSeed;
    try {
      [fin, finishSeed] = await seeded(L(prefix + "/client_finish"), () => finishLogin(ls.state, cr.ke2, ids));
    } catch (e) {
      queue.length = 0;
      assert(e.code === "opaque_failed", `${prefix}: wrong password gives opaque_failed (${e.code})`);
      return { ...step, client_finish_seed_hex: hex(seedFor(L(prefix + "/client_finish"))), expect: "auth_failed" };
    }
    const serverKey = await server.userAuth(cr.sec, fin.authU);
    assert(serverKey && hex(serverKey) === hex(fin.sessionKey), `${prefix}: server accepts auth_u, same session key`);
    return {
      ...step,
      client_finish_seed_hex: finishSeed,
      auth_u_hex: hex(fin.authU),
      session_key_hex: hex(fin.sessionKey),
      export_key_hex: hex(fin.exportKey),
    };
  }

  const ok = await login("login", password);
  assert(ok.export_key_hex === hex(rf.exportKey), "login export key equals the registration export key");
  const wrongPassword = "correct horse battery stapler";
  const bad = await login("login_wrong_password", wrongPassword);
  assert(bad.expect === "auth_failed", "wrong password fails");

  return {
    description:
      "The TS SDK's OPAQUE client (opaque-ke 4.0.1 in WASM) against its opaque-ke test server " +
      "(opaqueServerForTests: one ServerSetup per user, generated from server_seed, credential id \"ov\"). " +
      "Every *_seed_hex is the 32-byte ChaCha20Rng seed of that one operation.",
    password,
    password_nfkc_hex: nfkcHex(password),
    id_u: ids.idU,
    id_s: ids.idS,
    context: OPAQUE_CONTEXT,
    registration: {
      client_start_seed_hex: regStartSeed,
      request_hex: request,
      server_seed_hex: srvSeed,
      server_setup_hex: hex(srv.sec),
      response_hex: hex(srv.response),
      client_finish_seed_hex: regFinishSeed,
      record_hex: hex(rf.record),
      export_key_hex: hex(rf.exportKey),
      stored_record_hex: hex(stored),
    },
    login: ok,
    login_wrong_password: { password: wrongPassword, ...bad },
  };
}

// ---- 2. libopaque ----

async function libopaqueRuns() {
  const password = "Ünïcödé pässwörd ﬁ";
  const ids = opaqueIds("bob@example.com", "accounts.openvireo.example");
  const pwHex = nfkcHex(password);
  const idArgs = [hex(utf8(ids.idU)), hex(utf8(ids.idS))];
  const ctxHex = hex(utf8(OPAQUE_CONTEXT));
  const L = (s) => "libopaque/" + s;

  // a. libopaque client + libopaque server registration (what the desktop app does against Flask)
  const regSeed = hex(seedFor(L("registration")));
  const reg = libopaque("register", regSeed, pwHex, ...idArgs);

  // b. libopaque client logs in to that record
  const cSeed = hex(seedFor(L("login_c_client")));
  const c = libopaque("login", cSeed, reg.user_record, pwHex, ...idArgs, ctxHex);
  assert(c.export_key === reg.export_key, "C login export key equals the registration export key");

  // c. opaque-ke client (TS SDK) logs in to the libopaque-registered account on the libopaque server
  const P = "login_opaque_ke_client";
  const [ls, startSeed] = await seeded(L(P + "/client_start"), () => startLogin(password));
  const srvSeed = hex(seedFor(L(P + "/server")));
  const s = libopaque("server-login", srvSeed, reg.user_record, hex(ls.ke1), ...idArgs, ctxHex);
  const [fin, finishSeed] = await seeded(L(P + "/client_finish"), () => finishLogin(ls.state, unhex(s.ke2), ids));
  assert(hex(fin.authU) === s.expected_auth_u, "opaque-ke auth_u matches libopaque's expected auth_u");
  assert(hex(fin.sessionKey) === s.session_key, "opaque-ke and libopaque agree on the session key");
  assert(hex(fin.exportKey) === reg.export_key, "opaque-ke recovers libopaque's export key");

  // d. opaque-ke client registers on the libopaque server (the web flow), then the libopaque client logs in
  const R = "opaque_ke_registration";
  const [rs, rStartSeed] = await seeded(L(R + "/client_start"), () => startRegistration(password));
  const rSrvSeed = hex(seedFor(L(R + "/server")));
  const rsrv = libopaque("server-register", rSrvSeed, hex(rs.request));
  const [rf, rFinishSeed] = await seeded(L(R + "/client_finish"), () =>
    finishRegistration(rs.state, unhex(rsrv.response), ids),
  );
  const rstored = libopaque("server-store", rsrv.server_sec, hex(rf.record));
  const rcSeed = hex(seedFor(L(R + "/login_c_client")));
  const rc = libopaque("login", rcSeed, rstored.user_record, pwHex, ...idArgs, ctxHex);
  assert(rc.export_key === hex(rf.exportKey), "C login recovers the opaque-ke registration's export key");

  return {
    description:
      "libopaque 6e9ac92 (liboprf f925b87, libsodium 1.0.20), the C core of the Flask auth server and the " +
      "desktop client, run by vectors/tools/libopaque-transcript with seeded randombytes (seed_hex per " +
      "command). The server uses a per-user keypair: server_sec_hex = skS ‖ kU, user_record_hex = kU ‖ skS ‖ " +
      "record (libopaque's stored format). login_opaque_ke_client is the opaque-ke client (TS SDK) logging " +
      "in to the account libopaque registered: a replay feeds ke2_hex to an opaque-ke client started from " +
      "client_start_seed_hex and must produce auth_u_hex (= expected_auth_u_hex from the libopaque server), " +
      "session_key_hex and the registration's export_key_hex.",
    password,
    password_nfkc_hex: pwHex,
    id_u: ids.idU,
    id_s: ids.idS,
    context: OPAQUE_CONTEXT,
    registration: {
      seed_hex: regSeed,
      request_hex: reg.request,
      server_sec_hex: reg.server_sec,
      response_hex: reg.response,
      record_hex: reg.record,
      export_key_hex: reg.export_key,
      user_record_hex: reg.user_record,
    },
    login_c_client: {
      seed_hex: cSeed,
      ke1_hex: c.ke1,
      ke2_hex: c.ke2,
      auth_u_hex: c.auth_u,
      session_key_hex: c.session_key,
      export_key_hex: c.export_key,
    },
    login_opaque_ke_client: {
      client_start_seed_hex: startSeed,
      ke1_hex: hex(ls.ke1),
      server_seed_hex: srvSeed,
      ke2_hex: s.ke2,
      expected_auth_u_hex: s.expected_auth_u,
      client_finish_seed_hex: finishSeed,
      auth_u_hex: hex(fin.authU),
      session_key_hex: hex(fin.sessionKey),
      export_key_hex: hex(fin.exportKey),
    },
    opaque_ke_registration: {
      client_start_seed_hex: rStartSeed,
      request_hex: hex(rs.request),
      server_seed_hex: rSrvSeed,
      server_sec_hex: rsrv.server_sec,
      response_hex: rsrv.response,
      client_finish_seed_hex: rFinishSeed,
      record_hex: hex(rf.record),
      export_key_hex: hex(rf.exportKey),
      user_record_hex: rstored.user_record,
      login_c_client: {
        seed_hex: rcSeed,
        ke1_hex: rc.ke1,
        ke2_hex: rc.ke2,
        auth_u_hex: rc.auth_u,
        session_key_hex: rc.session_key,
        export_key_hex: rc.export_key,
      },
    },
  };
}

const doc = {
  spec: "ov v1, SPEC §8: OPAQUE (RFC 9807)",
  encoding: "binary values are lowercase hex (field names end in _hex); other strings are UTF-8",
  generated_by: "vectors/tools/gen-opaque-transcripts.sh (see vectors/SOURCE.md)",
  suite: {
    oprf: "ristretto255-SHA512",
    key_exchange: "3DH (ristretto255, SHA-512)",
    ksf: { alg: "argon2id", version: 19, m_kib: 65536, t: 2, p: 1, salt_hex: "00".repeat(16) },
    context: OPAQUE_CONTEXT,
    password_encoding: "UTF-8 of the NFKC-normalised password",
  },
  seed_derivation: `seed = SHA-256(UTF-8 "${SEED_PREFIX}" ‖ label); every seed used is recorded next to its step`,
  opaque_ke: await opaqueKe(),
  libopaque: await libopaqueRuns(),
};

writeFileSync(resolve(args.out), JSON.stringify(doc, null, 2) + "\n");
console.log(`wrote ${resolve(args.out)}; all cross-checks passed`);
