#!/usr/bin/env node
// Cross-client scenarios against the real local stack: the `ov` binary (native core) and the Node SDK
// (core-wasm) on the same accounts, each one checking what the other wrote. Run by e2e/run.sh, which
// brings the stack up and keeps the auth server's rate limits clear; see e2e/README.md.
//
//   OV_E2E_ISSUER    issuer (default http://localhost:8000)
//   OV_BIN           the ov binary
//   OV_E2E_SDK_DIR   an openvireo-sdk checkout with packages/sdk/dist built
//   OV_E2E_KDBX_CLI  optional: the desktop's openvireo-kdbx, to read a core-written vault file (scenario 3)
//   OV_E2E_OUT       where to write the results as JSON (default: none)
//   OV_E2E_ONLY      comma-separated scenario numbers to run (default: all)
//
// Exit status: 0 when every scenario passed, 1 otherwise. Never prints passwords or Secret Keys.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const ISSUER = process.env.OV_E2E_ISSUER || "http://localhost:8000";
const OV_BIN = process.env.OV_BIN;
const SDK_DIR = process.env.OV_E2E_SDK_DIR;
const KDBX_CLI = process.env.OV_E2E_KDBX_CLI || "";
const ONLY = (process.env.OV_E2E_ONLY || "").split(",").filter(Boolean);
// Failures already reported to their owners: shown as "fail (known)" and left out of the exit status unless
// OV_E2E_STRICT=1. Remove an entry once its fix is in.
const KNOWN = new Map();
const STRICT = process.env.OV_E2E_STRICT === "1";
if (!OV_BIN || !SDK_DIR) {
  console.error("set OV_BIN and OV_E2E_SDK_DIR (e2e/run.sh does)");
  process.exit(2);
}
const sdk = await import(pathToFileURL(join(SDK_DIR, "packages/sdk/dist/index.js")).href);

const RUN = Math.random().toString(16).slice(2, 8);
const PASSWORD = "correct horse battery staple ✓";
const scratch = mkdtempSync(join(tmpdir(), "ov-e2e-"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// KDBX stores whole seconds and the merge compares them: two edits of one entry need a second between them
const nextSecond = () => sleep(1100);

class Check extends Error {}
function expect(cond, what) {
  if (!cond) throw new Check(what);
}
function eq(actual, expected, what) {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) throw new Check(`${what}: expected ${e}, got ${a}`);
}
async function rejects(promise, what, pattern) {
  try {
    await promise;
  } catch (e) {
    if (pattern && !pattern.test(`${e?.code ?? ""} ${e?.message ?? e}`)) throw new Check(`${what}: wrong error ${e?.code} ${e?.message}`);
    return e;
  }
  throw new Check(`${what}: did not fail`);
}

// ---------------------------------------------------------------- clients

let users = 0;
/** A new account, registered with the SDK on its first device. */
async function sdkUser(tag) {
  const email = `e2e-${tag}-${RUN}-${++users}@example.com`;
  const device = await sdkDevice(`sdk ${tag} 1`);
  const { secretKey } = await device.register({ email, password: PASSWORD });
  const ovDir = mkdtempSync(join(scratch, `ov-${tag}-`));
  return { email, password: PASSWORD, secretKey, sdk: device, ovDir };
}
function sdkDevice(name) {
  return sdk.Account.connect({ issuer: ISSUER, device: { name, platform: "cli" } });
}
/** Another SDK device of `u`, signed in with the Secret Key. */
async function sdkLogin(u, name) {
  const d = await sdkDevice(name);
  await d.login({ email: u.email, password: u.password, secretKey: u.secretKey });
  return d;
}

/** Runs ov as `u` (its own config dir; the password from the environment). Never throws. */
function ov(u, args, { input, env = {}, timeoutMs = 60_000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(OV_BIN, args, {
      env: {
        PATH: process.env.PATH,
        HOME: u.ovDir,
        OPENVIREO_CONFIG_DIR: u.ovDir,
        OPENVIREO_PASSWORD: u.password,
        ...env,
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      resolve({ code: signal ? `signal ${signal}` : code, stdout, stderr: stderr.trim() });
    });
    child.stdin.end(input ?? "");
  });
}
async function ovOk(u, args, opts) {
  const r = await ov(u, args, opts);
  if (r.code !== 0) throw new Check(`ov ${args.slice(0, 2).join(" ")} exited ${r.code}: ${r.stderr}`);
  return r;
}
async function ovJson(u, args) {
  return JSON.parse((await ovOk(u, [...args, "--json"])).stdout);
}
async function ovFails(u, args, what, pattern) {
  const r = await ov(u, args);
  if (r.code === 0) throw new Check(`${what}: ov ${args.join(" ")} succeeded`);
  if (pattern && !pattern.test(r.stderr)) throw new Check(`${what}: unexpected error: ${r.stderr}`);
  return r;
}
function ovLogin(u) {
  return ovOk(u, ["login", "--issuer", ISSUER, "--email", u.email, "--secret-key", u.secretKey]);
}

const titles = (av) => av.vault.entries(false).map((e) => e.title).sort();
const entryByTitle = (av, title, bin = false) => av.vault.entries(bin).find((e) => e.title === title);
const field = (av, id, name) => {
  const f = av.vault.entry(id).fields.find((x) => x.name === name);
  return f ? new TextDecoder().decode(f.value) : undefined;
};
const setFields = (av, groupPath, entry, fields, create = false) => sdk.setItemFields(av.vault, { groupPath, entry }, fields, { create });

// ---------------------------------------------------------------- results

const SCENARIOS = {
  1: "register on one client, log in on the others",
  2: "create, edit, delete with concurrent conflicts",
  3: "recycle bin (restore to the previous group)",
  4: "share a vault to a second user",
  5: "share link made on one client, opened on another",
  6: "key rotation",
  "6b": "key rotation seen by a device signed in before it (no vault list first)",
  7: "account deletion and restore",
};
const results = []; // { scenario, client, status: pass|fail|n/a, note }
function cell(scenario, client, status, note = "", known = false) {
  results.push({ scenario, client, status, note, ...(known ? { known } : {}) });
}

async function scenario(n, clients, body) {
  if (ONLY.length && !ONLY.includes(String(n))) return;
  const steps = [];
  const step = (s) => steps.push(s);
  const t0 = Date.now();
  process.stdout.write(`\n[${n}] ${SCENARIOS[n]}\n`);
  try {
    const notes = (await body(step)) || {};
    for (const c of clients) cell(n, c, "pass", notes[c] || "");
    for (const [c, note] of Object.entries(notes)) if (!clients.includes(c)) cell(n, c, "n/a", note);
    process.stdout.write(`    PASS (${((Date.now() - t0) / 1000).toFixed(1)} s): ${steps.join("; ")}\n`);
  } catch (e) {
    const where = steps.length ? ` after: ${steps.join("; ")}` : "";
    const msg = e instanceof Check ? e.message : `${e?.code ?? e?.name ?? "error"}: ${e?.message ?? e}`;
    const known = KNOWN.get(String(n));
    for (const c of clients) cell(n, c, "fail", known ? `${msg} [known: ${known}]` : msg, !!known);
    process.stdout.write(`    FAIL${known ? " (known)" : ""}: ${msg}${where}\n`);
    if (!(e instanceof Check) && e?.stack) process.stdout.write(`    ${e.stack.split("\n").slice(1, 4).join("\n    ")}\n`);
  }
}

// ---------------------------------------------------------------- 1. register and log in

await scenario(1, ["sdk", "ov"], async (step) => {
  const u = await sdkUser("s1");
  step("SDK registered");
  const v = await u.sdk.createVault("Personal");
  setFields(v, ["Finance"], "Bank", { UserName: "alice", Password: "from-sdk-1" }, true);
  eq((await v.sync()).outcome, "uploaded", "first upload");
  step("SDK created a vault with an entry");

  // a second SDK device needs the Secret Key the first time
  const fresh = await sdkDevice("sdk s1 no key");
  await rejects(fresh.login({ email: u.email, password: u.password }), "SDK login without the Secret Key", /invalid_secret_key/);
  const second = await sdkLogin(u, "sdk s1 2");
  eq((await second.listVaults()).map((x) => x.name), ["Personal"], "second SDK device's vaults");
  step("second SDK device signed in");

  // ov: refuses a wrong password, then signs in and reads the SDK's entry
  await ovFails({ ...u, password: "wrong password" }, ["login", "--issuer", ISSUER, "--email", u.email, "--secret-key", u.secretKey], "ov login with a wrong password");
  await ovLogin(u);
  const who = (await ovOk(u, ["whoami"])).stdout;
  expect(who.includes(`email: ${u.email}`), `ov whoami shows the email: ${who}`);
  const vaults = await ovJson(u, ["vault", "list"]);
  eq(vaults.map((x) => [x.name, x.role]), [["Personal", "manage"]], "ov vault list");
  const item = await ovJson(u, ["item", "get", "ov://Personal/Finance/Bank", "--reveal"]);
  eq([item.group, item.fields.UserName, item.fields.Password], [["Finance"], "alice", "from-sdk-1"], "ov item get");
  step("ov signed in and read the entry");

  // and the other way: ov writes, both SDK devices read it
  await ovOk(u, ["item", "create", "ov://Personal/Mail", "UserName=alice@mail", "Password=from-ov-1"]);
  await v.sync({ localChanged: false });
  const opened = await second.openVault(vaults[0].id);
  eq(titles(v), ["Bank", "Mail"], "SDK device 1 sees ov's entry");
  eq(opened.read("ov://Personal/Mail/Password"), "from-ov-1", "SDK device 2 reads ov's entry");
  step("ov created an entry both SDK devices read");
  await ovOk(u, ["logout"]);
  await ovFails(u, ["vault", "list"], "ov after logout", /not signed in/);
  step("ov logout");
  return { ov: "ov can't register (no `ov register`), so it is the second client here" };
});

// ---------------------------------------------------------------- 2. create, edit, delete, conflicts

await scenario(2, ["sdk", "ov"], async (step) => {
  const u = await sdkUser("s2");
  const a = await u.sdk.createVault("Work");
  await ovLogin(u);
  const b = await (await sdkLogin(u, "sdk s2 2")).openVault(a.id);

  // create on ov, see it on the SDK (group path created on the way)
  await ovOk(u, ["item", "create", "ov://Work/Servers/DB", "UserName=admin", "Password=p1", "Notes=base"]);
  await a.sync({ localChanged: false });
  const db = entryByTitle(a, "DB");
  expect(db, "SDK sees ov's new entry");
  eq(db.groupPath, ["Servers"], "group path of ov's entry");
  step("ov created, SDK pulled");

  // concurrent edits of different fields: SDK changes UserName locally, ov changes Password and uploads first
  await nextSecond();
  setFields(a, ["Servers"], "DB", { UserName: "root" });
  await ovOk(u, ["item", "edit", "ov://Work/Servers/DB", "Password=p2"]);
  const r1 = await a.sync();
  eq(r1.outcome, "uploaded", "SDK sync after ov's edit");
  eq(r1.conflicts.length, 0, "different fields: no conflict");
  eq([field(a, db.id, "UserName"), field(a, db.id, "Password")], ["root", "p2"], "SDK keeps both edits");
  eq((await ovOk(u, ["read", "ov://Work/Servers/DB/UserName"])).stdout, "root\n", "ov reads the SDK's edit");
  eq((await ovOk(u, ["read", "ov://Work/Servers/DB/Password"])).stdout, "p2\n", "ov reads its own edit after the merge");
  step("different-field concurrent edits merged");

  // concurrent edits of the same field: the newer one (ov's) wins and the SDK reports the conflict
  await nextSecond();
  setFields(a, ["Servers"], "DB", { Notes: "from sdk" });
  await nextSecond();
  await ovOk(u, ["item", "edit", "ov://Work/Servers/DB", "Notes=from ov"]);
  const r2 = await a.sync();
  const conflict = r2.conflicts.find((c) => c.uuid === db.id);
  expect(conflict, `same field: SDK reports a conflict (got ${JSON.stringify(r2.conflicts)})`);
  expect(conflict.fields.includes("Notes"), `conflict names Notes: ${JSON.stringify(conflict)}`);
  eq(field(a, db.id, "Notes"), "from ov", "newer edit wins");
  eq((await ovOk(u, ["read", "ov://Work/Servers/DB/Notes"])).stdout, "from ov\n", "ov agrees");
  step("same-field conflict reported, newer wins");

  // three writers at once (two SDK devices and ov): each gets in through the 412 merge-and-retry
  await b.sync({ localChanged: false });
  setFields(a, [], "From A", { Password: "a" }, true);
  setFields(b, [], "From B", { Password: "b" }, true);
  const [ra, rb, rov] = await Promise.all([a.sync(), b.sync(), ov(u, ["item", "create", "ov://Work/From ov", "Password=o"])]);
  expect(rov.code === 0, `concurrent ov create: ${rov.stderr}`);
  await a.sync({ localChanged: false });
  await b.sync({ localChanged: false });
  const all = ["DB", "From A", "From B", "From ov"];
  eq(titles(a), all, "device A converged");
  eq(titles(b), all, "device B converged");
  const listed = (await ovJson(u, ["item", "list", "Work"])).map((i) => i.title).sort();
  eq(listed, all, "ov converged");
  step(`three concurrent writers converged (SDK attempts ${ra.attempts}+${rb.attempts})`);

  // delete on one SDK device: gone on the other and on ov
  await nextSecond();
  b.vault.deleteEntry(entryByTitle(b, "From B").id);
  await b.sync();
  await a.sync({ localChanged: false });
  eq(titles(a), ["DB", "From A", "From ov"], "SDK A after B's delete");
  await ovFails(u, ["item", "get", "ov://Work/From B"], "ov get of a deleted entry");
  eq((await ovJson(u, ["item", "list", "Work"])).length, 3, "ov list after delete");
  step("delete propagated");

  // delete on one side while the other edits it: the edit keeps it (deletions are decided against the base)
  await nextSecond();
  a.vault.deleteEntry(entryByTitle(a, "From ov").id);
  a.vault.emptyRecycleBin();
  await ovOk(u, ["item", "edit", "ov://Work/From ov", "Password=o2"]);
  await a.sync();
  eq((await ovOk(u, ["read", "ov://Work/From ov/Password"])).stdout, "o2\n", "edited entry survives a concurrent delete");
  step("edit beats concurrent delete");
  return { ov: "ov has no delete command: deletes are made on the SDK and checked on ov" };
});

// ---------------------------------------------------------------- 3. recycle bin

await scenario(3, ["sdk", "ov", ...(KDBX_CLI ? ["desktop"] : [])], async (step) => {
  const u = await sdkUser("s3");
  const a = await u.sdk.createVault("Home");
  setFields(a, ["Finance", "Cards"], "Visa", { UserName: "me", Password: "4111" }, true);
  setFields(a, [], "Wifi", { Password: "w" }, true);
  await a.sync();
  await ovLogin(u);
  const visa = entryByTitle(a, "Visa");

  // delete to the bin on SDK device A
  await nextSecond();
  a.vault.deleteEntry(visa.id);
  expect(a.vault.isInRecycleBin(visa.id), "deleted entry is in the bin");
  await a.sync();
  step("SDK moved Visa to the bin");

  // ov doesn't list or find it any more
  eq((await ovJson(u, ["item", "list", "Home"])).map((i) => i.title), ["Wifi"], "ov list skips the bin");
  await ovFails(u, ["item", "get", "ov://Home/Finance/Cards/Visa"], "ov get at the old place");
  step("ov no longer sees it");

  // the server's copy is KDBX 4.1 while it remembers the previous parent group (contract-v1.8)
  const fileVault = a.vault.copyWithoutRemotes({ password: new TextEncoder().encode("e2e") });
  const bytes = await fileVault.saveLocal();
  const minor = bytes[8] | (bytes[9] << 8);
  const major = bytes[10] | (bytes[11] << 8);
  eq(`${major}.${minor}`, "4.1", "KDBX version with an entry in the bin");
  step("file is KDBX 4.1");

  let desktopNote = "";
  if (KDBX_CLI) {
    // the desktop's own C++ KDBX reader opens the core-written file and shows Visa in the bin
    const file = join(scratch, `s3-${RUN}.kdbx`);
    writeFileSync(file, bytes);
    const home = mkdtempSync(join(scratch, "kdbx-home-"));
    const out = await new Promise((resolve) => {
      const c = spawn(KDBX_CLI, ["ls", "-q", "-R", "-f", file], { env: { PATH: process.env.PATH, HOME: home }, stdio: ["pipe", "pipe", "pipe"] });
      let o = "";
      let e = "";
      c.stdout.on("data", (d) => (o += d));
      c.stderr.on("data", (d) => (e += d));
      c.on("close", (code) => resolve({ code, o, e }));
      c.stdin.end("e2e\n");
    });
    expect(out.code === 0, `openvireo-kdbx ls exited ${out.code}: ${out.e.trim()}`);
    expect(/Recycle Bin\/Visa/.test(out.o), `openvireo-kdbx lists Visa in the bin: ${out.o}`);
    step("desktop openvireo-kdbx reads the 4.1 file");
    desktopNote = "desktop's openvireo-kdbx (its own KDBX reader) opens the core-written 4.1 file; Visa listed in the Recycle Bin. Restore itself is n/a: no scriptable desktop restore";
  }

  // a second SDK device restores it from a fresh download: it goes back to Finance/Cards, not the root
  const b = await (await sdkLogin(u, "sdk s3 2")).openVault(a.id);
  const inBin = b.vault.entries(true).find((e) => e.id === visa.id);
  expect(inBin?.inRecycleBin, "device B sees Visa in the bin");
  await nextSecond();
  b.vault.restoreFromRecycleBin(visa.id);
  eq(b.vault.entry(visa.id).groupPath, ["Finance", "Cards"], "restored to its previous group");
  await b.sync();
  step("SDK device B restored it");

  await a.sync({ localChanged: false });
  expect(!a.vault.isInRecycleBin(visa.id), "device A: out of the bin");
  eq(a.vault.entry(visa.id).groupPath, ["Finance", "Cards"], "device A: previous group");
  const item = await ovJson(u, ["item", "get", "ov://Home/Finance/Cards/Visa", "--reveal"]);
  eq([item.id, item.fields.Password], [visa.id, "4111"], "ov finds it at its old place");
  step("device A and ov see it back in Finance/Cards");

  // emptying the bin deletes for good everywhere
  await nextSecond();
  a.vault.deleteEntry(entryByTitle(a, "Wifi").id);
  a.vault.emptyRecycleBin();
  await a.sync();
  await b.sync({ localChanged: false });
  expect(!b.vault.entries(true).some((e) => e.title === "Wifi"), "emptied bin reaches device B");
  await ovFails(u, ["item", "get", "ov://Home/Wifi"], "ov after the bin was emptied");
  step("emptied bin propagated");
  return {
    ov: "ov has no bin commands (delete/restore made on the SDK); ov checked the entry left and came back to Finance/Cards",
    ...(KDBX_CLI ? { desktop: desktopNote } : {}),
  };
});

// ---------------------------------------------------------------- 4. share a vault

await scenario(4, ["sdk", "ov"], async (step) => {
  const alice = await sdkUser("s4-alice");
  const bob = await sdkUser("s4-bob");
  const v = await alice.sdk.createVault("Team");
  setFields(v, ["Infra"], "AWS", { UserName: "root", Password: "aws-1" }, true);
  await v.sync();

  // Alice (SDK) compares Bob's fingerprint with what Bob's own client shows, then shares to those keys
  const looked = await alice.sdk.auth.lookupUser(bob.email);
  const keys = sdk.trustedPublicKeys(looked);
  eq(sdk.fingerprint(keys), bob.sdk.fingerprint, "Bob's fingerprint as Alice sees it");
  const shared = await alice.sdk.shareWithKeys(v.id, { principal: looked.principal }, "write", keys);
  eq(shared.principal, looked.principal, "shared principal");
  step("SDK (Alice) shared Team to Bob with write");

  // Bob on ov: lists it, reads, writes
  await ovLogin(bob);
  const listed = await ovJson(bob, ["vault", "list"]);
  eq(listed.map((x) => [x.name, x.role]), [["Team", "write"]], "Bob's ov vault list");
  eq((await ovOk(bob, ["read", "ov://Team/Infra/AWS/Password"])).stdout, "aws-1\n", "Bob reads on ov");
  await ovOk(bob, ["item", "edit", "ov://Team/Infra/AWS", "Password=aws-2"]);
  await v.sync({ localChanged: false });
  eq(v.read("ov://Team/Infra/AWS/Password"), "aws-2", "Alice (SDK) reads Bob's ov edit");
  step("Bob (ov) read and wrote; Alice saw it");

  // Bob's SDK device too, and Alice on ov sees the vault as its manager
  const bobVault = await bob.sdk.openVault(v.id);
  eq(bobVault.info.role, "write", "Bob's SDK role");
  setFields(bobVault, [], "From Bob SDK", { Password: "b" }, true);
  await bobVault.sync();
  await ovLogin(alice);
  eq((await ovJson(alice, ["vault", "list"])).map((x) => [x.name, x.role]), [["Team", "manage"]], "Alice's ov vault list");
  eq((await ovOk(alice, ["read", "ov://Team/From Bob SDK/Password"])).stdout, "b\n", "Alice (ov) reads Bob's SDK entry");
  step("Bob (SDK) wrote; Alice (ov) read it");

  // a read-only share can't write
  await alice.sdk.share(v.id, { principal: looked.principal }, "read");
  eq((await ovJson(bob, ["vault", "list"]))[0].role, "read", "Bob's role is read");
  await ovFails(bob, ["item", "edit", "ov://Team/Infra/AWS", "Password=nope"], "ov write with read role");
  eq((await alice.sdk.openVault(v.id)).read("ov://Team/Infra/AWS/Password"), "aws-2", "refused write didn't land");
  step("read role refuses ov writes");
});

// ---------------------------------------------------------------- 5. share links

await scenario(5, ["sdk", "ov"], async (step) => {
  const u = await sdkUser("s5");
  const v = await u.sdk.createVault("Links");
  setFields(v, ["Web"], "Shop", { UserName: "buyer", Password: "shop-pw", URL: "https://shop.example" }, true);
  await v.sync();
  await ovLogin(u);
  const api = u.sdk.config.api;

  // made on ov, opened with the SDK (no account), twice
  const link = (await ovOk(u, ["share", "ov://Links/Web/Shop", "--max-opens", "2"])).stdout.trim();
  expect(link.includes("#"), "ov printed a link with a key fragment");
  const opened = await sdk.openShare(api, link);
  const flds = Object.fromEntries(opened.payload.fields.map((f) => [f.k, f.value]));
  eq([opened.payload.title, flds.username, flds.password, flds.url], ["Shop", "buyer", "shop-pw", "https://shop.example"], "SDK opens ov's link");
  eq(opened.opensLeft, 1, "opens left after one");
  await sdk.openShare(api, link);
  await rejects(sdk.openShare(api, link), "third open of a 2-open link");
  step("ov link opened twice by the SDK, third refused");

  // ov share list counts the opens; the SDK's list agrees
  const list = await ovJson(u, ["share", "list"]);
  expect(list.length === 1, `ov share list has one link: ${JSON.stringify(list)}`);
  const s = list[0];
  expect(s.opens === 2 && s.status === "ended", `ov share list: ${JSON.stringify(s)}`);
  const sdkList = await u.sdk.listShares();
  eq(sdkList.map((x) => x.id), [s.id], "SDK lists the same link");
  step("ov and SDK lists agree");

  // with a passcode
  const pl = (await ovOk(u, ["share", "--text", "--title", "Note", "--passcode"], { input: "the text\n", env: { OPENVIREO_SHARE_PASSCODE: "1234" } })).stdout.trim();
  await rejects(sdk.openShare(api, pl), "passcode link without a passcode", /passcode_required/);
  await rejects(sdk.openShare(api, pl, { passcode: "9999" }), "wrong passcode", /invalid_passcode/);
  const text = await sdk.openShare(api, pl, { passcode: "1234" });
  expect(JSON.stringify(text.payload).includes("the text"), `text share payload: ${JSON.stringify(text.payload)}`);
  step("passcode link from ov opened by the SDK");

  // made on the SDK, revoked on ov
  const item = sdk.itemOf(v.vault.entry(entryByTitle(v, "Shop").id), { reveal: true });
  const created = await u.sdk.createShare(sdk.itemSharePayload(item, sdk.DEFAULT_SHARE_FIELDS, "e2e"), { expiresIn: 3600, vaultId: v.id, entryId: item.id });
  await ovOk(u, ["share", "revoke", created.id]);
  await rejects(sdk.openShare(api, created.url), "revoked link");
  const after = await ovJson(u, ["share", "list"]);
  const revoked = after.find((x) => x.id === created.id);
  expect(revoked?.status === "ended", `ov lists the SDK's link as ended: ${JSON.stringify(revoked)}`);
  step("SDK link revoked on ov");
  return { ov: "ov makes, lists and revokes links but has no command to open one; the SDK opens them" };
});

// ---------------------------------------------------------------- 6. key rotation

await scenario(6, ["sdk", "ov"], async (step) => {
  const alice = await sdkUser("s6-alice");
  const bob = await sdkUser("s6-bob");
  const v = await alice.sdk.createVault("Rotating");
  setFields(v, [], "Prod", { Password: "prod-1" }, true);
  await v.sync();
  await alice.sdk.share(v.id, { email: bob.email }, "write");
  await ovLogin(bob);
  eq((await ovOk(bob, ["read", "ov://Rotating/Prod/Password"])).stdout, "prod-1\n", "Bob reads before rotation");

  // a plain rotation: everyone keeps access with the new key
  const before = (await alice.sdk.listVaults())[0].currentKeyVersion;
  await alice.sdk.rotate(v.id);
  const info = (await alice.sdk.listVaults())[0];
  eq([info.currentKeyVersion, info.pendingKeyVersion ?? null], [before + 1, null], "key version after rotate");
  eq((await ovOk(bob, ["read", "ov://Rotating/Prod/Password"])).stdout, "prod-1\n", "Bob (ov) reads after rotation");
  await ovOk(bob, ["item", "edit", "ov://Rotating/Prod", "Password=prod-2"]);
  const alice2 = await sdkLogin(alice, "sdk s6 2");
  const fresh = await alice2.openVault(v.id);
  fresh.account = alice2;
  eq(fresh.read("ov://Rotating/Prod/Password"), "prod-2", "Alice's new device reads Bob's post-rotation edit");
  step(`rotated to key ${before + 1}; ov and a new SDK device both use it`);

  // the old handle on device 1 follows the rotation too
  await v.sync({ localChanged: false });
  eq(v.read("ov://Rotating/Prod/Password"), "prod-2", "old SDK handle after rotation");

  // revoke = remove + rotate: Bob loses it on ov and on the SDK
  await alice.sdk.revoke(v.id, [(await alice.sdk.auth.lookupUser(bob.email)).principal]);
  eq((await alice.sdk.listVaults())[0].currentKeyVersion, before + 2, "key version after revoke");
  eq(await ovJson(bob, ["vault", "list"]), [], "Bob's ov vault list after revoke");
  await ovFails(bob, ["read", "ov://Rotating/Prod/Password"], "Bob (ov) read after revoke");
  eq((await bob.sdk.listVaults()).length, 0, "Bob's SDK vault list after revoke");
  await rejects(bob.sdk.openVault(v.id), "Bob (SDK) open after revoke");
  step("revoke rotated again and removed Bob everywhere");

  // ov's field rotation (`ov rotate`) after the key rotation, read back on Alice's second SDK device. That
  // device was signed in before the revoke's rotation, so it lists the vaults first, as apps do on the
  // `vaultsChanged` event (without that: scenario 6b)
  await ovLogin(alice);
  await ovOk(alice, ["rotate", "ov://Rotating/Prod/Password", "--stdin"], { input: "prod-3\n" });
  await fresh.account.listVaults();
  await fresh.sync({ localChanged: false });
  eq(fresh.read("ov://Rotating/Prod/Password"), "prod-3", "SDK reads ov's rotated secret");
  step("ov rotate (secret value) on the rotated vault");
  return { ov: "ov has no vault-key rotation command: the SDK rotates, ov proves it still/no longer has access" };
});

// 6b: a device that is signed in and unlocked when another device rotates the key opens and syncs the vault
// without listing the vaults first. Fails on contract-v1.8: the core's keyring keeps the old key list until
// `vaults()` runs, so `open_vault` / `Vault::sync` give vault_key_mismatch (reported in W3-X).
await scenario("6b", ["sdk"], async (step) => {
  const u = await sdkUser("s6b");
  const v1 = await u.sdk.createVault("R");
  setFields(v1, [], "E", { Password: "1" }, true);
  await v1.sync();
  const d2 = await sdkLogin(u, "sdk s6b 2");
  const v2 = await d2.openVault(v1.id);
  await u.sdk.rotate(v1.id);
  await v1.write("ov://R/E/Password", "2");
  step("device 1 rotated and wrote with key 2");
  const errors = [];
  try {
    await v2.sync({ localChanged: false });
    eq(v2.read("ov://R/E/Password"), "2", "device 2's open handle after the rotation");
  } catch (e) {
    errors.push(`Vault::sync on the open handle: ${e.code ?? ""} ${e.message}`);
  }
  try {
    eq((await d2.openVault(v1.id)).read("ov://R/E/Password"), "2", "device 2 opening it again");
  } catch (e) {
    errors.push(`Account::open_vault: ${e.code ?? ""} ${e.message}`);
  }
  if (errors.length) throw new Check(`device 2 (signed in before the rotation): ${errors.join("; ")}`);
  step("device 2 followed the rotation");
});

// ---------------------------------------------------------------- 7. account deletion and restore

await scenario(7, ["sdk", "ov"], async (step) => {
  // deleted on ov, restored on the SDK
  const u = await sdkUser("s7a");
  const v = await u.sdk.createVault("Keep");
  setFields(v, [], "Thing", { Password: "t" }, true);
  await v.sync();
  await ovLogin(u);
  const shareUrl = (await ovOk(u, ["share", "ov://Keep/Thing", "--field", "Password", "--expires", "1h"])).stdout.trim();
  await ovFails(u, ["account", "delete", "--yes", "--email", "someone-else@example.com"], "ov delete with the wrong email", /isn't this account's email/);
  const del = await ovOk(u, ["account", "delete", "--yes", "--email", u.email]);
  expect(/is locked and will be deleted on/.test(del.stderr), `ov delete output: ${del.stderr}`);
  expect(/1 share link stop/.test(del.stderr), `ov delete preview counts the share link: ${del.stderr}`);
  step("ov scheduled the deletion");

  await rejects(sdk.openShare(u.sdk.config.api, shareUrl), "share link after deletion");
  // the SDK device that was signed in is signed out by the server
  await rejects(u.sdk.listVaults(), "the old SDK session after deletion");
  const d2 = await sdkLogin(u, "sdk s7a 2");
  expect(d2.deletionScheduledFor, "SDK login sees the scheduled deletion");
  await rejects(d2.listVaults(), "SDK vault list while pending", /account_pending_deletion/);
  await d2.restoreAccount({ password: u.password });
  eq(d2.deletionScheduledFor, null, "SDK restored");
  step("SDK saw it pending and restored it");

  await ovLogin(u);
  eq((await ovJson(u, ["vault", "list"])).map((x) => x.name), ["Keep"], "ov after the SDK restore");
  eq((await ovOk(u, ["read", "ov://Keep/Thing/Password"])).stdout, "t\n", "vault content survives");
  step("ov uses the restored account");

  // deleted on the SDK, restored on ov
  const w = await sdkUser("s7b");
  const wv = await w.sdk.createVault("Mine");
  setFields(wv, [], "X", { Password: "x" }, true);
  await wv.sync();
  const preview = await w.sdk.deletionPreview();
  eq([preview.scheduledFor, preview.vaults.map((x) => x.name), preview.blocked], [null, ["Mine"], false], "SDK deletion preview");
  await rejects(w.sdk.deleteAccount({ password: w.password, confirm: "nobody@example.com" }), "SDK delete with the wrong email");
  const { scheduledFor } = await w.sdk.deleteAccount({ password: w.password, confirm: w.email });
  expect(Date.parse(scheduledFor) > Date.now(), "scheduled in the future");
  step("SDK scheduled the deletion");
  await ovLogin(w);
  const pending = await ov(w, ["vault", "list"]);
  expect(pending.code !== 0, "ov vault list fails while pending");
  const already = await ovOk(w, ["account", "delete", "--yes", "--email", w.email]);
  expect(/already scheduled for deletion/.test(already.stderr), `ov sees it is scheduled: ${already.stderr}`);
  const restored = await ovOk(w, ["account", "restore"]);
  expect(/was restored/.test(restored.stderr), `ov restore: ${restored.stderr}`);
  eq((await ovJson(w, ["vault", "list"])).map((x) => x.name), ["Mine"], "ov after its restore");
  const w2 = await sdkLogin(w, "sdk s7b 2");
  eq(w2.deletionScheduledFor, null, "SDK sees ov's restore");
  eq((await w2.openVault(wv.id)).read("ov://Mine/X/Password"), "x", "SDK reads the vault after ov's restore");
  step("ov saw it pending and restored it; SDK confirmed");
});

// ---------------------------------------------------------------- report

rmSync(scratch, { recursive: true, force: true });
if (process.env.OV_E2E_OUT) writeFileSync(process.env.OV_E2E_OUT, JSON.stringify({ run: RUN, issuer: ISSUER, results }, null, 2));
const failed = results.filter((r) => r.status === "fail");
const blocking = failed.filter((r) => STRICT || !r.known);
console.log(`\n${results.filter((r) => r.status === "pass").length} pass, ${failed.length} fail (${failed.length - blocking.length} known), ${results.filter((r) => r.status === "n/a").length} n/a`);
process.exit(blocking.length ? 1 : 0);
