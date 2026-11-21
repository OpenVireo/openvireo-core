#!/usr/bin/env node
// Prints the scenario × client matrix from a run.sh output folder: cross-client.json (ov + SDK, written by
// cross-client.mjs) and the iOS / desktop *.status files. `--check` prints nothing and exits 1 when a cell
// failed (known failures aside, unless OV_E2E_STRICT=1).
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const args = process.argv.slice(2);
const check = args[0] === "--check";
const dir = check ? args[1] : args[0];
if (!dir) {
  console.error("usage: matrix.mjs [--check] <run.sh output folder>");
  process.exit(2);
}
const strict = process.env.OV_E2E_STRICT === "1";

const SCENARIOS = [
  ["1", "register on one client, log in on the others"],
  ["2", "create / edit / delete, concurrent conflicts"],
  ["3", "recycle bin, restore to the previous group"],
  ["4", "share a vault to a second user"],
  ["5", "share link made on one client, opened on another"],
  ["6", "key rotation"],
  ["6b", "rotation seen by a device signed in before it"],
  ["7", "account deletion + restore"],
];
const CLIENTS = ["ov", "sdk", "ios", "desktop"];

// What the iOS and desktop suites cover. They run against the same stack but register their own accounts,
// so they are same-client checks (two iOS devices, two desktop devices), not cross-client ones.
const IOS_ONLY = "iOS↔iOS on the stack; the suites register their own accounts and have no hook to sign in to one made by ov/SDK";
const IOS = {
  1: [["EndToEndTests", "AccountEndToEndTests", "AccountStoreTests", "AccountFlowUITests"], `${IOS_ONLY}`],
  2: [["AccountEndToEndTests", "AccountStoreTests"], `${IOS_ONLY}; two-device edits/deletes/version restore, sequential (no concurrent same-field case against the stack)`],
  3: null, // no Recycle Bin e2e against the stack (PreviousParentGroup restore is covered by unit tests on fakes)
  4: [["AccountEndToEndTests", "OrgEndToEndTests"], `${IOS_ONLY}; share to a second user + org confirm/share`],
  5: null,
  6: [["AccountEndToEndTests", "OrgEndToEndTests"], `${IOS_ONLY}; remove = rotate (key version +1, old key opens nothing new)`],
  "6b": null,
  7: null,
};
const IOS_NA = {
  3: "n/a (no iOS Recycle Bin test against the stack; restore-to-previous-group is unit-tested on fakes)",
  5: "n/a (no iOS share-link test against the stack)",
  "6b": "n/a (needs a second long-running session; no iOS test against the stack)",
  7: "n/a (no iOS account-deletion test against the stack)",
};
const DESK_NA = "n/a (desktop account flows are only tested against in-memory fakes; its live-server mode is self-hosted sync only, so this needs a live-account test mode: new client code)";
const DESKTOP = {
  2: [["testremotesyncserver", "testguiautosync"], "self-hosted sync mode on this stack's sync server (testSyncEngineTwoDevices, testCombinesChangesToDifferentFields, background sync + server events); not account vaults"],
};

const cells = new Map(); // "scenario|client" -> { status, note, known }
const put = (s, c, v) => cells.set(`${s}|${c}`, v);

const json = join(dir, "cross-client.json");
if (existsSync(json)) {
  for (const r of JSON.parse(readFileSync(json, "utf8")).results) put(String(r.scenario), r.client, r);
}
const status = (prefix, name) => {
  const f = join(dir, `${prefix}-${name}.status`);
  return existsSync(f) ? readFileSync(f, "utf8").trim() : null;
};
const iosRan = status("ios", "OpenVireoCoreTests.EndToEndTests") !== null;
for (const [s] of SCENARIOS) {
  const m = IOS[s];
  if (!iosRan) put(s, "ios", { status: "not run", note: "set OV_E2E_IOS_DIR" });
  else if (!m) put(s, "ios", { status: "n/a", note: IOS_NA[s].replace(/^n\/a \(|\)$/g, "") });
  else {
    const results = m[0].map((b) => [b, status("ios", `OpenVireoCoreTests.${b}`) ?? status("ios", `OpenVireoKitTests.${b}`) ?? status("ios", `OpenVireoUITests.${b}`)]);
    const failed = results.filter(([, r]) => r !== "pass").map(([b]) => b);
    put(s, "ios", failed.length ? { status: "fail", note: `failed or not run: ${failed.join(", ")}` } : { status: "pass", note: `${m[1]} (${m[0].join(", ")})` });
  }
  const d = DESKTOP[s];
  const deskRan = status("desktop", "testremotesyncserver") !== null;
  const existing = cells.get(`${s}|desktop`);
  if (existing) continue; // scenario 3's KDBX interop check from cross-client.mjs
  if (!deskRan) put(s, "desktop", { status: "not run", note: "set OV_E2E_DESKTOP_BUILD" });
  else if (!d) put(s, "desktop", { status: "n/a", note: DESK_NA.replace(/^n\/a \(|\)$/g, "") });
  else {
    const failed = d[0].filter((t) => status("desktop", t) !== "pass");
    put(s, "desktop", failed.length ? { status: "fail", note: `failed: ${failed.join(", ")}` } : { status: "pass", note: d[1] });
  }
}

const blocking = [...cells.values()].filter((c) => c.status === "fail" && (strict || !c.known));
if (check) process.exit(blocking.length ? 1 : 0);

const label = (c) => (c ? (c.status === "fail" && c.known ? "FAIL (known)" : c.status === "fail" ? "FAIL" : c.status) : "-");
const w = [4, 50, 13, 13, 13, 13];
const row = (cols) => cols.map((c, i) => String(c).padEnd(w[i])).join(" ").trimEnd();
console.log(row(["#", "scenario", ...CLIENTS]));
console.log(row(w.map((n) => "-".repeat(n))));
for (const [s, name] of SCENARIOS) console.log(row([s, name, ...CLIENTS.map((c) => label(cells.get(`${s}|${c}`)))]));
console.log("\nNotes:");
for (const [s] of SCENARIOS) {
  for (const c of CLIENTS) {
    const v = cells.get(`${s}|${c}`);
    if (v?.note) console.log(`  ${s} ${c}: ${v.note}`);
  }
}
console.log(`\n${blocking.length ? `${blocking.length} failing cell(s)` : "no failing cells"}${[...cells.values()].some((c) => c.known && c.status === "fail") ? " (known failures listed above)" : ""}`);
