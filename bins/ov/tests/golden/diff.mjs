// Golden diff: runs the TS `ov` (openvireo-sdk packages/cli) and the Rust `ov` binary on the same
// inputs against the same in-memory servers (W2-E, behind a loopback relay: `cargo run -p ov
// --example test_servers`), and diffs exit code, stdout and stderr case by case.
//
// Each CLI gets a fresh server with the TS tests' world (world.ts) and runs the whole case list in
// order, so writes, logins and deletions carry through. Values that are random on every run (entry
// UUIDs, ids, share links, timestamps, generated passwords) are normalised before comparing. Then a
// carry-over phase checks that a session saved by one CLI's `ov login` works in the other.
//
//   node bins/ov/tests/golden/diff.mjs [--ts-cli <path>/packages/cli/dist/index.js] [--out <dir>]
//                                      [--record | --rust-only]
//
// --record writes the TS transcript to tests/golden/ts-transcript.txt; --rust-only compares the Rust
// binary with that recorded transcript (no Node SDK needed). Exit 0 when everything matches.
import { spawn, spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../../../..");
const args = process.argv.slice(2);
const opt = (name, dflt) => (args.includes(name) ? args[args.indexOf(name) + 1] : dflt);
const tsCli = resolve(opt("--ts-cli", join(root, "../../openvireo-sdk/packages/cli/dist/index.js")));
const outDir = resolve(opt("--out", mkdtempSync(join(tmpdir(), "ov-golden-"))));
const record = args.includes("--record");
const rustOnly = args.includes("--rust-only");
const recorded = join(here, "ts-transcript.txt");
mkdirSync(outDir, { recursive: true });

// --------------------------------------------------------------------------------------- cases

/** A shell script standing in for cli.test.ts's Node script in `ov run`. */
const RUN_SCRIPT = `p="$DB_PASSWORD"
printf 'pw=%s\\n' "$p"
printf 'half=%s' "$(printf %s "$p" | cut -c1-4)"
sleep 0.02
printf '%s\\n' "$(printf %s "$p" | cut -c5-)"
echo "stderr $GH user=$DB_USER plain=$PLAIN" >&2
echo "token-in-env=\${OPENVIREO_SERVICE_ACCOUNT_TOKEN:-none} len=\${#p}"
exit 3`;

const R = { OPENVIREO_SERVICE_ACCOUNT_TOKEN: "{READ}" };
const W = { OPENVIREO_SERVICE_ACCOUNT_TOKEN: "{WRITE}" };
const U = { OPENVIREO_PASSWORD: "{PW}" };
const ISS = { OPENVIREO_ISSUER: "https://auth.test" };

/** [argv, env?, stdin?, extra?] — extra: { capture: {NAME: regex on stdout}, lengthOnly: true, files: {name: text} } */
const CASES = [
  // usage, help, versions (no server)
  [["--help"]],
  [[]],
  [["version"]],
  [["frobnicate"]],
  [["read"]],
  [["read", "a", "b"]],
  [["read", "--bogus", "x"]],
  [["item"]],
  [["item", "get"]],
  [["vault"]],
  [["rotate", "ov://v/e/f"]],
  [["share", "--once", "--max-opens", "2", "ov://v/e"]],
  [["share", "--max-opens", "x", "ov://v/e"]],
  [["share", "--expires", "3w", "ov://v/e"]],
  [["account"]],
  [["login", "extra"]],
  [["logout", "--nope"]],
  [["read", "ov://a/b/c"]],
  [["whoami"]],
  [["logout"]],
  [["account", "restore"]],
  // service accounts: reads
  [["read", "ov://Team%20Infra/GitHub/password"], R],
  [["read", "-n", "ov://{VAULT}/Deploy/Database/username"], R],
  [["read", "ov://Team%20Infra/Deploy/Database/notes"], R],
  [["read", "ov://Team%20Infra/GitHub"], R],
  [["read", "https://x/y/z"], R],
  [["read", "ov://Team%20Infra/Nope/password"], R],
  [["read", "ov://Team%20Infra/GitHub/nope"], R],
  [["read", "ov://Team%20Infra/Nowhere/GitHub/password"], R],
  [["read", "ov://Private/Bank/password"], R],
  [["read", "ov://Team%20Infra/GitHub/password"], { OPENVIREO_SERVICE_ACCOUNT_TOKEN: "ov_sa_garbage" }],
  [["read", "ov://Team%20Infra/GitHub/password"], { OPENVIREO_SERVICE_ACCOUNT_TOKEN: "not-a-token" }],
  [["item", "get", "ov://Team%20Infra/GitHub"], R],
  [["item", "get", "ov://Team%20Infra/GitHub", "--reveal"], R],
  [["item", "get", "ov://Team%20Infra/GitHub", "--json"], R],
  [["item", "get", "ov://Team%20Infra/Deploy/Database", "--json", "--reveal"], R],
  [["item", "get", "ov://Team%20Infra/GitHub", "x=y"], R],
  [["item", "list", "Team Infra"], R],
  [["item", "list", "Team Infra", "--json"], R],
  [["item", "list", "Nope"], R],
  [["inject"], R, "user: ov://Team%20Infra/Deploy/Database/username\ndsn: postgres://app:{{ ov://Team%20Infra/Deploy/Database/password }}@db/app\nplain\n"],
  [["inject", "-i", "{DIR}/missing.tpl"], R],
  [["vault", "list"], R],
  [["vault", "list", "--json"], R],
  [["whoami"], W],
  // service accounts: writes
  [["rotate", "ov://Team%20Infra/GitHub/password", "--generate"], R],
  [["item", "edit", "ov://Team%20Infra/GitHub", "username=x"], R],
  [["item", "create", "ov://Team%20Infra/New", "password=x"], R],
  [["item", "create", "ov://Team%20Infra/Apps/Stripe", "username=billing", "url=https://stripe.com", "api_key=sk_live_1", "--json"], W],
  [["item", "create", "ov://Team%20Infra/Apps/Stripe", "x=y"], W],
  [["item", "edit", "ov://Team%20Infra/Apps/Nope", "x=y"], W],
  [["item", "edit", "ov://Team%20Infra/Apps/Stripe"], W],
  [["item", "edit", "ov://Team%20Infra/Apps/Stripe", "noequals"], W],
  [["item", "edit", "ov://Team%20Infra/Apps/Stripe", "username=billing2", "--stdin-field", "api_key"], W, "sk_live_2\n"],
  [["item", "get", "ov://Team%20Infra/Apps/Stripe", "--reveal", "--json"], R],
  [["item", "get", "ov://Team%20Infra/Apps/Stripe"], R],
  [["item", "create", "ov://Team%20Infra/Gen", "--generate", "--length", "20", "--charset", "letters,digits"], W],
  [["item", "create", "ov://Team%20Infra/Gen2", "--generate", "--charset", "emoji"], W],
  [["item", "list", "Team Infra"], R],
  [["rotate", "ov://Team%20Infra/Deploy/Database/password", "--stdin"], W, "from-stdin\n"],
  [["read", "ov://Team%20Infra/Deploy/Database/password"], R],
  [["rotate", "ov://Team%20Infra/Deploy/Database/password", "--generate", "--print"], W, "", { lengthOnly: true }],
  [["rotate", "ov://Team%20Infra/Deploy/Database/password"], W],
  [["rotate", "ov://Team%20Infra/Deploy/Database/password", "--stdin"], W, ""],
  [["rotate", "ov://Team%20Infra/Deploy/Database/nofield", "--stdin"], W, "v"],
  [["rotate", "ov://Team%20Infra/GitHub/password", "--stdin", "--print"], W, "known-value\n"],
  // ov run
  [["run", "--env-file", "{DIR}/.env.tpl", "--", "/bin/sh", "-c", RUN_SCRIPT], { ...R, GH: "ov://Team%20Infra/GitHub/password" }, "", { files: { ".env.tpl": 'DB_PASSWORD="ov://Team%20Infra/Deploy/Database/password"\nDB_USER=ov://Team%20Infra/Deploy/Database/username\nPLAIN=hello\n' } }],
  [["run", "--", "/bin/sh", "-c", 'echo "ok $Y"'], { Y: "y" }],
  [["run", "--", "/nonexistent/cmd"]],
  [["run", "--env-file", "{DIR}/bad.env", "--", "true"], {}, "", { files: { "bad.env": "not an assignment\n" } }],
  [["run"], R],
  // a user
  [["login", "--email", "{EMAIL}"], { ...ISS, ...U }],
  [["login", "--email", "{EMAIL}", "--secret-key", "K1-WRONG"], { ...ISS, ...U }],
  [["login", "--email", "{EMAIL}", "--secret-key", "{SK}"], { ...ISS, OPENVIREO_PASSWORD: "wrong" }],
  [["login", "--email", "{EMAIL}", "--secret-key", "{SK}"], { ...ISS, ...U }],
  [["read", "ov://Team%20Infra/GitHub/username"], U],
  [["vault", "list"], U],
  [["vault", "list", "--json"], U],
  [["read", "ov://Private/Bank/password"], { OPENVIREO_PASSWORD: "wrong" }],
  [["read", "ov://a/b/c"]],
  [["rotate", "ov://Private/Bank/password", "--stdin"], U, "by-human"],
  [["read", "ov://Private/Bank/password"], U],
  [["item", "list", "Private"], U],
  [["whoami"]],
  [["vault", "list"], { ...R }],
  // share links
  [["share", "ov://Team%20Infra/GitHub", "--field", "UserName", "--field", "Password", "--once"], U],
  [["share", "--text", "--title", "Door", "--passcode", "--expires", "1h"], { ...U, OPENVIREO_SHARE_PASSCODE: "tiger lily" }, "4321\n"],
  [["share", "--text", "--passcode"], U, "x\n"],
  [["share", "--text"], U, ""],
  [["share", "ov://Team%20Infra/GitHub", "--max-opens", "3", "--expires", "2d"], U],
  [["share", "list"], U, "", { capture: { SHARE_ID: /^(\S+)\s/m } }],
  [["share", "list", "--json"], U],
  [["share", "revoke", "{SHARE_ID}"], U],
  [["share", "revoke"], U],
  [["share", "ov://Team%20Infra/GitHub", "--field", "Nope"], U],
  [["share", "ov://Team%20Infra/GitHub", "--expires", "soon"], U],
  [["share", "ov://Team%20Infra/GitHub"], R],
  [["share", "list"], R],
  // deletion
  [["account", "delete", "--yes"], U],
  [["account", "delete", "--yes", "--email", "bob@example.com"], U],
  [["account", "delete"], U],
  [["account", "delete", "--yes", "--email", "{EMAIL}"], U],
  [["vault", "list"], U],
  [["login", "--email", "{EMAIL}"], { ...ISS, ...U }],
  [["vault", "list"], U],
  [["account", "delete", "--yes", "--email", "{EMAIL}"], U],
  [["account", "restore"], U],
  [["vault", "list"], U],
  [["account", "restore"], U],
  [["logout"]],
  [["read", "ov://a/b/c"], U],
  [["logout", "--forget"]],
  [["login", "--email", "{EMAIL}"], { ...ISS, ...U }],
  [["logout", "--forget"]],
];

/**
 * Differences that are understood and not the CLI's doing, by case title. They are still printed.
 * kdbxweb (TS) reads an empty protected value (`<Value Protected="True"></Value>`) back as a plain
 * empty string, so a new entry's empty Password stops being protected after the upload; ov-kdbx
 * keeps the flag (as KeePassXC does). Only entries with an empty Password show it.
 */
const KNOWN = {
  "$ ov item get ov://Team%20Infra/Apps/Stripe --reveal --json   [OPENVIREO_SERVICE_ACCOUNT_TOKEN]": "kdbxweb drops the protected flag of an empty Password",
  "$ ov item get ov://Team%20Infra/Apps/Stripe   [OPENVIREO_SERVICE_ACCOUNT_TOKEN]": "kdbxweb drops the protected flag of an empty Password",
};

// ------------------------------------------------------------------------------------ running

function build() {
  const r = spawnSync("cargo", ["build", "-p", "ov", "--bin", "ov", "--example", "test_servers"], { cwd: root, stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
}

/** Starts the servers; resolves with their info line. */
function startServers() {
  const child = spawn(join(root, "target/debug/examples/test_servers"), [], { stdio: ["pipe", "pipe", "inherit"] });
  return new Promise((ok, fail) => {
    const rl = createInterface({ input: child.stdout });
    rl.once("line", (line) => ok({ child, info: JSON.parse(line) }));
    child.once("exit", (code) => fail(new Error(`test_servers exited with ${code}`)));
  });
}

function stop(s) {
  s.child.stdin.end();
  s.child.kill();
}

const BIN = join(root, "target/debug/ov");

function runCli(side, info, dir, argv, env, stdin) {
  const base = { PATH: process.env.PATH, HOME: dir, OPENVIREO_CONFIG_DIR: join(dir, "config"), OPENVIREO_TEST_RELAY: info.relay };
  const [cmd, cmdArgs, extra] = side === "ts" ? [process.execPath, [join(here, "ts-ov.mjs"), ...argv], { OV_TS_CLI: tsCli }] : [BIN, argv, {}];
  const r = spawnSync(cmd, cmdArgs, { env: { ...base, ...extra, ...env }, input: stdin ?? "", encoding: "utf8" });
  return { code: r.status ?? -1, stdout: r.stdout, stderr: r.stderr };
}

function substitute(text, vars) {
  return text.replace(/\{([A-Z_]+)\}/g, (m, k) => (k in vars ? vars[k] : m));
}

/** Values that differ on every run, so both transcripts can be compared. */
function normalise(text, info) {
  return text
    .replaceAll(info.readToken, "<read-token>")
    .replaceAll(info.writeToken, "<write-token>")
    .replaceAll(info.secretKey, "<secret-key>")
    .replace(/https:\/\/[^\s/]+\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}/g, "<share-url>")
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g, "<uuid>")
    .replace(/\b[0-9a-f]{32}\b/g, "<hex32>")
    .replace(/\b[A-Za-z0-9_-]{22}\b(?=\s|$|")/g, "<id22>")
    .replace(/\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z/g, "<time>")
    .replace(/\b\d{4}-\d\d-\d\d\b/g, "<date>");
}

function transcriptOf(side, info) {
  const dir = mkdtempSync(join(tmpdir(), `ov-golden-${side}-`));
  const vars = { READ: info.readToken, WRITE: info.writeToken, SK: info.secretKey, PW: info.password, EMAIL: info.email, VAULT: info.vaultId, DIR: dir };
  const out = [];
  for (const [argv, env = {}, stdin = "", extra = {}] of CASES) {
    for (const [name, text] of Object.entries(extra.files ?? {})) writeFileSync(join(dir, name), text);
    const a = argv.map((x) => substitute(x, vars));
    const e = Object.fromEntries(Object.entries(env).map(([k, v]) => [k, substitute(v, vars)]));
    const r = runCli(side, info, dir, a, e, stdin);
    for (const [name, re] of Object.entries(extra.capture ?? {})) vars[name] = re.exec(r.stdout)?.[1] ?? "";
    if (extra.lengthOnly) r.stdout = `<${r.stdout.trimEnd().length} characters>\n`;
    const show = (s) => normalise(s.replaceAll(dir, "<dir>"), info);
    out.push({
      title: show(`$ ov ${a.map((x) => (x.includes("\n") ? JSON.stringify(x.split("\n")[0] + "…") : x)).join(" ")}` + (Object.keys(e).length ? `   [${Object.keys(e).join(" ")}]` : "")),
      body: `exit ${r.code}\n--- stdout\n${show(r.stdout)}--- stderr\n${show(r.stderr)}`,
    });
  }
  rmSync(dir, { recursive: true, force: true });
  return out;
}

const render = (t) => t.map((c) => `${c.title}\n${c.body}`).join("\n");

/** Splits a rendered transcript back into cases. */
function parse(text) {
  const out = [];
  for (const block of text.split(/\n(?=\$ ov )/)) {
    const i = block.indexOf("\n");
    out.push({ title: block.slice(0, i), body: block.slice(i + 1).replace(/\n$/, "") + "\n" });
  }
  return out;
}

function compare(ts, rust) {
  let same = 0;
  const diffs = [];
  const known = [];
  for (let i = 0; i < Math.max(ts.length, rust.length); i++) {
    const a = ts[i], b = rust[i];
    if (a && b && a.body.trimEnd() === b.body.trimEnd()) same++;
    else {
      const title = a?.title ?? b?.title;
      const text = `#${i + 1} ${title}\n  TS:\n${indent(a?.body)}\n  Rust:\n${indent(b?.body)}`;
      if (a && b && a.title === b.title && KNOWN[title]) known.push(`${text}\n  known: ${KNOWN[title]}`);
      else diffs.push(text);
    }
  }
  return { same, total: Math.max(ts.length, rust.length), diffs, known };
}
const indent = (s = "<missing>") => s.trimEnd().split("\n").map((l) => "    " + l).join("\n");

// ------------------------------------------------------------------------------ carry-over

/** A session saved by one CLI's `ov login` is used by the other, on the same server. */
async function carryOver() {
  const s = await startServers();
  const { info } = s;
  const checks = [];
  try {
    for (const [first, second] of [["ts", "rust"], ["rust", "ts"]]) {
      const dir = mkdtempSync(join(tmpdir(), `ov-carry-${first}-`));
      const login = runCli(first, info, dir, ["login", "--email", info.email, "--secret-key", info.secretKey], { OPENVIREO_ISSUER: "https://auth.test", OPENVIREO_PASSWORD: info.password });
      const read = runCli(second, info, dir, ["read", "ov://Private/Bank/password"], { OPENVIREO_PASSWORD: info.password });
      const who = runCli(second, info, dir, ["whoami"], {});
      // The second CLI's refresh rotated the token: the first must still be signed in with it.
      const back = runCli(first, info, dir, ["read", "ov://Team%20Infra/GitHub/username"], { OPENVIREO_PASSWORD: info.password });
      const out = runCli(second, info, dir, ["logout"], {});
      const after = runCli(first, info, dir, ["logout"], {});
      const row = { first, second, login, read, who, back, out, after };
      row.ok =
        login.code === 0 && read.stdout === "nope\n" && who.stdout.startsWith("kind: user\n") && who.stdout.includes("email: alice@example.com\n") &&
        back.stdout === "ci\n" && out.stderr === "Signed out\n" && after.stderr === "Not signed in\n";
      checks.push(row);
      rmSync(dir, { recursive: true, force: true });
    }
  } finally {
    stop(s);
  }
  return checks;
}

// ------------------------------------------------------------------------------------- main

build();
let ts;
if (rustOnly) {
  ts = parse(readFileSync(recorded, "utf8"));
} else {
  const s = await startServers();
  try {
    ts = transcriptOf("ts", s.info);
  } finally {
    stop(s);
  }
  writeFileSync(join(outDir, "ts.txt"), render(ts) + "\n");
  if (record) writeFileSync(recorded, render(ts) + "\n");
}
const s = await startServers();
let rust;
try {
  rust = transcriptOf("rust", s.info);
} finally {
  stop(s);
}
writeFileSync(join(outDir, "rust.txt"), render(rust) + "\n");

const { same, total, diffs, known } = compare(ts, rust);
console.log(`golden diff: ${same}/${total} cases identical (exit code, stdout, stderr), ${known.length} known differences, ${diffs.length} unexplained${rustOnly ? " (vs the recorded TS transcript)" : ""}`);
console.log(`transcripts: ${rustOnly ? recorded : `${outDir}/ts.txt`}, ${outDir}/rust.txt`);
for (const d of known) console.log("\n" + d);
for (const d of diffs) console.log("\nUNEXPLAINED " + d);

let carryOk = true;
if (!rustOnly) {
  for (const c of await carryOver()) {
    carryOk &&= c.ok;
    console.log(`\ncarry-over: ${c.first} login -> ${c.second} read/whoami/logout: ${c.ok ? "ok" : "FAILED"}`);
    if (!c.ok) for (const k of ["login", "read", "who", "back", "out", "after"]) console.log(`  ${k}: ${JSON.stringify(c[k])}`);
  }
}
process.exit(diffs.length === 0 && carryOk ? 0 : 1);
