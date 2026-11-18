// The TS `ov` (packages/cli) for the golden diff: its `main` with a `fetch` that sends every request
// to the loopback relay of `cargo run -p ov --example test_servers`, the real URL in
// `x-ov-relay-url` (as the Rust binary does in debug builds). bin.ts has no fetch option, so this
// replaces it. No terminal: `prompt` is unset, as when stdin isn't a TTY.
//
//   OV_TS_CLI=<openvireo-sdk>/packages/cli/dist/index.js OPENVIREO_TEST_RELAY=http://127.0.0.1:<port> node ts-ov.mjs <args>
import { pathToFileURL } from "node:url";

const { main } = await import(pathToFileURL(process.env.OV_TS_CLI).href);
const relay = process.env.OPENVIREO_TEST_RELAY;
const env = { ...process.env };
delete env.OV_TS_CLI;

const fetch = (url, init = {}) => {
  const u = new URL(url);
  const headers = new Headers(init.headers);
  headers.set("x-ov-relay-url", String(url));
  return globalThis.fetch(relay + u.pathname + u.search, { ...init, headers });
};

async function readStdin() {
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

const code = await main(process.argv.slice(2), { env, stdout: process.stdout, stderr: process.stderr, stdin: readStdin, fetch });
process.exitCode = code;
