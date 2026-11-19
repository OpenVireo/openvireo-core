// @vitest-environment node
// The package bundles: esbuild follows every loader import (literal paths), the bundle runs in Node
// on its own (no node_modules next to it), and a lite-only bundle stays small.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { afterAll, expect, it } from "vitest";

const pkg = fileURLToPath(new URL("../pkg/", import.meta.url));
const dir = mkdtempSync(join(tmpdir(), "ov-wasm-bundle-"));
mkdirSync(join(dir, "node_modules", "@openvireo"), { recursive: true });
symlinkSync(pkg, join(dir, "node_modules", "@openvireo", "core-wasm"), "dir");
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const ENTRY = `
import { loadCore, OvError } from "@openvireo/core-wasm";
import { loadCoreSync } from "@openvireo/core-wasm/sync";
import { loadLite } from "@openvireo/core-wasm/lite";
import { loadLiteSync } from "@openvireo/core-wasm/lite-sync";
const hex = (b) => Buffer.from(b).toString("hex");
const sync = loadCoreSync();
const core = await loadCore();
const lite = await loadLite();
let code;
try { lite.parseShareLink("nope"); } catch (e) { code = e instanceof OvError && e.code; }
console.log(JSON.stringify({
  sameInstance: core === sync && lite === loadLiteSync(),
  sha: hex(lite.sha256(new TextEncoder().encode("abc"))),
  x25519: hex(core.x25519PublicKey(new Uint8Array(32).fill(1))).length,
  kdbx: typeof core.Kdbx.read,
  code,
}));
`;

const LITE_ENTRY = `
import { loadLiteSync } from "@openvireo/core-wasm/lite-sync";
const lite = loadLiteSync();
console.log(Buffer.from(lite.sha256(new TextEncoder().encode("abc"))).toString("hex"));
`;

it("bundles every entry with esbuild and runs the bundle alone in Node", async () => {
  writeFileSync(join(dir, "entry.mjs"), ENTRY);
  const outfile = join(dir, "out", "bundle.mjs");
  const r = await build({ entryPoints: [join(dir, "entry.mjs")], bundle: true, format: "esm", platform: "node", outfile, logLevel: "silent", metafile: true });
  // Both glue modules and both embedded .wasm copies are in the bundle.
  const inputs = Object.keys(r.metafile.inputs).join("\n");
  for (const f of ["gen/ov_wasm.js", "gen/wasm-base64.js", "gen/lite/ov_wasm_lite.js", "gen/lite/wasm-base64.js"]) expect(inputs).toContain(f);
  // Only `fresh: true` keeps a computed import().
  const src = readFileSync(outfile, "utf8");
  expect(src.match(/import\((?!["'])/g)?.length ?? 0).toBeLessThanOrEqual(1);
  const out = JSON.parse(execFileSync(process.execPath, [outfile], { cwd: join(dir, "out"), encoding: "utf8" }));
  expect(out).toEqual({ sameInstance: true, sha: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", x25519: 64, kdbx: "function", code: "invalid_link" });
}, 60_000);

it("a lite-only browser bundle carries only the lite module", async () => {
  writeFileSync(join(dir, "lite-entry.mjs"), LITE_ENTRY);
  const outfile = join(dir, "out", "lite.mjs");
  const r = await build({ entryPoints: [join(dir, "lite-entry.mjs")], bundle: true, format: "esm", platform: "browser", minify: true, outfile, logLevel: "silent", metafile: true, define: { Buffer: "undefined" }, external: [] });
  const inputs = Object.keys(r.metafile.inputs).join("\n");
  expect(inputs).not.toContain("gen/ov_wasm.js");
  const bytes = readFileSync(outfile);
  console.log(`lite-only browser bundle: ${bytes.length} bytes, ${gzipSync(bytes, { level: 9 }).length} gzip -9`);
  expect(gzipSync(bytes, { level: 9 }).length).toBeLessThan(300_000);
}, 60_000);
