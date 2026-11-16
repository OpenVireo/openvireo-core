// Opens a .kdbx with kdbxweb (through the SDK, which wires up Argon2) and prints one JSON line:
//   {"version":"4.0","generator":"…","groups":3,"entries":2,"history":1,"binaries":1,"unknown":["ZzUnknownMeta",…]}
// `entries` counts live entries (not history items), `history` counts history items, and `unknown`
// lists every element in the raw decrypted XML whose name starts with "Zz" (the corpus's injected
// unknown elements), in document order. Exit code 1 and a message on stderr when it can't open.
//
//   node corpus/kdbx/kdbxweb-open.mjs <file.kdbx> [--password <pw>] [--key-file <path>]
//
// The SDK is found at $OV_SDK, else $HOME/kpnx/openvireo-sdk. It must be built
// (packages/sdk/dist/index.js); it bundles kdbxweb 2.1.1.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const file = args.shift();
let password = null;
let keyFile = null;
while (args.length) {
  const flag = args.shift();
  if (flag === "--password") password = args.shift();
  else if (flag === "--key-file") keyFile = args.shift();
  else {
    console.error(`unknown argument: ${flag}`);
    process.exit(2);
  }
}
if (!file) {
  console.error("usage: kdbxweb-open.mjs <file.kdbx> [--password <pw>] [--key-file <path>]");
  process.exit(2);
}

const sdkRoot = process.env.OV_SDK ?? join(process.env.HOME ?? "", "kpnx/openvireo-sdk");
const sdk = await import(pathToFileURL(join(sdkRoot, "packages/sdk/dist/index.js")).href);
const { kdbxweb, initKdbx } = sdk;
initKdbx();

try {
  const data = readFileSync(file);
  const credentials = new kdbxweb.Credentials(
    password === null ? null : kdbxweb.ProtectedValue.fromString(password),
    keyFile === null ? null : readFileSync(keyFile),
  );
  const buf = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
  const db = await kdbxweb.Kdbx.load(buf, credentials, { preserveXml: true });

  let groups = 0;
  let entries = 0;
  let history = 0;
  const walk = (group) => {
    groups++;
    for (const e of group.entries) {
      entries++;
      history += e.history.length;
    }
    for (const g of group.groups) walk(g);
  };
  for (const g of db.groups) walk(g);

  const unknown = [];
  const visit = (node) => {
    if (node.nodeType === 1 && node.tagName.startsWith("Zz")) unknown.push(node.tagName);
    for (let c = node.firstChild; c; c = c.nextSibling) visit(c);
  };
  if (db.xml) visit(db.xml.documentElement);

  console.log(
    JSON.stringify({
      version: `${db.versionMajor}.${db.versionMinor}`,
      generator: db.meta.generator ?? "",
      groups,
      entries,
      history,
      binaries: db.binaries.getAll().length,
      unknown,
    }),
  );
} catch (e) {
  console.error(`kdbxweb could not open ${file}: ${e?.code ?? ""} ${e?.message ?? e}`);
  process.exit(1);
}
