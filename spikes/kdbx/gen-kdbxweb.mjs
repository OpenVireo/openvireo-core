// Writes the kdbxweb test files for the W1-K1 spike (spikes/kdbx/files/):
//   kdbxweb-vault.kdbx    an account vault as the SDK writes it (createVaultKdbx: KDBX 4, Argon2id
//                         m=1MiB t=2 p=1, the 32-byte vault key as the only key component)
//   kdbxweb-unknown.kdbx  the same content, password "spike pw", with unknown elements injected
//                         into KeePassFile, Meta, Root, Group, Entry and AutoType before encryption
//   kdbxweb-unknown-leaf.kdbx  the same, but unknown elements only in Meta, Entry and AutoType
//                         (keepass-rs rejects an unknown child of <Group>, so this isolates the rest)
//
//   node spikes/kdbx/gen-kdbxweb.mjs [path/to/openvireo-sdk]
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sdkRoot = process.argv[2] ?? join(here, "../../../../openvireo-sdk");
const sdk = await import(join(sdkRoot, "packages/sdk/dist/index.js"));
const { kdbxweb, createVaultKdbx, saveKdbx, setSyncGeneration, passwordCredentials, initKdbx } = sdk;

const vectors = JSON.parse(readFileSync(join(here, "../../vectors/test-vectors.json"), "utf8"));
const vaultKey = Uint8Array.from(Buffer.from(vectors.vault_kdbx.vault_key_hex, "hex"));

function fill(db) {
  const root = db.getDefaultGroup();
  const work = db.createGroup(root, "Work");
  work.customData = new Map([["group-cd", { value: "g1" }]]);
  const e = db.createEntry(work);
  e.fields.set("Title", "Server");
  e.fields.set("UserName", "root");
  e.fields.set("Password", kdbxweb.ProtectedValue.fromString("first pw"));
  e.fields.set("URL", "ssh://server.example");
  e.fields.set("Zeta custom", "z");
  e.fields.set("Alpha custom", "a");
  e.fields.set("PIN", kdbxweb.ProtectedValue.fromString("4321"));
  e.tags = ["infra", "prod"];
  e.fgColor = "#FF0000";
  e.bgColor = "#00FF00";
  e.overrideUrl = "cmd://ssh {URL}";
  e.autoType.defaultSequence = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
  e.autoType.items.push({ window: "Terminal*", keystrokeSequence: "{PASSWORD}{ENTER}" });
  e.customData = new Map([["entry-cd", { value: "e1" }]]);
  e.times.update();
  e.pushHistory();
  e.fields.set("Password", kdbxweb.ProtectedValue.fromString("second pw ✓"));
  e.times.update();
  const att = db.binaries.add(new TextEncoder().encode("attached from kdbxweb"));
  return Promise.resolve(att).then((ref) => {
    e.binaries.set("note.txt", ref);
    const gone = db.createEntry(root);
    gone.fields.set("Title", "Deleted one");
    db.remove(gone); // to the recycle bin
    db.move(gone, null); // deleted for good: a DeletedObjects tombstone
    db.meta.customData.set("KPXC_SYNC_GENERATION", { value: "7" });
    db.meta.desc = "written by kdbxweb 2.1.1";
  });
}

function inject(db, groupLevel = true) {
  const orig = db.buildXml.bind(db);
  db.buildXml = (ctx) => {
    orig(ctx);
    const doc = db.xml;
    const el = (parent, name, text, attrs = {}) => {
      const n = doc.createElement(name);
      for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
      if (text) n.appendChild(doc.createTextNode(text));
      parent.appendChild(n);
      return n;
    };
    const kf = doc.documentElement;
    if (groupLevel) el(kf, "ZzUnknownFile", "file-level");
    const meta = kf.getElementsByTagName("Meta")[0];
    const m = el(meta, "ZzUnknownMeta", "meta-text", { a: "1" });
    el(m, "Child", "nested");
    const rootEl = kf.getElementsByTagName("Root")[0];
    if (groupLevel) el(rootEl, "ZzUnknownRoot", "root-level");
    const group = rootEl.getElementsByTagName("Group")[0];
    if (groupLevel) el(group, "ZzUnknownGroup", "group-text");
    for (const entry of Array.from(group.getElementsByTagName("Entry"))) {
      if (entry.parentNode.tagName === "History") continue;
      el(entry, "ZzUnknownEntry", "entry-text", { b: "2" });
      const at = entry.getElementsByTagName("AutoType")[0];
      if (at) el(at, "ZzUnknownAutoType", "autotype-text");
    }
  };
}

initKdbx();
{
  const db = createVaultKdbx("kdbxweb vault", vaultKey);
  await fill(db);
  writeFileSync(join(here, "files/kdbxweb-vault.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb unknown");
  db.setKdf(kdbxweb.Consts.KdfId.Argon2id);
  await fill(db);
  inject(db);
  writeFileSync(join(here, "files/kdbxweb-unknown.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb unknown leaf");
  db.setKdf(kdbxweb.Consts.KdfId.Argon2id);
  await fill(db);
  inject(db, false);
  writeFileSync(join(here, "files/kdbxweb-unknown-leaf.kdbx"), await saveKdbx(db));
}
console.log("wrote files/kdbxweb-vault.kdbx, kdbxweb-unknown.kdbx, kdbxweb-unknown-leaf.kdbx");
