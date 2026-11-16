// Writes the kdbxweb corpus files (corpus/kdbx/kdbxweb/). The first three were made for the W1-K1
// spike (ADR 0002); W1-K3 moved them here and added the last two.
//   kdbxweb-vault.kdbx    an account vault as the SDK writes it (createVaultKdbx: KDBX 4, Argon2id
//                         m=1MiB t=2 p=1, the 32-byte vault key as the only key component)
//   kdbxweb-unknown.kdbx  the same content, password "spike pw", with unknown elements injected
//                         into KeePassFile, Meta, Root, Group, Entry and AutoType before encryption
//   kdbxweb-unknown-leaf.kdbx  the same, but unknown elements only in Meta, Entry and AutoType
//                         (keepass-rs rejects an unknown child of <Group>, so this isolates the rest)
//   kdbxweb-41-icons.kdbx the same content as KDBX 4.1, AES-256 + AES-KDF, password "spike pw", with
//                         a named custom icon on a group and an entry and tags on a group
//   kdbxweb-kdbx31.kdbx   the same content as KDBX 3.1 (Salsa20 inner stream), password "spike pw"
//
//   node corpus/kdbx/gen-kdbxweb.mjs [path/to/openvireo-sdk]
//
// The SDK defaults to $OV_SDK, else $HOME/kpnx/openvireo-sdk; it must be built (dist/).
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sdkRoot = process.argv[2] ?? process.env.OV_SDK ?? join(process.env.HOME ?? "", "kpnx/openvireo-sdk");
const sdk = await import(pathToFileURL(join(sdkRoot, "packages/sdk/dist/index.js")).href);
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
  writeFileSync(join(here, "kdbxweb/kdbxweb-vault.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb unknown");
  db.setKdf(kdbxweb.Consts.KdfId.Argon2id);
  await fill(db);
  inject(db);
  writeFileSync(join(here, "kdbxweb/kdbxweb-unknown.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb unknown leaf");
  db.setKdf(kdbxweb.Consts.KdfId.Argon2id);
  await fill(db);
  inject(db, false);
  writeFileSync(join(here, "kdbxweb/kdbxweb-unknown-leaf.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb 4.1 icons");
  db.header.versionMinor = 1;
  db.header.dataCipherUuid = new kdbxweb.KdbxUuid(kdbxweb.Consts.CipherId.Aes);
  db.setKdf(kdbxweb.Consts.KdfId.Aes);
  await fill(db);
  const iconId = new kdbxweb.KdbxUuid(Buffer.alloc(16, 7));
  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
    "base64",
  );
  db.meta.customIcons.set(iconId.id, { data: png, name: "dot", lastModified: new Date(Date.UTC(2026, 10, 15)) });
  const work = db.getDefaultGroup().groups.find((g) => g.name === "Work");
  work.customIcon = iconId;
  work.tags = ["office", "team"];
  work.entries[0].customIcon = iconId;
  writeFileSync(join(here, "kdbxweb/kdbxweb-41-icons.kdbx"), await saveKdbx(db));
}
{
  const db = kdbxweb.Kdbx.create(passwordCredentials("spike pw")(), "kdbxweb 3.1");
  db.setVersion(3);
  await fill(db);
  writeFileSync(join(here, "kdbxweb/kdbxweb-kdbx31.kdbx"), await saveKdbx(db));
}
console.log("wrote kdbxweb/{kdbxweb-vault,kdbxweb-unknown,kdbxweb-unknown-leaf,kdbxweb-41-icons,kdbxweb-kdbx31}.kdbx");
