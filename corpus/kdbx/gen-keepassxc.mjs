// Writes the KeePassXC corpus files (corpus/kdbx/keepassxc/) with the desktop CLI
// (openvireo-cli, KeePassXC 2.8.0-snapshot renamed; any keepassxc-cli 2.7+ works the same):
//
//   keepassxc-features.kdbx  `import` of features.xml (built below): attachments (one shared by two
//                            entries), history, a custom icon on a group and an entry, entry and
//                            group tags, a recycle bin holding an entry and a group, custom data on
//                            Meta/group/entry, auto-type with associations, an expiring entry,
//                            colours, override URL, protected custom fields, DeletedObjects,
//                            QualityCheck=False. KeePassXC saves it as KDBX 4.1 (it has 4.1 fields).
//   keepassxc-cli-keyfile.kdbx  built with plain CLI commands (db-create with password + key file,
//                            mkdir, add, edit to make history, attachment-import, rm to the recycle
//                            bin). Password plus keys/keepassxc-cli-keyfile.key (64 hex chars).
//   keepassxc-5k.kdbx        `import` of 5,000 entries in 50 groups (not committed: see SOURCE.md;
//                            written only with --5k).
//
// Password for all three: "corpus pw ✓". Every value in the XML is fixed, so reruns produce the same
// content (the files still differ byte for byte: KDBX salts and IVs are random per save).
//
//   node corpus/kdbx/gen-keepassxc.mjs [--5k] [--out <dir>]
//
// The CLI is $OV_KEEPASSXC_CLI, else $HOME/kpnx/openvireo/build/src/cli/openvireo-cli, else
// keepassxc-cli on PATH.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const PASSWORD = "corpus pw ✓";
const here = dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const with5k = args.includes("--5k");
const outIdx = args.indexOf("--out");
const outDir = outIdx >= 0 ? args[outIdx + 1] : join(here, "keepassxc");

function findCli() {
  if (process.env.OV_KEEPASSXC_CLI) return process.env.OV_KEEPASSXC_CLI;
  const local = join(process.env.HOME ?? "", "kpnx/openvireo/build/src/cli/openvireo-cli");
  return existsSync(local) ? local : "keepassxc-cli";
}
const cli = findCli();
const run = (argv, input = "") => execFileSync(cli, argv, { input, stdio: ["pipe", "pipe", "pipe"] }).toString();

// ---- deterministic values ----------------------------------------------------------------------
const uuid = (label) => createHash("sha256").update(`corpus:${label}`).digest().subarray(0, 16).toString("base64");
const T0 = Date.UTC(2026, 10, 15, 12, 0, 0); // 2026-11-15T12:00:00Z
const iso = (offsetSec = 0) => new Date(T0 + offsetSec * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const el = (name, body, attrs = "") => `<${name}${attrs}>${body}</${name}>`;
const b64 = (s) => Buffer.from(s).toString("base64");
// A 1x1 transparent PNG.
const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";

const times = (t = 0, { expires = false, expiry = 0, usage = 0 } = {}) =>
  el(
    "Times",
    el("CreationTime", iso(t)) +
      el("LastModificationTime", iso(t)) +
      el("LastAccessTime", iso(t)) +
      el("ExpiryTime", iso(expires ? expiry : t)) +
      el("Expires", expires ? "True" : "False") +
      el("UsageCount", usage) +
      el("LocationChanged", iso(t)),
  );
const customData = (items) =>
  el(
    "CustomData",
    items.map(([k, v, t]) => el("Item", el("Key", esc(k)) + el("Value", esc(v)) + (t === undefined ? "" : el("LastModificationTime", iso(t))))).join(""),
  );
const str = (key, value, prot = false) =>
  el("String", el("Key", esc(key)) + el("Value", esc(value), prot ? ' ProtectInMemory="True"' : ""));

function entry(label, o = {}) {
  const fields = o.fields ?? {};
  const body =
    el("UUID", uuid(label)) +
    el("IconID", o.icon ?? 0) +
    (o.customIcon ? el("CustomIconUUID", uuid(o.customIcon)) : "") +
    el("ForegroundColor", o.fg ?? "") +
    el("BackgroundColor", o.bg ?? "") +
    el("OverrideURL", esc(o.overrideUrl ?? "")) +
    (o.qualityCheck === false ? el("QualityCheck", "False") : "") +
    el("Tags", esc((o.tags ?? []).join(";"))) +
    (o.previousParent ? el("PreviousParentGroup", uuid(o.previousParent)) : "") +
    times(o.t ?? 0, o.times) +
    str("Title", o.title ?? label) +
    str("UserName", fields.UserName ?? "") +
    str("Password", fields.Password ?? "", true) +
    str("URL", fields.URL ?? "") +
    str("Notes", fields.Notes ?? "") +
    Object.entries(o.custom ?? {})
      .map(([k, [v, p]]) => str(k, v, p))
      .join("") +
    (o.binaries ?? []).map(([name, ref]) => el("Binary", el("Key", esc(name)) + `<Value Ref="${ref}"/>`)).join("") +
    el(
      "AutoType",
      el("Enabled", o.autoTypeEnabled === false ? "False" : "True") +
        el("DataTransferObfuscation", o.obfuscation ?? 0) +
        (o.sequence ? el("DefaultSequence", esc(o.sequence)) : "") +
        (o.associations ?? []).map(([w, k]) => el("Association", el("Window", esc(w)) + el("KeystrokeSequence", esc(k)))).join(""),
    ) +
    (o.customData ? customData(o.customData) : "") +
    (o.history ? el("History", o.history.join("")) : "");
  return el("Entry", body);
}

function group(label, o = {}) {
  const body =
    el("UUID", uuid(label)) +
    el("Name", esc(o.name ?? label)) +
    el("Notes", esc(o.notes ?? "")) +
    el("IconID", o.icon ?? 48) +
    (o.customIcon ? el("CustomIconUUID", uuid(o.customIcon)) : "") +
    times(o.t ?? 0) +
    el("IsExpanded", o.expanded === false ? "False" : "True") +
    el("DefaultAutoTypeSequence", esc(o.sequence ?? "")) +
    el("EnableAutoType", o.autoType ?? "null") +
    el("EnableSearching", o.searching ?? "null") +
    el("LastTopVisibleEntry", "AAAAAAAAAAAAAAAAAAAAAA==") +
    (o.tags ? el("Tags", esc(o.tags.join(";"))) : "") +
    (o.previousParent ? el("PreviousParentGroup", uuid(o.previousParent)) : "") +
    (o.customData ? customData(o.customData) : "") +
    (o.entries ?? []).join("") +
    (o.groups ?? []).join("");
  return el("Group", body);
}

function file({ name, description, root, recycleBin = null, binaries = [], icons = [], metaCustomData = [], deleted = [] }) {
  const meta =
    el("Generator", "OpenVireo corpus") +
    el("DatabaseName", esc(name)) +
    el("DatabaseNameChanged", iso()) +
    el("DatabaseDescription", esc(description)) +
    el("DatabaseDescriptionChanged", iso()) +
    el("DefaultUserName", "corpus") +
    el("DefaultUserNameChanged", iso()) +
    el("MaintenanceHistoryDays", 365) +
    el("Color", "#336699") +
    el("MasterKeyChanged", iso()) +
    el("MasterKeyChangeRec", -1) +
    el("MasterKeyChangeForce", -1) +
    el(
      "MemoryProtection",
      el("ProtectTitle", "False") +
        el("ProtectUserName", "False") +
        el("ProtectPassword", "True") +
        el("ProtectURL", "False") +
        el("ProtectNotes", "False"),
    ) +
    (icons.length
      ? el(
          "CustomIcons",
          icons.map(([label, iconName]) => el("Icon", el("UUID", uuid(label)) + el("Data", PNG) + el("Name", esc(iconName)) + el("LastModificationTime", iso()))).join(""),
        )
      : "") +
    el("RecycleBinEnabled", "True") +
    el("RecycleBinUUID", recycleBin ? uuid(recycleBin) : "AAAAAAAAAAAAAAAAAAAAAA==") +
    el("RecycleBinChanged", iso()) +
    el("EntryTemplatesGroup", "AAAAAAAAAAAAAAAAAAAAAA==") +
    el("EntryTemplatesGroupChanged", iso()) +
    el("HistoryMaxItems", 10) +
    el("HistoryMaxSize", 6291456) +
    el("LastSelectedGroup", "AAAAAAAAAAAAAAAAAAAAAA==") +
    el("LastTopVisibleGroup", "AAAAAAAAAAAAAAAAAAAAAA==") +
    (binaries.length ? el("Binaries", binaries.map((data, i) => `<Binary ID="${i}" Compressed="False">${b64(data)}</Binary>`).join("")) : "") +
    customData(metaCustomData);
  const del = el("DeletedObjects", deleted.map(([label, t]) => el("DeletedObject", el("UUID", uuid(label)) + el("DeletionTime", iso(t)))).join(""));
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n${el("KeePassFile", el("Meta", meta) + el("Root", root + del))}\n`;
}

// ---- keepassxc-features ------------------------------------------------------------------------
function featuresXml() {
  const server = (pw, t, extra = {}) =>
    entry("server", {
      title: "Server",
      t,
      fields: { UserName: "root", Password: pw, URL: "ssh://server.example", Notes: "line one\nline two" },
      custom: { "Zeta custom": ["z", false], "Alpha custom": ["a", false], PIN: ["4321", true] },
      tags: ["infra", "prod"],
      fg: "#FF0000",
      bg: "#00FF00",
      overrideUrl: "cmd://ssh {URL}",
      customIcon: "icon-dot",
      sequence: "{USERNAME}{TAB}{PASSWORD}{ENTER}",
      associations: [
        ["Terminal*", "{PASSWORD}{ENTER}"],
        ["*SSH*", ""],
      ],
      binaries: [["note.txt", 0]],
      customData: [["entry-cd", "e1", 60]],
      ...extra,
    });
  const serverEntry = server("third pw ✓", 120, {
    history: [server("first pw", 0, { binaries: [] }), server("second pw", 60)],
  });
  const shared = entry("shared-attachment", {
    title: "Shares note.txt",
    fields: { UserName: "bob", Password: "pw" },
    binaries: [
      ["same-note.txt", 0],
      ["image.bin", 1],
    ],
    qualityCheck: false,
  });
  const expiring = entry("expiring", {
    title: "Expires 2027",
    fields: { Password: "old" },
    times: { expires: true, expiry: 365 * 86400, usage: 3 },
    autoTypeEnabled: false,
    obfuscation: 1,
  });
  const binned = entry("binned-entry", { title: "Binned entry", fields: { Password: "gone soon" }, previousParent: "work" });
  const root = group("root", {
    name: "Root",
    notes: "root notes",
    entries: [entry("bank", { title: "Bank", fields: { UserName: "alice", Password: "bank pw", URL: "https://bank.example" } })],
    groups: [
      group("work", {
        name: "Work",
        customIcon: "icon-dot",
        tags: ["office"],
        sequence: "{USERNAME}{TAB}{PASSWORD}",
        autoType: "True",
        searching: "False",
        customData: [["group-cd", "g1", 0]],
        entries: [serverEntry, shared, expiring],
        groups: [group("work-sub", { name: "Nested ✓", expanded: false })],
      }),
      group("recycle-bin", {
        name: "Recycle Bin",
        icon: 43,
        autoType: "False",
        searching: "False",
        entries: [binned],
        groups: [group("binned-group", { name: "Binned group", previousParent: "root" })],
      }),
    ],
  });
  return file({
    name: "keepassxc features",
    description: "written by KeePassXC from corpus/kdbx/gen-keepassxc.mjs",
    root,
    recycleBin: "recycle-bin",
    binaries: ["attached from KeePassXC", "\u0000\u0001\u0002 binary-ish"],
    icons: [["icon-dot", "dot"]],
    metaCustomData: [
      ["KPXC_SYNC_GENERATION", "7", 0],
      ["corpus-meta", "m1", 0],
    ],
    deleted: [["deleted-for-good", 30]],
  });
}

// ---- keepassxc-5k ------------------------------------------------------------------------------
function fiveKXml() {
  const groups = [];
  for (let g = 0; g < 50; g++) {
    const entries = [];
    for (let e = 0; e < 100; e++) {
      const n = g * 100 + e;
      entries.push(
        entry(`5k-${n}`, {
          title: `Entry ${n}`,
          t: n,
          fields: { UserName: `user${n}`, Password: `pw-${n}-${uuid(`pw${n}`).slice(0, 12)}`, URL: `https://site${n}.example`, Notes: n % 10 === 0 ? `notes for ${n}` : "" },
          tags: n % 7 === 0 ? ["seven"] : [],
        }),
      );
    }
    groups.push(group(`5k-group-${g}`, { name: `Group ${g}`, entries }));
  }
  return file({ name: "keepassxc 5k", description: "5,000 entries in 50 groups", root: group("5k-root", { name: "Root", groups }) });
}

// ---- driver ------------------------------------------------------------------------------------
mkdirSync(outDir, { recursive: true });
const tmp = mkdtempSync(join(tmpdir(), "ov-corpus-"));
const pwTwice = `${PASSWORD}\n${PASSWORD}\n`;
try {
  const importXml = (xml, out) => {
    const x = join(tmp, "in.xml");
    writeFileSync(x, xml);
    rmSync(out, { force: true });
    run(["import", "-q", "-p", "-t", "100", x, out], pwTwice);
    console.log(`wrote ${out}`);
  };
  importXml(featuresXml(), join(outDir, "keepassxc-features.kdbx"));

  // Plain CLI commands, as a user would.
  const db = join(outDir, "keepassxc-cli-keyfile.kdbx");
  const key = join(here, "keys", "keepassxc-cli-keyfile.key");
  writeFileSync(key, createHash("sha256").update("corpus key file").digest("hex"));
  rmSync(db, { force: true });
  run(["db-create", "-q", "-p", "-t", "100", "--set-key-file", key, db], pwTwice);
  const k = ["-q", "-k", key];
  run(["mkdir", ...k, db, "Work"], `${PASSWORD}\n`);
  run(["add", ...k, "-u", "alice", "--url", "https://bank.example", "--notes", "first notes", "-p", db, "Bank"], `${PASSWORD}\nbank pw 1\n`);
  run(["edit", ...k, "-p", db, "Bank"], `${PASSWORD}\nbank pw 2 ✓\n`); // makes a history item
  run(["add", ...k, "-u", "root", "--url", "ssh://server.example", "-p", db, "Work/Server"], `${PASSWORD}\nserver pw\n`);
  const att = join(tmp, "note.txt");
  writeFileSync(att, "attached with the CLI\n");
  run(["attachment-import", ...k, db, "Work/Server", "note.txt", att], `${PASSWORD}\n`);
  run(["add", ...k, "-u", "temp", db, "Temporary"], `${PASSWORD}\n`);
  run(["rm", ...k, db, "Temporary"], `${PASSWORD}\n`); // moves it to the recycle bin
  console.log(`wrote ${db}`);

  if (with5k) importXml(fiveKXml(), join(outDir, "keepassxc-5k.kdbx"));
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
