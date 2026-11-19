// @vitest-environment node
// contract-v1.6 on the full module (docs/adr/0001-contract.md § contract-v1.6).
import { describe, expect, it } from "vitest";
import { loadCore } from "../pkg/index.js";
import { consoleLog, memoryCache, memoryStore } from "../pkg/host/index.js";
import { bytes } from "./helpers.js";

const config = { device: { name: "vitest", platform: "web" }, offline: false };
const pw = (p) => ({ password: bytes(p) });
const text = (name, value) => ({ name, value: bytes(value) });
const input = (extra = {}) => ({ fields: [], removeFields: [], expiry: { kind: "keep" }, ...extra });

function host(send = async () => ({ status: 500, headers: [], body: new Uint8Array() })) {
  return {
    http: { send, openStream: async () => ({ status: 500, nextChunk: async () => null, close() {} }) },
    store: memoryStore(),
    cache: memoryCache(),
    clock: { nowUnixMs: () => 1_700_000_000_000 },
    log: consoleLog("error"),
  };
}

describe("contract-v1.6", () => {
  it("adds entries with chosen ids, colours, icons, field order and attachment flags", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host());
    const v = await client.createLocal("Home", pw("pw"));
    const icon = v.addCustomIcon(new Uint8Array([0x89, 0x50, 0x4e, 0x47]));
    const id = v.addEntryWithId("0123456789ABCDEF0123456789ABCDEF", v.rootGroupId(), input({
      fields: [text("Title", "Mail"), text("B", "b"), text("A", "a")],
      foregroundColor: "#112233",
      customIcon: icon,
      fieldOrder: ["A", "B"],
    }));
    expect(id).toBe("0123456789abcdef0123456789abcdef");
    expect(() => v.addEntryWithId(id, v.rootGroupId(), input())).toThrow(expect.objectContaining({ code: "conflict" }));
    let e = v.entry(id);
    expect(e.modifiedAt).toBe(1_700_000_000); // the Host clock
    expect([e.foregroundColor, e.customIcon]).toEqual(["#112233", icon]);
    expect(e.fields.slice(-2).map((f) => f.name)).toEqual(["A", "B"]);
    expect(e.usageCount).toBe(0);
    expect(e.lastAccessAt).toBeUndefined();
    v.editEntry(id, input({ customIcon: null }));
    expect(v.entry(id).customIcon).toBeUndefined();
    v.editEntry(id, input({ backgroundColor: "#abcdef" })); // customIcon absent: unchanged
    expect(() => v.editEntry(id, input({ foregroundColor: "red" }))).toThrow(expect.objectContaining({ code: "invalid_request" }));

    v.setAttachmentWith(id, "plain.txt", bytes("hi"), false);
    v.setAttachment(id, "secret.bin", bytes("s"));
    v.setAttachmentWith(id, "plain.txt", bytes("hi!"), undefined);
    e = v.entry(id);
    expect(e.attachments.map((a) => [a.name, a.protected])).toEqual([["secret.bin", true], ["plain.txt", false]]);
    expect(v.entryRecords(false).map((r) => r.id)).toEqual(v.entries(false).map((s) => s.id));
    // A record without the v1.6 fields is still accepted (they default).
    const { usageCount: _u, lastAccessAt: _l, ...old } = e;
    old.attachments = old.attachments.map(({ protected: _p, ...a }) => a);
    expect(v.applyAutofillEdits({ vaultId: v.id(), entries: [{ entry: old, groupPath: "" }], version: "1" })).toBe(false);
  });

  it("imports between open vaults, sets metadata and KDFs, and copies without remotes", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host());
    const source = await client.createLocal("Work", pw("pw"));
    source.addEntry(source.ensureGroup("Servers"), input({ fields: [text("Title", "db")] }));
    expect(source.importPreview()).toEqual({ entries: 1, groups: 1 });

    const target = await client.createLocal("Home", pw("pw"));
    const into = target.ensureGroup("Imported");
    expect(target.importTargets().map((t) => t.path)).toEqual(["Home", "Home / Imported"]);
    const copies = target.importFrom(source, { kind: "copies", parentGroupId: into });
    expect([copies.added, copies.groupsAdded]).toEqual([1, 2]);
    expect(target.importFrom(source, { kind: "merge" }).added).toBe(1);
    expect(() => target.importFrom(source, { kind: "nope" })).toThrow(/kind/);

    target.setName("Family");
    expect(target.name()).toBe("Family");
    target.setMetaCustomData("KPXC_REMOTE_SYNC_SETTINGS", '[{"type":"syncServer","url":"https://s"}]');
    expect(target.metaCustomData("KPXC_REMOTE_SYNC_SETTINGS")).toContain("syncServer");
    const copy = target.copyWithoutRemotes(undefined);
    expect(copy.metaCustomData("KPXC_REMOTE_SYNC_SETTINGS")).toBeUndefined();
    copy.setKdf({ kind: "argon2id", memory: 1 << 20, iterations: 3, parallelism: 1 });
    const reopened = await client.openLocal(await copy.saveLocal(), pw("pw"));
    expect(reopened.name()).toBe("Family");
    expect(() => copy.setKdf({ kind: "aesKdf", rounds: 0 })).toThrow(expect.objectContaining({ code: "invalid_request" }));
    target.setMetaCustomData("KPXC_REMOTE_SYNC_SETTINGS", undefined);
    expect(target.metaCustomData("KPXC_REMOTE_SYNC_SETTINGS")).toBeUndefined();

    const exported = await target.exportKdbxWith(pw("ex"), undefined, { kind: "aesKdf", rounds: 100 });
    expect((await client.openLocal(exported, pw("ex"))).entries(false)).toHaveLength(2);
  });

  it("lists and opens self-hosted versions", async () => {
    const core = await loadCore();
    const plain = new core.OvClient(config, host());
    const old = await plain.createLocal("Home", pw("pw"));
    old.addEntry(old.rootGroupId(), input({ fields: [text("Title", "Wifi")] }));
    const rev1 = await old.saveLocal();
    const versions = { versions: [
      { id: "home", etag: '"r2"', revision: 2, size: 10, updatedAt: "2026-11-19T10:00:00Z" },
      { id: "home", etag: '"r1"', revision: 1, size: 9, updatedAt: "2026-11-18T10:00:00Z" },
    ] };
    const send = async (req) => {
      if (req.url.endsWith("/databases/home/history")) return { status: 200, headers: [["content-type", "application/json"]], body: bytes(JSON.stringify(versions)) };
      if (req.url.endsWith("/databases/home/history/1")) return { status: 200, headers: [["etag", '"r1"']], body: rev1 };
      return { status: 404, headers: [], body: bytes('{"error":"not_found"}') };
    };
    const client = new core.OvClient(config, host(send));
    const sh = core.SelfHosted.connect(client, "https://sync.test", bytes("dev"));
    const history = await sh.history("home");
    expect(history.map((h) => [h.revision, h.isCurrent])).toEqual([[2, true], [1, false]]);
    const v1 = await sh.openVersion("home", 1, pw("pw"));
    expect(v1.isReadOnly()).toBe(true);
    expect(v1.entries(false).map((e) => e.title)).toEqual(["Wifi"]);
    expect(v1.etag()).toBe('"r1"');
  });
});
