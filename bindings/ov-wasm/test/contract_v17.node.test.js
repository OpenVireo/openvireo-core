// @vitest-environment node
// contract-v1.7 on the full module (docs/adr/0001-contract.md § contract-v1.7): local files opened
// with the password hash, SelfHosted.syncDatabaseWith, vault_key_mismatch for a wrong local-file key.
import { describe, expect, it } from "vitest";
import { loadCore } from "../pkg/index.js";
import { consoleLog, memoryCache, memoryStore } from "../pkg/host/index.js";
import { bytes } from "./helpers.js";

const config = { device: { name: "vitest", platform: "web" }, offline: false };
const pw = (p) => ({ password: bytes(p) });
const text = (name, value) => ({ name, value: bytes(value) });
const input = (extra = {}) => ({ fields: [], removeFields: [], expiry: { kind: "keep" }, ...extra });

/** A self-hosted sync server holding `databases/home` in memory (conditional GET/HEAD/PUT). */
function databaseServer() {
  const s = { versions: [], methods: [] };
  const header = (req, name) => req.headers.find(([k]) => k.toLowerCase() === name)?.[1];
  const etagOf = (n) => `"v${n}"`;
  const headers = (v) => [["etag", etagOf(v.revision)], ["x-database-revision", String(v.revision)]];
  s.send = async (req) => {
    if (!req.url.includes("/databases/home")) return { status: 404, headers: [], body: bytes('{"error":"not_found"}') };
    s.methods.push(req.method);
    const cur = s.versions.at(-1);
    if (req.method === "GET" || req.method === "HEAD") {
      if (!cur) return { status: 404, headers: [], body: bytes('{"error":"not_found"}') };
      if (header(req, "if-none-match") === etagOf(cur.revision)) return { status: 304, headers: headers(cur), body: new Uint8Array() };
      return { status: 200, headers: headers(cur), body: req.method === "GET" ? cur.data : new Uint8Array() };
    }
    if (req.method === "PUT") {
      const ifMatch = header(req, "if-match");
      if ((header(req, "if-none-match") === "*" && cur) || (ifMatch && (!cur || ifMatch !== etagOf(cur.revision)))) {
        return { status: 412, headers: [], body: bytes('{"error":"changed","code":"precondition_failed"}') };
      }
      const v = { data: req.body.slice(), revision: (cur?.revision ?? 0) + 1 };
      s.versions.push(v);
      return { status: cur ? 200 : 201, headers: headers(v), body: new Uint8Array() };
    }
    return { status: 405, headers: [], body: new Uint8Array() };
  };
  return s;
}

function host(send) {
  return {
    http: { send, openStream: async () => ({ status: 500, nextChunk: async () => null, close() {} }) },
    store: memoryStore(),
    cache: memoryCache(),
    clock: { nowUnixMs: () => 1_700_000_000_000 },
    log: consoleLog("error"),
  };
}

describe("contract-v1.7", () => {
  it("opens and saves a local file with the password hash", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host(async () => ({ status: 500, headers: [], body: new Uint8Array() })));
    const v = await client.createLocal("Home", pw("pw ✓"));
    v.addEntry(v.rootGroupId(), input({ fields: [text("Title", "Mail")] }));
    const file = await v.saveLocal();
    const passwordHash = core.kdbxPasswordHash("pw ✓");
    for (const opened of [await core.Vault.openLocal(file, { passwordHash }), await client.openLocal(file, { passwordHash })]) {
      const back = await core.Vault.openLocal(await opened.saveLocal(), pw("pw ✓"));
      expect(back.entries(false).map((e) => e.title)).toEqual(["Mail"]);
    }
    await expect(core.Vault.openLocal(file, { passwordHash: core.kdbxPasswordHash("no") })).rejects.toMatchObject({ code: "vault_key_mismatch" });
    await expect(core.Vault.openLocal(file, pw("no"))).rejects.toMatchObject({ code: "vault_key_mismatch" });
    await expect(core.Vault.openLocal(file, { password: bytes("pw ✓"), passwordHash })).rejects.toMatchObject({ code: "invalid_request" });
    await expect(core.Vault.openLocal(file, { passwordHash: new Uint8Array(31) })).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("syncDatabaseWith checks with a HEAD when nothing changed locally", async () => {
    const core = await loadCore();
    const server = databaseServer();
    const client = new core.OvClient(config, host(server.send));
    const sh = core.SelfHosted.connect(client, "https://sync.test", bytes("dev"));
    const v = await client.createLocal("Home", pw("pw"));
    v.addEntry(v.rootGroupId(), input({ fields: [text("Title", "Wifi")] }));
    const first = await sh.syncDatabase("home", await v.saveLocal(), pw("pw"));
    expect(first.report.outcome).toBe("created");

    const passwordHash = core.kdbxPasswordHash("pw");
    const check = { localChanged: false, acceptServerState: false };
    let n = server.methods.length;
    const same = await sh.syncDatabaseWith("home", first.kdbx, { passwordHash }, check);
    expect([same.report.outcome, same.report.attempts]).toEqual(["unchanged", 0]);
    expect(same.kdbx).toEqual(first.kdbx);
    expect(server.methods.slice(n)).toEqual(["HEAD"]);

    // Another device uploads: the HEAD sees it, one download
    const other = await client.openLocal(first.kdbx, pw("pw"));
    other.addEntry(other.rootGroupId(), input({ fields: [text("Title", "Bank")] }));
    server.versions.push({ data: await other.saveLocal(), revision: server.versions.length + 1 });
    n = server.methods.length;
    const pulled = await sh.syncDatabaseWith("home", first.kdbx, { passwordHash }, check);
    expect(pulled.report.outcome).toBe("pulled");
    expect(server.methods.slice(n)).toEqual(["HEAD", "GET"]);
    const merged = await client.openLocal(pulled.kdbx, pw("pw"));
    expect(merged.entries(false).map((e) => e.title).sort()).toEqual(["Bank", "Wifi"]);
  });
});
