// @vitest-environment node
// contract-v1.8 on the full module (docs/adr/0001-contract.md § contract-v1.8): Recycle Bin restore
// to the previous group through a saved file, restoreEntry on a binned entry, the web app's plain
// export, SelfHosted.download and health (not_sync_server), and the new calls on Account and
// ServiceAccount.
import { describe, expect, it } from "vitest";
import { loadCore } from "../pkg/index.js";
import { consoleLog, memoryCache, memoryStore } from "../pkg/host/index.js";
import { bytes } from "./helpers.js";

const config = { device: { name: "vitest", platform: "web" }, offline: false };
const pw = (p) => ({ password: bytes(p) });
const text = (name, value) => ({ name, value: bytes(value) });
const input = (fields) => ({ fields: fields.map(([n, v]) => text(n, v)), removeFields: [], expiry: { kind: "keep" } });
const utf8 = (b) => new TextDecoder().decode(b);

function host(send) {
  return {
    http: { send, openStream: async () => ({ status: 500, nextChunk: async () => null, close() {} }) },
    store: memoryStore(),
    cache: memoryCache(),
    clock: { nowUnixMs: () => 1_700_000_000_000 },
    log: consoleLog("error"),
  };
}

const answer = (status, contentType, body) => async () => ({ status, headers: [["content-type", contentType]], body: bytes(body) });

describe("contract-v1.8", () => {
  it("restores from the Recycle Bin to the previous group after a save (KDBX 4.1)", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host(answer(500, "text/plain", "")));
    const v = await client.createLocal("Home", pw("pw"));
    const work = v.addGroup(undefined, "Work");
    const id = v.addEntry(work, input([["Title", "VPN"]]));
    v.deleteEntry(id);
    const back = await core.Vault.openLocal(await v.saveLocal(), pw("pw"));
    back.restoreFromRecycleBin(id);
    expect(back.entry(id).groupPath).toEqual(["Work"]);
  });

  it("restores a version of a binned entry keeping its history", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host(answer(500, "text/plain", "")));
    const v = await client.createLocal("Home", pw("pw"));
    const work = v.addGroup(undefined, "Work");
    const id = v.addEntry(work, input([["Title", "VPN"], ["Password", "v1"]]));
    const version = v.copyWithoutRemotes(undefined);
    v.editEntry(id, input([["Password", "v2"]]));
    v.deleteEntry(id);
    v.restoreEntry(version, id, "Elsewhere");
    const rec = v.entry(id);
    expect([v.isInRecycleBin(id), rec.groupPath, rec.historyCount]).toEqual([false, ["Work"], 2]);
    expect(utf8(rec.fields.find((f) => f.name === "Password").value)).toBe("v1");
  });

  it("exports plain text exactly as the web app", async () => {
    const core = await loadCore();
    const client = new core.OvClient(config, host(answer(500, "text/plain", "")));
    const v = await client.createLocal("Home", pw("pw"));
    const work = v.addGroup(undefined, "Work");
    v.addEntry(work, input([["Title", "VPN"], ["UserName", "ops"], ["Password", 'p"w']]));
    const rows = [{ folder: "Work", title: "VPN", username: "ops", passwordValue: 'p"w', url: "", notes: "" }];
    expect(utf8(v.exportPlain("json", undefined))).toBe(JSON.stringify(rows, null, 2));
    expect(utf8(v.exportPlain("csv", undefined))).toBe('Folder,Title,Username,Password,URL,Notes\n"Work","VPN","ops","p""w","",""');
  });

  it("downloads a database without its key, and says when an address isn't a sync server", async () => {
    const core = await loadCore();
    const empty = core.SelfHosted.connect(new core.OvClient(config, host(answer(404, "application/json", '{"error":"not_found"}'))), "https://sync.test", bytes("dev"));
    expect(await empty.download("home")).toBeUndefined();
    const file = new Uint8Array([1, 2, 3]);
    const full = core.SelfHosted.connect(
      new core.OvClient(config, host(async () => ({ status: 200, headers: [["etag", '"v1"']], body: file }))),
      "https://sync.test",
      bytes("dev"),
    );
    expect(await full.download("home")).toEqual(file);

    const page = core.SelfHosted.connect(new core.OvClient(config, host(answer(404, "text/html", "<html>no</html>"))), "https://example.com", bytes("dev"));
    await expect(page.health()).rejects.toMatchObject({ code: "not_sync_server", status: 404 });
    const ok = core.SelfHosted.connect(new core.OvClient(config, host(answer(200, "application/json", '{"status":"ok"}'))), "https://sync.test", bytes("dev"));
    expect(JSON.parse(await ok.health())).toEqual({ status: "ok" });
  });

  it("has the new Account and ServiceAccount calls", async () => {
    const core = await loadCore();
    expect(typeof core.Account.prototype.shareVaultWithKeys).toBe("function");
    expect(typeof core.ServiceAccount.prototype.vaultKdbxCredentials).toBe("function");
    expect(typeof core.ServiceAccount.prototype.syncVaultKdbx).toBe("function");
  });
});
