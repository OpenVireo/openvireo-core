// Type-checked by `npm run typecheck` (tsc --noEmit): the package's .d.ts must describe the API.
import { loadCore, OvError, type Account, type Core, type Host, type ImportPreview, type ImportSummary, type ImportTarget, type KdbxCredentials, type KdbxKdf, type KdbxMergeReport, type Keyset, type LocalImportMode, type LoginStep, type ServerConfig, type SharePayload, type Vault, type VaultInfo, type VaultKdbxSyncResult, type VaultVersion } from "../pkg/index.js";
import { loadCoreSync } from "../pkg/sync.js";
import { loadLite, type LiteCore, type ShareLinkParts } from "../pkg/lite.js";
import { loadLiteSync } from "../pkg/lite-sync.js";
import { consoleLog, fetchTransport, indexedDbCache, memoryStore, systemClock } from "../pkg/host/index.js";

export async function example(): Promise<void> {
  const core: Core = await loadCore();
  const version: string = core.version();
  const digest: Uint8Array = core.sha256(new Uint8Array([1]));
  const host: Host = { http: fetchTransport(), store: memoryStore(), cache: indexedDbCache(), clock: systemClock, log: consoleLog("warn") };
  const client = new core.OvClient({ device: { name: "web", platform: "web" }, offline: true }, host);
  const ac = new AbortController();
  const account: Account = await client.connect("https://accounts.example", ac.signal);
  const step: LoginStep = await account.login({ email: "a@b.c", password: new Uint8Array(), trustDevice: true });
  if (step.kind === "needsTotp") await account.submitTotp(step.challenge, "123456");
  const vaults: VaultInfo[] = await account.vaults();
  const vault = await account.openVault(vaults[0]!.id);
  vault.addEntry(vault.rootGroupId(), { fields: [{ name: "Title", value: new Uint8Array() }], removeFields: [], expiry: { kind: "keep" } });
  const report = await vault.sync({ localChanged: true });
  if (report.outcome === "uploaded") console.log(version, digest, report.clockSkewed);
  try {
    await account.createVault("x");
  } catch (e) {
    if (e instanceof OvError && e.code === "plan_limit") console.log(account.upgradeUrl(e));
  }
}

export async function lowLevel(): Promise<void> {
  const core: Core = loadCoreSync();
  const ks: Keyset = core.generateKeyset();
  const sealed: Uint8Array = core.sealVaultKey(ks.encPk, "v1", core.randomBytes(32));
  const key: Uint8Array = core.unsealVaultKey(ks.encSk, "v1", sealed);
  const auk: Uint8Array = core.deriveAuk("pw", core.newKdfParams(), core.generateSecretKey(), { allowWeak: false });
  const start = core.opaqueStartLogin("pw");
  const fin = core.opaqueFinishLogin(start.state, new Uint8Array(), core.opaqueIds("a@b.c", "https://accounts.example"));
  const db = core.Kdbx.read(new Uint8Array(), { vaultKey: key });
  const remote = db.clone();
  const merged: KdbxMergeReport = db.merge(remote);
  const out: Uint8Array = db.write();
  const m = core.kdbxMerge(out, out, undefined, { password: "pw" });
  console.log(auk, fin.authU, merged.conflicts, m.report.remoteChanged);

  const lite: LiteCore = await loadLite();
  const parts: ShareLinkParts = lite.parseShareLink("https://s.example/AAAAAAAAAAAAAAAAAAAAAA#key");
  const open = new lite.ShareOpen(parts.base, undefined, undefined);
  const payload: SharePayload = open.decrypt("ct");
  const same: LiteCore = loadLiteSync();
  console.log(payload.fields[0]?.value, same.totpCode(same.parseTotpUri("otpauth://totp/x?secret=AA"), Date.now()).code);
}

export async function contractV16(core: Core, client: InstanceType<Core["OvClient"]>): Promise<void> {
  const v = await client.createLocal("Home", { password: new Uint8Array() });
  const id: string = v.addEntryWithId("00".repeat(16), v.rootGroupId(), { fields: [], removeFields: [], expiry: { kind: "keep" }, customIcon: null, fieldOrder: ["A"], foregroundColor: "#000000" });
  const records = v.entryRecords(true);
  const used: number | undefined = records[0]?.lastAccessAt;
  const count: number | undefined = records[0]?.usageCount;
  const prot: boolean | undefined = records[0]?.attachments[0]?.protected;
  v.setAttachmentWith(id, "a", new Uint8Array(), undefined);
  const summary: ImportSummary = v.importFrom(v, { kind: "copies", parentGroupId: v.rootGroupId() });
  const preview: ImportPreview = v.importPreview();
  const targets: ImportTarget[] = v.importTargets();
  v.setName("x");
  v.setKdf({ kind: "argon2id", memory: 1 << 20, iterations: 2, parallelism: 1 });
  const kdf: KdbxKdf = { kind: "databaseDefault" };
  const copy: Vault = v.copyWithoutRemotes(undefined);
  copy.setMetaCustomData("k", undefined);
  const value: string | undefined = copy.metaCustomData("k");
  const out: Uint8Array = await v.exportKdbxWith({ password: new Uint8Array() }, undefined, kdf);
  const sh = core.SelfHosted.connect(client, "https://sync.example", new Uint8Array());
  const versions: VaultVersion[] = await sh.history("db");
  const old: Vault = await sh.openVersion("db", versions[0]!.revision, { password: new Uint8Array() });
  const sa = await core.ServiceAccount.fromToken(client, new Uint8Array());
  const issuer: string = sa.issuer();
  const config: ServerConfig = sa.serverConfig();
  const mode: LocalImportMode = { kind: "merge" };
  const account: Account = await client.connect("https://accounts.example");
  const fileCreds: KdbxCredentials = await account.vaultKdbxCredentials("v");
  const synced: VaultKdbxSyncResult = await account.syncVaultKdbx("v", out, undefined, { localChanged: true, acceptServerState: true });
  const jwt: Uint8Array = await account.accessToken(false);
  const b32: Uint8Array = core.base32Decode("JBSWY3DP");
  const lite: LiteCore = await loadLite();
  const b32lite: Uint8Array = lite.base32Decode("JBSWY3DP");
  console.log(b32, b32lite, fileCreds, synced.report.outcome, jwt, used, count, prot, summary, preview, targets, value, out, old, issuer, config, mode);
}
