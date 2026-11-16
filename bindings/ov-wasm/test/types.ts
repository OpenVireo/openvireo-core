// Type-checked by `npm run typecheck` (tsc --noEmit): the package's .d.ts must describe the API.
import { loadCore, OvError, type Account, type Core, type Host, type LoginStep, type VaultInfo } from "../pkg/index.js";
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
