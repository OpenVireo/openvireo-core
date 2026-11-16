// The offline cache (SPEC §20) in IndexedDB. Everything the core caches is ciphertext or public,
// so it is stored as is. Two object stores, keyed by [userId, vaultId] and [userId, name].

const VERSION = 1;

const req = (r) =>
  new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });

const done = (tx) =>
  new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error("transaction aborted"));
  });

// Every key [userId, x] with x a string sorts between [userId] and [userId, []].
const userRange = (userId) => IDBKeyRange.bound([userId], [userId, []]);

/** @param {{ name?: string, indexedDB?: IDBFactory }} [opts] */
export function indexedDbCache(opts = {}) {
  const factory = opts.indexedDB ?? globalThis.indexedDB;
  const name = opts.name ?? "openvireo-core-cache";
  let dbp = null;

  const db = () =>
    (dbp ??= new Promise((resolve, reject) => {
      if (!factory) return reject(new Error("IndexedDB is not available"));
      const open = factory.open(name, VERSION);
      open.onupgradeneeded = () => {
        const d = open.result;
        if (!d.objectStoreNames.contains("vaults")) d.createObjectStore("vaults");
        if (!d.objectStoreNames.contains("meta")) d.createObjectStore("meta");
      };
      open.onsuccess = () => resolve(open.result);
      open.onerror = () => reject(open.error);
    }).catch((e) => {
      dbp = null;
      throw e;
    }));

  async function run(stores, mode, fn) {
    const tx = (await db()).transaction(stores, mode);
    const result = fn(tx);
    await done(tx);
    return result === undefined ? undefined : await result;
  }

  const toVault = (v) => (v ? { state: v.state, base: v.base ?? undefined, pending: v.pending ?? undefined, autofill: v.autofill ?? undefined } : undefined);

  return {
    async load(userId, vaultId) {
      return toVault(await run("vaults", "readonly", (tx) => req(tx.objectStore("vaults").get([userId, vaultId]))));
    },
    async save(userId, vaultId, v) {
      const record = { state: v.state, base: v.base ?? null, pending: v.pending ?? null, autofill: v.autofill ?? null };
      await run("vaults", "readwrite", (tx) => void tx.objectStore("vaults").put(record, [userId, vaultId]));
    },
    async remove(userId, vaultId) {
      await run("vaults", "readwrite", (tx) => void tx.objectStore("vaults").delete([userId, vaultId]));
    },
    async list(userId) {
      const keys = await run("vaults", "readonly", (tx) => req(tx.objectStore("vaults").getAllKeys(userRange(userId))));
      return keys.map((k) => k[1]);
    },
    async loadMeta(userId, metaName) {
      return (await run("meta", "readonly", (tx) => req(tx.objectStore("meta").get([userId, metaName])))) ?? undefined;
    },
    async saveMeta(userId, metaName, value) {
      await run("meta", "readwrite", (tx) => void tx.objectStore("meta").put(value, [userId, metaName]));
    },
    async clearUser(userId) {
      await run(["vaults", "meta"], "readwrite", (tx) => {
        tx.objectStore("vaults").delete(userRange(userId));
        tx.objectStore("meta").delete(userRange(userId));
      });
    },
    close() {
      dbp?.then((d) => d.close()).catch(() => {});
      dbp = null;
    },
  };
}
