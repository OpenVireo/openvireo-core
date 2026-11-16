// In-memory Host pieces, for tests and short-lived processes.

const copy = (b) => (b == null ? b : new Uint8Array(b));

/** An in-memory secure store for tests. Values are copied in and out, and wiped on delete/overwrite. */
export function memoryStore() {
  const m = new Map();
  const wipe = (k) => m.get(k)?.fill(0);
  return {
    async get(key) {
      return m.has(key) ? copy(m.get(key)) : undefined;
    },
    async set(key, value) {
      wipe(key);
      m.set(key, copy(value));
    },
    async delete(key) {
      wipe(key);
      m.delete(key);
    },
    get size() {
      return m.size;
    },
  };
}

const copyVault = (v) => ({ state: copy(v.state), base: copy(v.base), pending: copy(v.pending), autofill: copy(v.autofill) });

/** An in-memory offline cache. */
export function memoryCache() {
  const vaults = new Map(); // userId -> Map(vaultId -> CachedVault)
  const meta = new Map(); // userId -> Map(name -> Uint8Array)
  const of = (m, user) => {
    if (!m.has(user)) m.set(user, new Map());
    return m.get(user);
  };
  return {
    async load(userId, vaultId) {
      const v = vaults.get(userId)?.get(vaultId);
      return v ? copyVault(v) : undefined;
    },
    async save(userId, vaultId, v) {
      of(vaults, userId).set(vaultId, copyVault(v));
    },
    async remove(userId, vaultId) {
      vaults.get(userId)?.delete(vaultId);
    },
    async list(userId) {
      return [...(vaults.get(userId)?.keys() ?? [])];
    },
    async loadMeta(userId, name) {
      return copy(meta.get(userId)?.get(name));
    },
    async saveMeta(userId, name, value) {
      of(meta, userId).set(name, copy(value));
    },
    async clearUser(userId) {
      vaults.delete(userId);
      meta.delete(userId);
    },
  };
}
