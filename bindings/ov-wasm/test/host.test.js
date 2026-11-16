// @vitest-environment node
import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { fetchTransport, indexedDbCache, memoryCache, memoryStore } from "../pkg/host/index.js";

const req = { method: "GET", url: "https://api.example/x", headers: [["authorization", "Bearer t"]], keepalive: false };

describe("fetchTransport", () => {
  it("sends without redirects or cookies and returns any status as a response", async () => {
    let seen;
    const t = fetchTransport({
      fetch: async (url, init) => {
        seen = { url, init };
        return new Response("nope", { status: 404, headers: { "x-a": "1" } });
      },
    });
    const res = await t.send({ ...req, method: "POST", body: new Uint8Array([1, 2]) });
    expect(seen.url).toBe(req.url);
    expect(seen.init).toMatchObject({ method: "POST", redirect: "error", credentials: "omit", cache: "no-store", keepalive: false });
    expect(seen.init.headers).toEqual([["authorization", "Bearer t"]]);
    expect(res.status).toBe(404);
    expect(res.headers).toContainEqual(["x-a", "1"]);
    expect(new TextDecoder().decode(res.body)).toBe("nope");
  });

  it("maps failures to TransportFailure kinds", async () => {
    const offline = fetchTransport({ fetch: async () => { throw new TypeError("fetch failed"); } });
    await expect(offline.send(req)).rejects.toMatchObject({ kind: "offline" });
    const slow = fetchTransport({ timeoutMs: 10, fetch: (_u, init) => new Promise((_r, rej) => init.signal.addEventListener("abort", () => rej(new DOMException("x", "AbortError")))) });
    await expect(slow.send(req)).rejects.toMatchObject({ kind: "timeout" });
  });

  it("streams a body chunk by chunk", async () => {
    const t = fetchTransport({ fetch: async () => new Response(new Blob(["data: 1\n\n"]).stream(), { status: 200 }) });
    const s = await t.openStream(req);
    expect(s.status).toBe(200);
    const chunk = await s.nextChunk();
    expect(new TextDecoder().decode(chunk)).toBe("data: 1\n\n");
    expect(await s.nextChunk()).toBeNull();
    s.close();
  });
});

describe("memoryStore", () => {
  it("copies values and wipes on delete", async () => {
    const s = memoryStore();
    const v = new Uint8Array([1, 2, 3]);
    await s.set("k", v);
    v.fill(0);
    const got = await s.get("k");
    expect([...got]).toEqual([1, 2, 3]);
    await s.delete("k");
    expect(await s.get("k")).toBeUndefined();
    expect(s.size).toBe(0);
  });
});

for (const [name, make] of [["memoryCache", () => memoryCache()], ["indexedDbCache", () => indexedDbCache({ name: `t-${Math.random()}` })]]) {
  describe(name, () => {
    it("keeps vaults and records per user", async () => {
      const c = make();
      const v = { state: new Uint8Array([1]), base: new Uint8Array([2]) };
      await c.save("u1", "v1", v);
      await c.save("u1", "v2", { state: new Uint8Array([3]) });
      await c.save("u2", "v1", { state: new Uint8Array([4]) });
      await c.saveMeta("u1", "profile", new Uint8Array([5]));
      await c.saveMeta("", "config:https://x", new Uint8Array([6]));
      const got = await c.load("u1", "v1");
      expect([...got.state]).toEqual([1]);
      expect([...got.base]).toEqual([2]);
      expect(got.pending).toBeUndefined();
      expect((await c.list("u1")).sort()).toEqual(["v1", "v2"]);
      await c.remove("u1", "v2");
      expect(await c.list("u1")).toEqual(["v1"]);
      await c.clearUser("u1");
      expect(await c.list("u1")).toEqual([]);
      expect(await c.load("u1", "v1")).toBeUndefined();
      expect(await c.loadMeta("u1", "profile")).toBeUndefined();
      expect(await c.list("u2")).toEqual(["v1"]);
      expect([...(await c.loadMeta("", "config:https://x"))]).toEqual([6]);
      c.close?.();
    });
  });
}
