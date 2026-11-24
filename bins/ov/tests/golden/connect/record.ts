/**
 * Records what the TypeScript connect server (`createConnectHandler`, @openvireo/connect 1.1.0)
 * answers to a fixed request script, as golden fixtures (cases.json) the Rust `ov connect` must match.
 *
 * Runs inside an openvireo-sdk checkout, against its in-memory auth and sync servers. See README.md:
 *
 *   cd openvireo-sdk && npx vite-node --config <this dir>/vite.config.mjs <this dir>/record.ts
 *
 * Nothing here is committed to the SDK; the aliases in vite.config.mjs point into its tree.
 */
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Account } from "@sdk-src/account.ts";
import { MemoryStorage } from "@sdk-src/auth/storage.ts";
import { utf8 } from "@sdk-src/util/bytes.ts";
import { FakeAuthServer, ISSUER } from "@sdk-test/auth-server.ts";
import { FakeSyncServer } from "@sdk-test/sync-server.ts";
import { json as jsonResponse } from "@sdk-test/mock-fetch.ts";
import { ServiceAccount } from "@openvireo/sdk";
import { createConnectHandler } from "@connect/handler.ts";
import { type ConnectToken, hashConnectToken } from "@connect/tokens.ts";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "cases.json");

// ---------------------------------------------------------------------------------------------
// The fixture world (README.md "Fixture world")

const TOKENS = { app: "ov_ct_golden_app", ro: "ov_ct_golden_ro", other: "ov_ct_golden_other" } as const;
const tokens: ConnectToken[] = [
  { name: "app", sha256: hashConnectToken(TOKENS.app), vaults: ["Team Infra"], access: "write" },
  { name: "ro", sha256: hashConnectToken(TOKENS.ro), vaults: ["*"], access: "read" },
  { name: "other", sha256: hashConnectToken(TOKENS.other), vaults: ["Other"], access: "write" },
];

type Field = [name: string, value: string, protectedField: boolean];

async function makeWorld() {
  const auth = new FakeAuthServer();
  const sync = new FakeSyncServer();
  auth.onToken = (t) => sync.tokens.add(t);
  // the sync server enforces vault roles like the JWT routes (same as sdk/test/helpers/world.ts)
  const syncFetch = async (url: string, init: RequestInit = {}) => {
    const m = /\/api\/v1\/vaults\/([^/]+)/.exec(new URL(url).pathname);
    const principal = auth.tokens.get(new Headers(init.headers).get("authorization")?.replace(/^Bearer /, "") ?? "");
    if (m && principal) {
      const role = auth.vaults.get(m[1]!)?.access.get(principal)?.role;
      if (!role) return jsonResponse(403, { error: "no access to this vault", code: "forbidden" });
      if ((init.method === "PUT" || init.method === "DELETE") && role === "read") return jsonResponse(403, { error: "read-only access", code: "forbidden" });
    }
    return sync.fetch(url, init);
  };
  const fetch = (url: string, init?: RequestInit) => (new URL(url).host === "sync.example" ? syncFetch(url, init) : auth.fetch(url, init));

  const alice = await Account.connect({ issuer: ISSUER, fetch, storage: new MemoryStorage(), device: { name: "test", platform: "web" } });
  await alice.register({ email: "alice@example.com", password: "correct horse ü", kdf: { m: 19456, t: 2 } });
  const org = await alice.core.createOrg("Acme");

  const ids: Record<string, string> = {};
  const add = (v: any, group: string, title: string, fields: Field[]) => {
    ids[title] = v.addEntry(group, {
      fields: [{ name: "Title", value: utf8(title) }, ...fields.map(([name, value, p]) => ({ name, value: utf8(value), protected: p }))],
      removeFields: [],
      expiry: { kind: "never" },
    });
  };

  const infra = await alice.createVault("Team Infra", { orgId: org.id });
  {
    const v = infra.vault;
    const root = v.rootGroupId();
    add(v, root, "GitHub", [
      ["UserName", "ci", false],
      ["Password", "s3cret", true],
      ["URL", "https://github.com", false],
    ]);
    const deploy = v.addGroup(root, "Deploy");
    add(v, deploy, "Database", [
      ["UserName", "app", false],
      ["Password", "pg-pa$$word", true],
      ["URL", "postgres://db.internal:5432/app", false],
      ["Notes", "multi\nline", false],
      ["api key", "ak-12345", true],
    ]);
    const apps = v.addGroup(root, "Apps");
    const prod = v.addGroup(apps, "Prod");
    add(v, prod, "Service", [
      ["UserName", "svc", false],
      ["Password", "svc-pass", true],
    ]);
    await infra.sync();
  }
  const other = await alice.createVault("Other", { orgId: org.id });
  add(other.vault, other.vault.rootGroupId(), "Token", [["Password", "other-secret", true]]);
  await other.sync();
  const priv = await alice.createVault("Private", { orgId: org.id });
  add(priv.vault, priv.vault.rootGroupId(), "Bank", [["Password", "nope", true]]);
  await priv.sync();

  const sa = await alice.createServiceAccount(org.id, {
    name: "connect",
    vaults: [
      { id: infra.id, role: "write" },
      { id: other.id, role: "read" },
    ],
  });
  ids["Team Infra"] = infra.id;
  ids["Other"] = other.id;
  ids["Private"] = priv.id;
  return { fetch, saToken: sa.token, ids };
}

// ---------------------------------------------------------------------------------------------
// Normalization (README.md "Normalization")

const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;
const ID_LIKE = /\b[0-9a-f]{32}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const TIME_KEYS = new Set(["updatedAt", "createdAt", "modifiedAt", "expiresAt", "time"]);
const ETAG_KEYS = new Set(["etag", "eTag", "ETag"]);

function makeNormalizer(ids: Record<string, string>) {
  const replaceIds = (s: string): string => {
    let out = s;
    // longest first, so no id is a prefix of another's replacement
    for (const [name, id] of Object.entries(ids).sort((a, b) => b[1].length - a[1].length)) {
      out = out.split(id).join(`<uuid:${name}>`).split(id.toUpperCase()).join(`<uuid:${name}>`);
    }
    if (ID_LIKE.test(out)) {
      ID_LIKE.lastIndex = 0;
      console.error(`warning: unmapped id in ${JSON.stringify(out)}`);
      out = out.replace(ID_LIKE, "<uuid:?>");
    }
    ID_LIKE.lastIndex = 0;
    return out;
  };
  const value = (v: unknown, key?: string): unknown => {
    if (typeof v === "string") {
      if (key && ETAG_KEYS.has(key)) return "<etag>";
      if ((key && TIME_KEYS.has(key)) || ISO_TIME.test(v)) return "<time>";
      return replaceIds(v);
    }
    if (Array.isArray(v)) return v.map((x) => value(x));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, value(x, k)]));
    return v;
  };
  return { value, replaceIds };
}

/** Learns entry ids from any {id, title} object in a response (entries created by PUT). */
function learnIds(v: unknown, ids: Record<string, string>) {
  if (Array.isArray(v)) return v.forEach((x) => learnIds(x, ids));
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (typeof o.id === "string" && typeof o.title === "string" && !(o.title in ids)) ids[o.title] = o.id;
    Object.values(o).forEach((x) => learnIds(x, ids));
  }
}

// ---------------------------------------------------------------------------------------------
// The request script

/** A body too large to keep inline: `prefix + repeat × count + suffix`. */
interface GeneratedBody {
  prefix: string;
  repeat: string;
  count: number;
  suffix: string;
}
interface Step {
  name: string;
  method: string;
  /** path and query, with `<uuid:Name>` placeholders for ids */
  path: string;
  token?: keyof typeof TOKENS;
  headers?: Record<string, string>;
  body?: string | GeneratedBody;
  /** don't send Content-Length (a chunked upload) */
  noContentLength?: boolean;
}

const MiB = 1 << 20;
const TI = "/v1/vaults/Team%20Infra";
const put = (name: string, path: string, token: keyof typeof TOKENS, body: unknown, raw = false): Step => ({
  name,
  method: "PUT",
  path,
  token,
  headers: { "content-type": "application/json" },
  body: raw ? (body as string) : JSON.stringify(body),
});

const script: Step[] = [
  // liveness and readiness (no auth)
  { name: "ready before any other request", method: "GET", path: "/ready" },
  { name: "health", method: "GET", path: "/health" },
  { name: "health with a bearer token is still public", method: "GET", path: "/health", token: "ro" },
  { name: "health with POST (no method check)", method: "POST", path: "/health" },
  { name: "health with a trailing slash is an unknown route", method: "GET", path: "/health/" },

  // authentication
  { name: "vaults without a bearer token", method: "GET", path: "/v1/vaults" },
  { name: "vaults with an unknown bearer token", method: "GET", path: "/v1/vaults", headers: { authorization: "Bearer ov_ct_nope" } },
  { name: "vaults with an empty bearer", method: "GET", path: "/v1/vaults", headers: { authorization: "Bearer " } },
  { name: "vaults with a Basic authorization", method: "GET", path: "/v1/vaults", headers: { authorization: `Basic ${TOKENS.ro}` } },
  { name: "bearer scheme is case-insensitive", method: "GET", path: "/v1/vaults", headers: { authorization: `bearer ${TOKENS.ro}` } },
  { name: "unknown route is 404 before auth", method: "GET", path: "/v2/vaults" },
  { name: "unknown route with a token", method: "GET", path: "/v2/x", token: "ro" },
  { name: "bad percent-encoding is 400 before auth", method: "GET", path: "/v1/vaults/%zz" },

  // vault list and lookup
  { name: "vaults for app (one vault, write grant)", method: "GET", path: "/v1/vaults", token: "app" },
  { name: "vaults for ro (every vault the SA can open)", method: "GET", path: "/v1/vaults", token: "ro" },
  { name: "vaults for other", method: "GET", path: "/v1/vaults", token: "other" },
  { name: "vaults with a trailing slash", method: "GET", path: "/v1/vaults/", token: "ro" },
  { name: "vault by name", method: "GET", path: TI, token: "app" },
  { name: "vault by id", method: "GET", path: "/v1/vaults/<uuid:Team Infra>", token: "app" },
  { name: "vault outside the token's scope is 404", method: "GET", path: "/v1/vaults/Other", token: "app" },
  { name: "vault outside the token's scope by id is 404", method: "GET", path: "/v1/vaults/<uuid:Other>/items", token: "app" },
  { name: "vault not granted to the SA is 404", method: "GET", path: "/v1/vaults/Private", token: "ro" },
  { name: "vault not granted to the SA by id is 404", method: "GET", path: "/v1/vaults/<uuid:Private>", token: "ro" },
  { name: "unknown vault", method: "GET", path: "/v1/vaults/Nope", token: "ro" },
  { name: "unknown sub-route of a vault", method: "GET", path: `${TI}/secrets`, token: "app" },

  // items
  { name: "items list without values", method: "GET", path: `${TI}/items`, token: "ro" },
  { name: "items list of the read-grant vault", method: "GET", path: "/v1/vaults/Other/items", token: "other" },
  { name: "item at the root by title", method: "GET", path: `${TI}/items/GitHub`, token: "ro" },
  { name: "item by UUID", method: "GET", path: `${TI}/items/<uuid:GitHub>`, token: "ro" },
  { name: "item in a group", method: "GET", path: `${TI}/items/Deploy/Database`, token: "app" },
  { name: "item two groups deep", method: "GET", path: `${TI}/items/Apps/Prod/Service`, token: "ro" },
  { name: "item with the wrong group path", method: "GET", path: `${TI}/items/Apps/Service`, token: "ro" },
  { name: "nested item by title alone", method: "GET", path: `${TI}/items/Service`, token: "ro" },
  { name: "root item under a group it isn't in", method: "GET", path: `${TI}/items/Deploy/GitHub`, token: "ro" },
  { name: "encoded slash is part of the title", method: "GET", path: `${TI}/items/Deploy%2FDatabase`, token: "ro" },
  { name: "unknown item", method: "GET", path: `${TI}/items/Nope`, token: "ro" },
  { name: "bad percent-encoding in an item path", method: "GET", path: `${TI}/items/%zz`, token: "ro" },
  { name: "field by alias (password)", method: "GET", path: `${TI}/items/Deploy/Database?field=password`, token: "ro" },
  { name: "custom field with a space", method: "GET", path: `${TI}/items/Deploy/Database?field=api%20key`, token: "ro" },
  { name: "field as text/plain", method: "GET", path: `${TI}/items/Deploy/Database?field=notes`, token: "ro", headers: { accept: "text/plain" } },
  { name: "field with Accept text/plain and json gets JSON", method: "GET", path: `${TI}/items/Deploy/Database?field=username`, token: "ro", headers: { accept: "text/plain, application/json" } },
  { name: "unknown field", method: "GET", path: `${TI}/items/Deploy/Database?field=nope`, token: "ro" },

  // methods
  { name: "POST on the items list is 405", method: "POST", path: `${TI}/items`, token: "app" },
  { name: "DELETE on an item is 405", method: "DELETE", path: `${TI}/items/GitHub`, token: "app" },
  { name: "PATCH on an item is 405", method: "PATCH", path: `${TI}/items/GitHub`, token: "app" },
  { name: "DELETE on a vault", method: "DELETE", path: TI, token: "app" },
  { name: "POST on the vault list", method: "POST", path: "/v1/vaults", token: "app" },

  // writes that fail
  put("PUT from a read-only token", `${TI}/items/GitHub`, "ro", { fields: { password: "x" } }),
  put("PUT from a read-only token with a bad body is still 403", `${TI}/items/GitHub`, "ro", "not json", true),
  put("PUT to a vault the SA can only read", "/v1/vaults/Other/items/Token", "other", { fields: { password: "x" } }),
  put("PUT outside the token's scope", "/v1/vaults/Other/items/Token", "app", { fields: { password: "x" } }),
  put("PUT body not JSON", `${TI}/items/X`, "app", "{fields:", true),
  put("PUT body without fields", `${TI}/items/X`, "app", {}),
  put("PUT fields not an object", `${TI}/items/X`, "app", { fields: ["a"] }),
  put("PUT field value not a string", `${TI}/items/X`, "app", { fields: { a: 1 } }),
  put("PUT protected not bools", `${TI}/items/X`, "app", { fields: { a: "1" }, protected: { a: "yes" } }),
  put("PUT protected an array", `${TI}/items/X`, "app", { fields: { a: "1" }, protected: ["a"] }),
  {
    name: "PUT body over 1 MiB (Content-Length)",
    method: "PUT",
    path: `${TI}/items/X`,
    token: "app",
    headers: { "content-type": "application/json" },
    body: { prefix: '{"fields":{"a":"', repeat: "a", count: MiB, suffix: '"}}' },
  },
  {
    name: "PUT body over 1 MiB (chunked, no Content-Length)",
    method: "PUT",
    path: `${TI}/items/X`,
    token: "app",
    headers: { "content-type": "application/json" },
    body: { prefix: '{"fields":{"a":"', repeat: "a", count: MiB, suffix: '"}}' },
    noContentLength: true,
  },
  put("PUT ?create=false on a missing entry", `${TI}/items/Missing?create=false`, "app", { fields: { a: "1" } }),

  // writes that succeed
  put("PUT creates an entry in a new group", `${TI}/items/Apps/Api`, "app", { fields: { username: "svc", token: "t-1" }, protected: { username: true } }),
  put("PUT updates an entry", `${TI}/items/GitHub`, "app", { fields: { password: "via-connect", URL: "https://github.example" } }),
  put("PUT ?create=false updates an existing entry", `${TI}/items/Deploy/Database?create=false`, "app", { fields: { "api key": "ak-67890" } }),
  { name: "GET shows the update", method: "GET", path: `${TI}/items/GitHub`, token: "ro" },
  { name: "GET shows the created entry", method: "GET", path: `${TI}/items/Apps/Api`, token: "ro" },
  { name: "GET shows the ?create=false update", method: "GET", path: `${TI}/items/Deploy/Database?field=api%20key`, token: "ro", headers: { accept: "text/plain" } },
  { name: "items list after the writes", method: "GET", path: `${TI}/items`, token: "app" },
];

// ---------------------------------------------------------------------------------------------

const RECORDED_HEADERS = ["content-type", "cache-control", "allow", "www-authenticate"];
const bodyText = (b: string | GeneratedBody) => (typeof b === "string" ? b : b.prefix + b.repeat.repeat(b.count) + b.suffix);

async function main() {
  const world = await makeWorld();
  const sa = await ServiceAccount.fromToken(world.saToken, { fetch: world.fetch, headers: { "User-Agent": "openvireo-connect/1.1.0" } });
  let lines: string[] = [];
  // cacheTtlMs 0: every request re-checks the sync server, so no case depends on timing
  const handler = createConnectHandler({ source: sa, tokens, cacheTtlMs: 0, log: (l) => lines.push(l) });
  const ids = world.ids;
  const norm = makeNormalizer(ids);
  const cases: unknown[] = [];

  for (const step of script) {
    const headers: Record<string, string> = {};
    if (step.token) headers.authorization = `Bearer ${TOKENS[step.token]}`;
    Object.assign(headers, step.headers);
    let body: string | undefined;
    if (step.body !== undefined) {
      body = bodyText(step.body);
      if (!step.noContentLength) headers["content-length"] = String(Buffer.byteLength(body));
    }
    const realPath = step.path.replace(/<uuid:([^>]+)>/g, (_, n: string) => {
      if (!ids[n]) throw new Error(`no id for ${n}`);
      return ids[n]!;
    });
    lines = [];
    const res = await handler(new Request(`http://connect.local${realPath}`, { method: step.method, headers, body }));
    const text = await res.text();
    const ct = res.headers.get("content-type") ?? "";
    let parsed: unknown = text;
    if (ct.includes("json")) {
      parsed = JSON.parse(text);
      learnIds(parsed, ids);
    }
    const resHeaders: Record<string, string> = {};
    for (const h of RECORDED_HEADERS) {
      const v = res.headers.get(h);
      if (v !== null) resHeaders[h] = v;
    }
    const request: Record<string, unknown> = { method: step.method, path: step.path, headers };
    if (step.body !== undefined) request.body = step.body;
    cases.push({
      name: step.name,
      request,
      response: {
        status: res.status,
        headers: resHeaders,
        body: norm.value(parsed),
        // what `ov connect` writes to stderr: `<ISO time> ` + the handler's line
        log: lines.map((l) => `<time> ${norm.replaceIds(l)}`),
      },
    });
  }
  sa.close();
  // Deliberate divergences from TS (README "Deliberate divergences"): the Rust server fixes these
  for (const c of cases) {
    if (c.name === "POST on the vault list") {
      c.response.status = 405;
      c.response.headers = { ...c.response.headers, allow: "GET" };
      c.response.body = { error: "method not allowed", code: "invalid_request" };
      c.response.log = ["<time> POST /v1/vaults 405 token=app"];
      c.divergesFromTs = "TS answers 500 server_error (it calls vault(undefined))";
    }
  }
  writeFileSync(OUT, JSON.stringify(cases, null, 2) + "\n");
  console.error(`wrote ${cases.length} cases to ${OUT}`);
}

await main();
