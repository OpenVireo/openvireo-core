# Golden fixtures: `ov connect` REST API

`cases.json` records what the TypeScript connect server (`createConnectHandler` from
`@openvireo/connect` 1.1.0, openvireo-sdk `develop` at 6926a1d) answers to a fixed script of
requests. The Rust `ov connect` handler must give the same status, headers, body and log line for
each case, after the normalization below. Plan: `openvireo-dev-guide/plans/connect-rust.md` §5, task C3.

| File | |
|---|---|
| `cases.json` | the recorded cases (generated, do not edit by hand) |
| `record.ts` | the recorder: builds the fixture world, runs the script, writes `cases.json` |
| `vite.config.mjs` | aliases that let `record.ts` import the SDK's sources and test helpers from an SDK checkout |

## Fixture world

Build the same world on `ov-testkit` (in-memory auth and sync servers; the sync server enforces vault
roles: no grant → 403, a write with a `read` grant → 403).

- User `alice@example.com` (password `correct horse ü`), org `Acme`, three org vaults:
  - **Team Infra**
    - `GitHub` at the root: `UserName` = `ci`, `Password` = `s3cret` (protected), `URL` = `https://github.com`
    - group `Deploy`, entry `Database`: `UserName` = `app`, `Password` = `pg-pa$$word` (protected),
      `URL` = `postgres://db.internal:5432/app`, `Notes` = `multi\nline` (a real newline),
      custom field `api key` = `ak-12345` (protected)
    - groups `Apps` / `Prod`, entry `Service`: `UserName` = `svc`, `Password` = `svc-pass` (protected)
  - **Other**: `Token` at the root, `Password` = `other-secret` (protected)
  - **Private**: `Bank` at the root, `Password` = `nope` (protected)
- Fields are added in the order listed (after `Title`); groups and entries too (`GitHub`, then `Deploy`,
  then `Apps`). The order shows in `fields`, `protected` and `items`.
- One service account `connect` in `Acme` with grants **Team Infra = write** and **Other = read**. It has
  no grant on Private.
- Connect tokens (plain token → config entry; `sha256` is the hex SHA-256 of the plain token):

  | Plain token | name | vaults | access |
  |---|---|---|---|
  | `ov_ct_golden_app` | `app` | `["Team Infra"]` | `write` |
  | `ov_ct_golden_ro` | `ro` | `["*"]` | `read` |
  | `ov_ct_golden_other` | `other` | `["Other"]` | `write` |

- The handler runs with **cache TTL 0** (every request re-checks the sync server) and the default vault
  list TTL (60 s) and body limit (1 MiB). Cases run in file order against one handler instance: the PUTs
  near the end change the world, and the GETs after them show the result.

## Format

`cases.json` is an array of:

```jsonc
{
  "name": "item in a group",
  "request": {
    "method": "GET",
    "path": "/v1/vaults/Team%20Infra/items/Deploy/Database",   // path + query, sent as is
    "headers": { "authorization": "Bearer ov_ct_golden_app" }, // exactly the headers sent (lowercase names)
    "body": "…"                                                 // optional, see below
  },
  "response": {
    "status": 200,
    "headers": { "content-type": "application/json", "cache-control": "no-store" },
    "body": { … },        // parsed JSON when content-type is JSON; otherwise the text as a string
    "log": ["<time> GET /v1/vaults/Team%20Infra/items/Deploy/Database 200 token=app"]
  }
}
```

- **`request.path`** may hold placeholders `<uuid:NAME>` where the request uses an id. Substitute the
  id your world gave that vault or entry (`<uuid:Team Infra>`, `<uuid:Other>`, `<uuid:Private>`,
  `<uuid:GitHub>`) before sending. Ids are inserted raw (entry ids are 32 lowercase hex digits, vault
  ids whatever the auth server issues; neither needs percent-encoding).
- **`request.body`** is a string sent byte for byte (UTF-8), or, for bodies too big to keep inline, an
  object `{"prefix","repeat","count","suffix"}` meaning `prefix + repeat × count + suffix`.
- **`request.headers`** includes `content-length` (the UTF-8 byte length of the body) whenever the
  recorder sent one. One case ("PUT body over 1 MiB (chunked, no Content-Length)") deliberately has a
  body and no `content-length`: send it without that header so the limit on the bytes read is what
  rejects it. Requests without a body have no `content-type`/`content-length`.
- **`response.headers`** holds only `content-type`, `cache-control`, `allow` and `www-authenticate`,
  lowercase names, when present. Compare exactly those four: a header listed must match exactly, and a
  header absent here must be absent from the Rust response too.
- **`response.body`**: compare JSON structurally after normalization (object key order is not
  compared by the fixture; see "Key order" below). Text bodies compare as exact strings.
- **`response.log`**: the lines the server writes to stderr for the request (`ov connect` prints the
  handler's line prefixed by an ISO timestamp and a space), normalized. Every request logs exactly one
  line.

### Key order

The TS server serializes keys in this order, and the fixture keeps it, so a test may also check order
(ESO `jsonPath` does not care, people diffing output do): vault `{id, name, role}`; Item `{id, title,
group, fields, protected, tags, updatedAt}`; error `{error, code}`; `fields` in the entry's field order.

## Normalization

Apply the same rules to the Rust response before comparing (the fixture already has them applied):

1. **Ids → `<uuid:NAME>`.** Every occurrence of a known vault id or entry id, anywhere in a JSON
   string value (including inside messages like `vault "<id>" not found`) or in a log line, is replaced
   by `<uuid:NAME>`, where NAME is the vault's name or the entry's title. The id is matched as a
   substring, lowercase or uppercase. Known ids: the three vaults, the five seeded entries (`GitHub`,
   `Database`, `Service`, `Token`, `Bank`), plus any entry learned from a response: whenever a JSON
   response contains an object with string `id` and `title` and that title has no id yet, map it (this is
   how `<uuid:Api>`, created by a PUT, gets its name). Learn before normalizing the next case; the
   recorder learns from each response before normalizing it.
2. **Unmapped ids → `<uuid:?>`.** Anything left that looks like an id (32 hex digits, or an 8-4-4-4-12
   UUID) becomes `<uuid:?>`. The current fixture has none.
3. **Times → `<time>`.** A string value under a key named `updatedAt`, `createdAt`, `modifiedAt`,
   `expiresAt` or `time`, or any string that is an ISO 8601 date-time
   (`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`), becomes `<time>`. In log lines the leading timestamp
   becomes `<time>`.
4. **ETags → `<etag>`.** A string under a key named `etag` (any case listed: `etag`, `eTag`, `ETag`)
   becomes `<etag>`. The current fixture has none (the API exposes no etags).
5. Nothing else is touched: secret values, names, messages and statuses compare exactly.

## Behaviour worth knowing (recorded as is)

These are what the TS server actually does; some differ from a reading of plan §5 or `docs/connect.md`:

- `/health` and `/ready` answer any method (`POST /health` → 200) and ignore the bearer token;
  `/health/` (trailing slash) is a 404 `no such route`.
- Unknown routes (not under `/v1/vaults`) are 404 **before** authentication, and bad percent-encoding
  anywhere in the path is 400 before authentication (the log says `token=-` even with a valid token).
- `POST /v1/vaults` is a **500 `server_error`** (the handler looks up vault `undefined`); `DELETE
  /v1/vaults/{vault}` is 404 `no such route`, not 405. Only `…/items` (Allow `GET`) and
  `…/items/{entry}` (Allow `GET, PUT`) send 405, with code `invalid_request`.
- Repeated or trailing slashes are dropped from the segments (`/v1/vaults/` = `/v1/vaults`).
- The group path in front of an entry narrows the search to entries **under** that group, at any depth:
  `Apps/Service` and plain `Service` both find `Apps/Prod/Service`; `Deploy/GitHub` is 404. An encoded
  `%2F` stays inside one segment (`Deploy%2FDatabase` looks for the title `Deploy/Database`).
- `?field=` resolves exact name, then the standard aliases (`password`, `username`, `user`, `url`,
  `notes`, `title`), then a case-insensitive match. `text/plain` is used only when `Accept` contains
  `text/plain` and not `json`.
- Items always carry the standard fields (`Title`, `UserName`, `Password`, `URL`, `Notes`), empty when
  unset; a created entry gets an empty protected `Password`.
- PUT checks run in this order: vault lookup (404), token access (403 `token "…" is read-only`, even for
  a malformed body), body size, JSON, `fields`, `protected`, then the SA grant (403 `this service account
  can only read vault "…"`). The PUT response omits protected values; `protected` names in the request are
  resolved like `?field=` (`username` → `UserName`).
- The log line is `<METHOD> <path> <status> token=<name|->` where `<path>` is the **raw, still
  percent-encoded** URL path **without the query string**.

## Deliberate divergences

`record.ts` rewrites these cases after recording, because the Rust server fixes the TS behaviour. Each
carries a `divergesFromTs` note.

- **POST on the vault list**: TS answers 500 `server_error` (it calls `vault(undefined)`); Rust answers
  405 `invalid_request` with `Allow: GET`.
- Not a fixture, but also fixed: the body limit counts bytes, also for chunked bodies (TS counts UTF-16
  code units there).

## Re-recording

From a clean openvireo-sdk checkout with dependencies installed (`npm ci`; nothing is written to the
SDK tree):

```sh
cd /path/to/openvireo-sdk
G=/path/to/openvireo-core/bins/ov/tests/golden/connect
npx vite-node --config "$G/vite.config.mjs" "$G/record.ts"
# wrote 67 cases to …/cases.json
```

`vite-node` ships with the SDK's `vitest` dev dependency. The config resolves the SDK from the current
directory (or `OPENVIREO_SDK=/path/to/openvireo-sdk`). A run takes about a second and is deterministic:
two runs give byte-identical `cases.json`. Review the diff before committing: a change means the TS
behaviour (or the script) changed, and the Rust side must follow.
