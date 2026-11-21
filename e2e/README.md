# Cross-client end-to-end tests

Every OpenVireo client now runs on this core. These tests run the clients against the real local stack
(the auth server with Postgres, Redis and the mail catcher, plus the sync server, all from the workspace
`compose.yaml`). Where a client can be scripted, the clients also check each other's work on the same
accounts.

| Client | How it takes part |
|---|---|
| `ov` (Rust CLI, native core) | spawned by `cross-client.mjs` with its own `OPENVIREO_CONFIG_DIR` per user, the password from `OPENVIREO_PASSWORD` |
| SDK (Node, core-wasm) | imported from an openvireo-sdk checkout's built `packages/sdk/dist` |
| iOS | its own e2e suites (`scripts/test-e2e.sh` in openvireo-ios), one bundle at a time |
| desktop | its live-server tests (`testremotesyncserver`, `testguiautosync`) and its `openvireo-kdbx` reader |

## Running

```sh
# ov + SDK only (builds ov into e2e/target)
OV_E2E_SDK_DIR=~/kpnx/openvireo-sdk e2e/run.sh

# the whole matrix, on a clean stack
OV_E2E_FRESH=1 \
OV_E2E_SDK_DIR=~/kpnx/openvireo-sdk \
OV_E2E_IOS_DIR=~/kpnx/openvireo-ios \
OV_E2E_DESKTOP_BUILD=~/kpnx/openvireo/cmake-build-debug \
e2e/run.sh
```

`run.sh` does the following:

1. It starts `auth` and `sync` with `docker compose up -d --wait` and waits for discovery.
2. It clears the auth server's rate-limit counters in Redis, then every two seconds for the rest of the run, as
   the iOS `test-e2e.sh` does. The server allows 5 registrations a minute per IP, and a run registers about 15
   accounts. This only ever happens against the local stack.
3. It builds `ov`, unless you set `OV_BIN`.
4. It runs `cross-client.mjs` (ov + SDK), then the iOS bundles and the desktop tests when their variables are set.
5. It prints the scenario × client matrix (`matrix.mjs`) and exits 1 if any cell failed.

Logs, `cross-client.json` and `matrix.txt` go to `OV_E2E_OUT_DIR`, or a new temporary folder.

### Prerequisites

- **SDK:** in its checkout, `npm ci && npm run build -w packages/sdk`.
- **iOS:** `scripts/build-vendor.sh` once in that checkout. It does a full core build of more than 10 GB, so
  check your free disk first. Each run creates its own iPhone 17 simulator on the newest iOS runtime and deletes
  it afterwards. `AccountFlowUITests` depends on the accounts a simulator remembers: after a few runs on the same
  simulator, the "Add another account" button falls below the fold of the account list and the tests can't find
  "Create account". `OV_E2E_IOS_DESTINATION` picks a simulator of your own instead.
- **Desktop:** a CMake build with tests. The tests use the in-memory token store (`OPENVIREO_TEST_BINARY`).
  `testPlatformTokenStore` is never run, `HOME` points to a scratch folder, and `QT_QPA_PLATFORM=offscreen`.

### A clean stack

With `OV_E2E_FRESH=1`, the run doesn't touch your everyday stack's data:

1. It stops your everyday stack (the project named in `.env`). Its volumes stay.
2. It runs a throwaway project, `openvireo-e2e-<pid>`, with new volumes on the same ports.
3. It deletes that project with `down -v`.
4. It starts your everyday stack's services again.

The throwaway project is set through `COMPOSE_PROJECT_NAME`, so the iOS script's compose calls use it too.

## Scenarios

`cross-client.mjs` runs these with `ov` and the SDK:

| # | What | Clients |
|---|---|---|
| 1 | Register on the SDK. Sign in on a second SDK device (refused without the Secret Key) and on ov (refused with a wrong password). ov reads the SDK's entry, both SDK devices read ov's, and ov logs out. | SDK → SDK, ov |
| 2 | ov creates an entry and the SDK pulls it. Concurrent edits to different fields merge. Concurrent edits to the same field: the newer wins and the SDK reports a conflict. Three writers at once (two SDK devices and ov) converge through 412 merge-and-retry. A delete reaches ov. An edit beats a concurrent delete. | SDK, ov |
| 3 | The SDK moves an entry to the Recycle Bin, and ov stops seeing it. The server copy is KDBX 4.1. The desktop's `openvireo-kdbx` lists the entry in the bin. A second SDK device restores it from a fresh download to its previous group (`Finance/Cards`), and ov finds it there again. Emptying the bin reaches every client. | SDK, ov, desktop (file) |
| 4 | Alice (SDK) checks Bob's fingerprint and shares to his keys with write access. Bob (ov) reads and writes, and Alice sees it. Bob (SDK) writes, and Alice (ov) reads it. After Alice drops Bob to read, ov's write is refused. | SDK ↔ ov, two users |
| 5 | ov makes a link with 2 opens. The SDK opens it twice and the third open is refused, and ov's and the SDK's share lists agree. A passcode link from ov is refused without the passcode and with the wrong one, and opens with the right one. A link made on the SDK is revoked on ov. | ov → SDK, SDK → ov |
| 6 | The SDK rotates the vault key. Bob (ov) and a new SDK device use the new key. Revoking Bob rotates again and removes him on ov and on the SDK. Then `ov rotate` changes a secret and the SDK reads it. | SDK, ov |
| 6b | A device that was signed in before another device rotated the key opens and syncs the vault without listing the vaults first. Fixed after contract-v1.8 (W3-X found it): the core fetches the vault's keys again when the server copy doesn't open with the ones it holds. | SDK |
| 7 | ov deletes the account (wrong email refused; the preview counts its share link). The link stops working, the old SDK session ends, and a new SDK sign-in sees the account pending and restores it. Then ov uses it again. The reverse also runs: the SDK deletes and ov restores. | ov ↔ SDK |

Cells marked n/a need new client code:

- ov can't register, delete entries, use the Recycle Bin, share vaults, rotate vault keys or open share
  links. The SDK does those steps and ov checks the result.
- The iOS suites register their own accounts and have no hook to sign in to one made elsewhere, so they are
  iOS↔iOS checks against the stack. There's no iOS e2e test against the stack for the Recycle Bin, share links
  or account deletion.
- The desktop's account flows are only tested against in-memory fakes. Its live-server mode is self-hosted
  sync only, so it counts for scenario 2 (in self-hosted mode), and scenario 3 checks its KDBX reader.

## Known failures

Known failures are listed in `KNOWN` in `cross-client.mjs`. They show as `FAIL (known)` and don't change the
exit status unless `OV_E2E_STRICT=1`. Delete an entry once its fix lands.

None at the moment.

## Running a subset

```sh
OV_E2E_ONLY=2,5 OV_E2E_SDK_DIR=… e2e/run.sh            # only some ov + SDK scenarios
OV_BIN=… OV_E2E_SDK_DIR=… node e2e/cross-client.mjs     # no stack handling: you clear the rate limits yourself
```
