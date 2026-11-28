# corpus/kdbx/

KDBX files written by other apps, for `crates/ov-kdbx/tests/corpus.rs` (task W1-K3). The harness
opens each file listed in `manifest.tsv`, saves it, reopens the output and requires an equal model
(`Database == Database`), saves it again (it must be stable), and checks that KeePassXC's CLI and
kdbxweb open the rewrite and see what they saw in the original. See the top of `corpus.rs` for the
environment variables (`OV_KEEPASSXC_CLI`, `OV_SDK`, `OV_KEEPASSXC_SRC`, `OV_CORPUS_REQUIRE_TOOLS`).

```
cargo test -p openvireo-kdbx --test corpus -- --nocapture
```

The files contain only made-up test data. Every password and key file is listed in `manifest.tsv`.

## Files

| File | Writer | Format | Key | Covers |
|---|---|---|---|---|
| `kdbxweb/kdbxweb-vault.kdbx` | SDK `createVaultKdbx` (kdbxweb 2.1.1) | 4.0, ChaCha20, Argon2id 1 MiB/2/1 | `keys/vault.key` only | custom + protected fields (non-standard order), history, attachment, entry tags, colours, override URL, auto-type association, custom data on Meta/group/entry, recycle bin, `DeletedObjects` |
| `kdbxweb/kdbxweb-unknown.kdbx` | kdbxweb 2.1.1 + injected XML | 4.0, Argon2id | `spike pw` | the above, plus unknown `Zz*` elements in KeePassFile, Meta, Root, Group, Entry, AutoType |
| `kdbxweb/kdbxweb-unknown-leaf.kdbx` | kdbxweb 2.1.1 + injected XML | 4.0, Argon2id | `spike pw` | unknown elements only in Meta, Entry, AutoType |
| `kdbxweb/kdbxweb-41-icons.kdbx` | kdbxweb 2.1.1 | 4.1, AES-256, AES-KDF | `spike pw` | the vault content, plus a named custom icon (4.1) on a group and an entry, group tags |
| `kdbxweb/kdbxweb-kdbx31.kdbx` | kdbxweb 2.1.1 | 3.1, AES-256, AES-KDF, Salsa20 inner stream | `spike pw` | the vault content as KDBX 3.1 (`Meta/Binaries`, ISO times) |
| `ios/ios-interop.kdbx` | iOS app, `DesktopInteropTests.writeInteropSource()` (simulator) | 4.0, Argon2d | `desktop pw ✓` | protected custom field, attachment |
| `ios/ios-passkey.kdbx` | iOS app, `PasskeyTests.writesInteropFile()` (simulator) | 4.0, AES-KDF | `interop` | passkey fields |
| `keepassxc/keepassxc-features.kdbx` | KeePassXC CLI `import` of the XML in `gen-keepassxc.mjs` | 4.1, AES-256, AES-KDF | `corpus pw ✓` | attachments (one shared by two entries, one binary), history (2 items, one without the attachment), custom icon (named) on a group and an entry, entry + group tags, recycle bin holding an entry and a group, `PreviousParentGroup`, custom data on Meta/group/entry with times, auto-type (sequence, 2 associations, one disabled with obfuscation), expiring entry with usage count, colours, override URL, protected custom field, `QualityCheck=False`, `DeletedObjects` |
| `keepassxc/keepassxc-cli-keyfile.kdbx` | KeePassXC CLI commands (`db-create`, `mkdir`, `add`, `edit`, `attachment-import`, `rm`) | 4.1 (KeePassXC's default for a new file) | `corpus pw ✓` + `keys/keepassxc-cli-keyfile.key` (64 hex chars) | composite key (password + hex key file), history from `edit`, attachment, recycle bin from `rm` |
| `keepassxc/keepassxc-5k.kdbx` | KeePassXC CLI `import` | 3.1, AES-KDF | `corpus pw ✓` | 5,000 entries in 50 groups. **Not committed** (see below) |

The harness also round-trips the three contract fixtures in `vectors/` (`vault-fixture.kdbx`,
`kdbx/desktop-kdbx31.kdbx`, `kdbx/desktop-kdbx4-argon2d.kdbx`; see `vectors/kdbx/SOURCE.md`), and
builds a 5,000-entry database in memory (`five_thousand_entries_round_trip`: history on every 10th
entry, an attachment on every 100th), so 5k coverage never depends on the generated file.

`keys/vault.key` is the contract's test vault key (`vectors/test-vectors.json`
`vault_kdbx.vault_key_hex`) as 32 raw bytes: the SPEC §7 key-file component that opens
`kdbxweb-vault.kdbx` and `vectors/vault-fixture.kdbx`.

## How they were made

Tools: the desktop CLI `openvireo/build/src/cli/openvireo-cli` (**KeePassXC 2.8.0-snapshot**,
renamed; openvireo `develop` at `14873339afc6faa2dbf450200b17aec69aa58df7`; the card asks for 2.7,
and there is no 2.7 build here), openvireo-sdk at `fd5e5318ae7db680ba625253a6561ded33d08870`
(bundles kdbxweb 2.1.1), node 24.14.0.

- **kdbxweb**: `node corpus/kdbx/gen-kdbxweb.mjs` (rewrites all five files). The first three were
  written for the W1-K1 spike (ADR 0002) and moved here unchanged (git history follows them from
  `spikes/kdbx/files/`); `kdbxweb-41-icons` and `kdbxweb-kdbx31` were added by W1-K3. Unknown
  elements are injected after kdbxweb's `buildXml`, since kdbxweb rebuilds its XML on save.
- **KeePassXC**: `node corpus/kdbx/gen-keepassxc.mjs [--5k]`. The XML it imports has fixed UUIDs
  (SHA-256 of a label) and times, so reruns give the same content; the bytes still change (random
  salts and IVs on every save). `-t 100` sets the KDF time.
- **iOS app**: written by the W1-K1 spike from openvireo-ios `develop` (HEAD
  `5c9b545562b0292ff3040c51289ecdb0728f0e39`, 2026-11-12) on the iOS simulator and moved here
  unchanged. Recipe:
  `TEST_RUNNER_OV_INTEROP_OUT=<path> xcodebuild test -project OpenVireo.xcodeproj -scheme OpenVireo
  -destination 'platform=iOS Simulator,name=iPhone 16'
  '-only-testing:OpenVireoCoreTests/DesktopInteropTests/writeInteropSource()'` (and
  `PasskeyTests/writesInteropFile()`). Use the `OpenVireo` scheme (the `OpenVireoCore` scheme has no
  test action), set the variable in the environment, and add `()` to Swift Testing identifiers.

### The 5,000-entry file

`keepassxc/keepassxc-5k.kdbx` is **reproducible, not committed** (it's 381,038 bytes; it's in
`.gitignore`). `node corpus/kdbx/gen-keepassxc.mjs --5k` writes it; the manifest marks it
`optional`, so the harness tests it when it's present and skips it otherwise. The copy made on
2026-11-15 was 381,038 bytes, SHA-256
`c39f9552dae312e79dcdea7e0dff371bc53a84ad84ab91c3292ff61a24fb0ee4`; a rerun gives the same content
and a different hash (random salts and IVs).

## Not available here

- **KeePass 2.x** (Windows .NET): not installed, and there's no `mono` to run it (checked
  2026-11-15: `which mono`, `brew list`). Instead the manifest lists six KeePass 2.x-written files
  (`Generator` = `KeePass`, checked with `kdbxweb-open.mjs`) from the desktop repo's
  `tests/data/` (KeePassXC's test fixtures: `Format300` (KDBX 3.0), `Format400`, `Compressed`,
  `ProtectedStrings`, `NonAscii`, `NewDatabase`), as `external` entries read in place from
  `$OV_KEEPASSXC_SRC` (default `$HOME/kpnx/openvireo`) and skipped when absent. They're not copied
  here because KeePassXC is GPL; copying them needs a licence decision. Making our own KeePass 2.x
  files needs a Windows machine (or mono) with KeePass 2.5x.
- **Strongbox**: not installed (no app in `/Applications`, not in Homebrew). Strongbox files need a
  Mac or iPhone with Strongbox; add them as `strongbox/*.kdbx` with a row in `manifest.tsv`.
- KeePassium is installed on this Mac (another writer, GUI only); it isn't in the corpus.

## Checksums

```
7b5b11f9ab7358a2a5394aaad3e7973a555d8c64099cfcdbbd320d1ce98013b9  kdbxweb/kdbxweb-vault.kdbx
311e5a246b4d31e349ba2492490acc24b3ed73cb2caff1b0b683f8d703f506ab  kdbxweb/kdbxweb-unknown.kdbx
0257b7eedaca4ad1fff86aba612531615fe179a18afcdc1f2c8c2c59241deaea  kdbxweb/kdbxweb-unknown-leaf.kdbx
ed7b63dccc4957b521ae7387465c1d8bb05f8c8d545bcd0686257a014181860d  kdbxweb/kdbxweb-41-icons.kdbx
94b52f415ffd40258f88d3573e562e7f2a06c215e40abb58e00a9650d98fe298  kdbxweb/kdbxweb-kdbx31.kdbx
8de09ef37139def5a9f906e2b9f6c2dd195041741fb0700e47230cd0d9af8413  ios/ios-interop.kdbx
a412303cb6fd216b3d08d4ba5dc71790616c61bcbd5cee579a2f62957bafddf1  ios/ios-passkey.kdbx
94830256c3a1d24d50f3f46b1a2974161e256dbcd6a67d2709d5447347918aff  keepassxc/keepassxc-features.kdbx
78999bb4ee11f8171306aa1e72b1770d08c3a3ddef6acf1c848f19220411a0da  keepassxc/keepassxc-cli-keyfile.kdbx
d3aad9b28a75e7ba1e714b734a73ad195400ad74895e7ccb8a9794a2c64afd21  keys/keepassxc-cli-keyfile.key
0d9c5e36f0d193d2a28307292096596cc528334903cc71a9728cc8694bb82b85  keys/vault.key
```
