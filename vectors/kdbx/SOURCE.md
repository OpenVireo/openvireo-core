# kdbx/

`.kdbx` files written by the desktop app, copied unchanged from openvireo-ios
(`github.com/openvireo/openvireo-ios`) `OpenVireoCoreTests/Fixtures/`, branch `develop`, at HEAD
`5c9b545562b0292ff3040c51289ecdb0728f0e39` (2026-11-12). Both were added in
`2d571785e0400eab81e90c05162152052827ed9f` (2026-10-30, "Add a Swift KDBX 4 reader and writer") and
haven't changed since. Password for both: `desktop pw ✓` (`ov_testkit::kdbx::DESKTOP_PASSWORD`).

From openvireo-ios's `Fixtures/SOURCE.md`: made with the desktop app's `openvireo-cli` (2.8.0-snapshot):

- `desktop-kdbx31.kdbx`: `db-create -p -t 100` (KDBX 3.1, AES-KDF, AES-256), then `add` Bank and
  Work/Server and `attachment-import` note.txt.
- `desktop-kdbx4-argon2d.kdbx`: written by the iOS app's `DesktopInteropTests.interopSource()`, then
  `add` "From desktop" with the CLI, which saved it as KDBX 4.0 (Argon2d).

## Checksums

```
f857a4e0f51c263771d4de7a9f2770ffd3cb402de79f82bb0ea6172991a7f339  desktop-kdbx31.kdbx
1f4366accac857157262887e7645a0520a3a6b296cf6511d58a1b4579cec73e4  desktop-kdbx4-argon2d.kdbx
```
