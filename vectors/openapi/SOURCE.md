# vectors/openapi/

The auth and sync server API contracts, copied unchanged. `cargo xtask openapi` (W1-P) checks that every
`example` in them round-trips through the ov-protocol serde types. The dev guide's
`scripts/check-contract-copies.sh` compares these copies with the canonical files.

From openvireo (`github.com/openvireo/openvireo`), branch `develop`, at HEAD `14873339afc6faa2dbf450200b17aec69aa58df7` (2026-11-15),
`docs/plans/accounts/`:

- `openapi.yaml` (auth server): last changed in 7745b5f6f13cbfffdaa74faa88a91eda99557e36 (2026-11-08, "Contract: billed_by_apple from POST /billing/apple/transactions (SPEC §19)").
- `sync-openapi.yaml` (sync server): last changed in be89289c704b0c2e210dd91b1301ec03cbfb8434 (2026-10-26, "Merge feature/accounts: plans and limits contract (SPEC §19)").

Added in `contract-v1.2` (W1-P CONTRACT-REQUEST, user-approved 2026-11-15).

2026-11-21 (B8, contract-v1.9 candidate): `openapi.yaml` `Platform` gained `android`, the same
one-line change as openvireo branch `feat/platform-android`; the copy matches the canonical file
again once that branch is on `develop`.

## Checksums

```
8462d27609d8ef5fadbffb11ed10e79d4024b36281244c1a11437451e774e3ac  openapi.yaml
f42b2a19c8ad97350d45029361955b1dce490503655006d72b126a9a6841fd32  sync-openapi.yaml
```
