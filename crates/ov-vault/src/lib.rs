//! Keyring and vault keys (SPEC §5, §7), key rotation, member sealing and confirmation (§12),
//! service-account master keys (§9) and `ov://` secret references (§14).
//!
//! Pure logic: inputs are `ov-protocol` wire types (what the servers answered) and the unlocked
//! [`ov_crypto::keyset::Keyset`]; outputs are `ov-protocol` request bodies, which the facade sends
//! with the `AuthApi` builders, and `ov-kdbx` key versions. No I/O, no Host, no clock (callers pass
//! `now`).
//!
//! | Module | What | TS reference |
//! |---|---|---|
//! | [`keyring`] | unseal each vault's keys per version, decrypt names | `Account.ingest`, `ServiceAccount.listVaults` |
//! | [`sharing`] | new vault + org vault grant rule, seal a grant | `registerVault`, `share` |
//! | [`rotation`] | key rotation plan and requests | `rotate`, `revoke` |
//! | [`orgs`] | confirm, promote, flagged vaults | `confirmMember`, `setMemberRole`, `removeMember` |
//! | [`service_account`] | SA master wrapping, secrets, SA unlock | `createServiceAccount`, `issueServiceAccountSecret`, `service-account.ts` |
//! | [`unlock`] | sealed keyset resume check | `sealUnlocked`, `resumeUnlocked` |
//! | [`reference`](mod@reference), [`items`] | `ov://` references, items, templates | `vault/reference.ts`, `vault/items.ts` |
//!
//! Every key is held in `Zeroizing` and wiped on drop; `Debug` never prints one.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod items;
pub mod keyring;
pub mod keys;
pub mod orgs;
pub mod reference;
pub mod rotation;
pub mod service_account;
pub mod sharing;
pub mod unlock;

pub use items::{
    entry_id, find_item, is_protected_by_default, item_of, list_items, set_item_fields, CreateMode, FieldUpdate, Item,
    ItemField, ItemValues, SetFieldsOutcome,
};
pub use keyring::{Ingested, Keyring, VaultInfo, VaultKeys};
pub use orgs::{
    confirm_member_request, member_keys, missing_vaults, promotion, set_member_role_request, MemberKeys, VaultChoice,
};
pub use ov_kdbx::vault::KeyVersion;
pub use reference::{
    find_entry, find_references, format_item_reference, format_reference, inject, parse_item_reference,
    parse_reference, read_field, resolve_field_name, write_field, Injected, ItemReference, SecretReference,
};
pub use rotation::{plan_rotation, rename_request, RotationMember, RotationPlan};
pub use service_account::{
    check_writable, exchange_request, find_vault, issue_sa_secret, new_service_account, seal_sa_master_keys,
    unlock_service_account, unseal_master, IssuedSaSecret, NewServiceAccount, ServiceAccountSpec,
};
pub use sharing::{grant, new_vault, seal_grant, NewVault, SealedGrant, FIRST_KEY_VERSION};
pub use unlock::{keyset_secret, resume_keyset, unlock_seal_aad, UNLOCK_SEAL_VERSION};
