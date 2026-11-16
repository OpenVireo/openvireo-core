//! A minimal in-memory stand-in for the auth server's vault, org and service-account state (the
//! parts of the SDK's `FakeAuthServer` the sharing tests exercise) plus a blob store, so the pure
//! ov-vault functions can be driven end to end without HTTP.
#![allow(dead_code)]

use std::collections::BTreeMap;

use ov_crypto::encoding::{b64u, from_b64u};
use ov_crypto::keyset::{generate_keyset, Keyset};
use ov_crypto::tokens::sa_secret_hash;
use ov_error::{OvError, OvErrorCode};
use ov_kdbx::entries::{add_entry, EntryData};
use ov_kdbx::model::Database;
use ov_kdbx::vault::{create_vault_kdbx, open_with_key_versions, rekey_to_vault_key, KeyVersion};
use ov_protocol::types::*;
use ov_vault::keys::{user_principal, wire_public};
use ov_vault::{plan_rotation, VaultKeys};
use zeroize::Zeroizing;

pub const NOW: i64 = 1_700_000_000;
pub const ISSUER: &str = "https://accounts.example";

pub struct User {
    pub id: String,
    pub email: String,
    pub keyset: Keyset,
}

impl User {
    pub fn new(name: &str) -> User {
        User { id: name.to_owned(), email: format!("{name}@example.com"), keyset: generate_keyset().unwrap() }
    }
    pub fn principal(&self) -> Principal {
        user_principal(&self.id)
    }
}

#[derive(Clone, Default)]
pub struct AccessRow {
    pub role: Option<VaultRole>,
    /// key version → sealed key
    pub keys: BTreeMap<i64, String>,
}

#[derive(Clone)]
pub struct ServerVault {
    pub org_id: Option<String>,
    pub encrypted_name: String,
    pub current: i64,
    pub pending: Option<i64>,
    pub rotation_required: bool,
    pub access: BTreeMap<Principal, AccessRow>,
}

pub struct ServerSa {
    pub org_id: String,
    pub name: String,
    pub keyset: WrappedKeyset,
    pub masters: BTreeMap<Principal, String>,
    /// secret hash → wrapped master
    pub secrets: BTreeMap<String, String>,
}

#[derive(Default)]
pub struct Server {
    pub publics: BTreeMap<Principal, PublicKeys>,
    pub emails: BTreeMap<String, Principal>,
    pub vaults: BTreeMap<String, ServerVault>,
    pub members: BTreeMap<String, Vec<Member>>,
    pub sas: BTreeMap<String, ServerSa>,
    pub blobs: BTreeMap<String, Vec<u8>>,
}

fn err(code: OvErrorCode, status: u16, msg: &str) -> OvError {
    OvError::new(code, msg).with_status(status)
}

impl Server {
    pub fn register(&mut self, u: &User) {
        self.publics.insert(u.principal(), wire_public(&u.keyset.public));
        self.emails.insert(u.email.clone(), u.principal());
    }

    pub fn public_principal(&self, p: &str) -> PublicPrincipal {
        let k = &self.publics[p];
        PublicPrincipal {
            enc_pk: k.enc_pk.clone(),
            sign_pk: k.sign_pk.clone(),
            sig: k.sig.clone(),
            principal: p.to_owned(),
            email: None,
            name: None,
        }
    }

    pub fn lookup(&self, email: &str) -> PublicPrincipal {
        self.public_principal(&self.emails[email])
    }

    // ------------------------------------------------------------------- vaults

    pub fn create_vault(&mut self, caller: &str, req: &CreateVaultRequest) -> Result<Vault, OvError> {
        if !req.grants.iter().any(|g| g.principal == caller) {
            return Err(err(OvErrorCode::InvalidRequest, 400, "the caller must be a grantee"));
        }
        if let Some(org) = &req.org_id {
            for m in &self.members[org] {
                let p = user_principal(&m.user_id);
                let manager = matches!(m.role, OrgRole::Owner | OrgRole::Admin);
                if manager && m.status == MemberStatus::Confirmed && !req.grants.iter().any(|g| g.principal == p) {
                    return Err(err(OvErrorCode::InvalidRequest, 400, &format!("missing a manage grant for {p}")));
                }
            }
        }
        let mut access = BTreeMap::new();
        for g in &req.grants {
            assert_eq!(g.key_version, 1);
            access.insert(
                g.principal.clone(),
                AccessRow { role: Some(g.role.clone()), keys: [(1, g.sealed_key.clone())].into() },
            );
        }
        self.vaults.insert(
            req.id.clone(),
            ServerVault {
                org_id: req.org_id.clone(),
                encrypted_name: req.encrypted_name.clone(),
                current: 1,
                pending: None,
                rotation_required: false,
                access,
            },
        );
        // like the real server, the create answer leaves the keys out
        let mut v = self.vault(caller, &req.id).unwrap();
        v.keys.clear();
        Ok(v)
    }

    pub fn vault(&self, caller: &str, id: &str) -> Option<Vault> {
        let v = self.vaults.get(id)?;
        let row = v.access.get(caller)?;
        let role = row.role.clone()?;
        let mut keys: Vec<VaultKey> = row
            .keys
            .iter()
            .filter(|(ver, _)| **ver == v.current || Some(**ver) == v.pending)
            .map(|(ver, k)| VaultKey { key_version: *ver, sealed_key: k.clone() })
            .collect();
        keys.sort_by_key(|k| std::cmp::Reverse(k.key_version));
        Some(Vault {
            id: id.to_owned(),
            org_id: v.org_id.clone(),
            owner_id: None,
            encrypted_name: v.encrypted_name.clone(),
            role,
            current_key_version: v.current,
            pending_key_version: v.pending,
            rotation_required: Some(v.rotation_required),
            keys,
            created_at: None,
        })
    }

    pub fn list_vaults(&self, caller: &str) -> Vec<Vault> {
        self.vaults.keys().filter_map(|id| self.vault(caller, id)).collect()
    }

    pub fn list_access(&self, id: &str) -> Vec<VaultAccess> {
        self.vaults[id]
            .access
            .iter()
            .filter_map(|(p, r)| {
                Some(VaultAccess {
                    principal: p.clone(),
                    role: r.role.clone()?,
                    key_version: *r.keys.keys().max()?,
                    display: None,
                    granted_by: None,
                    granted_at: None,
                })
            })
            .collect()
    }

    pub fn grant_access(&mut self, caller: &str, id: &str, grants: &[Grant]) -> Result<(), OvError> {
        let v = self.vaults.get_mut(id).unwrap();
        if v.access.get(caller).and_then(|r| r.role.clone()) != Some(VaultRole::Manage) {
            return Err(err(OvErrorCode::Forbidden, 403, "needs manage"));
        }
        for g in grants {
            assert_eq!(g.key_version, v.current, "grants are at the current key version");
            let row = v.access.entry(g.principal.clone()).or_default();
            row.role = Some(g.role.clone());
            row.keys.insert(g.key_version, g.sealed_key.clone());
        }
        Ok(())
    }

    pub fn start_rotation(&mut self, id: &str, req: &StartRotationRequest) {
        let v = self.vaults.get_mut(id).unwrap();
        assert_eq!(req.key_version, v.current + 1);
        for p in req.remove.iter().flatten() {
            v.access.remove(p);
        }
        for g in &req.grants {
            let row = v.access.entry(g.principal.clone()).or_default();
            row.role = Some(g.role.clone());
            row.keys.insert(g.key_version, g.sealed_key.clone());
        }
        v.pending = Some(req.key_version);
    }

    pub fn activate(&mut self, id: &str, version: i64) {
        let v = self.vaults.get_mut(id).unwrap();
        assert_eq!(v.pending, Some(version));
        v.current = version;
        v.pending = None;
        v.rotation_required = false;
        for row in v.access.values_mut() {
            row.keys.retain(|ver, _| *ver >= version);
        }
    }

    pub fn rename(&mut self, id: &str, req: &RenameVaultRequest) {
        self.vaults.get_mut(id).unwrap().encrypted_name = req.encrypted_name.clone();
    }

    // ------------------------------------------------------------------- orgs

    pub fn create_org(&mut self, org: &str, owner: &User) {
        self.members.insert(org.to_owned(), vec![member(owner, OrgRole::Owner, MemberStatus::Confirmed)]);
    }

    pub fn add_member(&mut self, org: &str, u: &User) {
        self.members.get_mut(org).unwrap().push(member(u, OrgRole::Member, MemberStatus::Accepted));
    }

    pub fn find_member(&self, org: &str, user: &str) -> Member {
        self.members[org].iter().find(|m| m.user_id == user).unwrap().clone()
    }

    fn store_masters(&mut self, keys: &[SaMasterGrant]) {
        for k in keys {
            self.sas.get_mut(&k.sa_id).unwrap().masters.insert(k.principal.clone(), k.sealed_key.clone());
        }
    }

    pub fn confirm_member(&mut self, caller: &str, org: &str, user: &str, req: &ConfirmMemberRequest) -> Member {
        for g in req.grants.iter().flatten() {
            let grant = Grant {
                principal: g.principal.clone(),
                role: g.role.clone(),
                key_version: g.key_version,
                sealed_key: g.sealed_key.clone(),
            };
            self.grant_access(caller, &g.vault_id, &[grant]).unwrap();
        }
        self.store_masters(req.sa_master_keys.as_deref().unwrap_or_default());
        let m = self.members.get_mut(org).unwrap().iter_mut().find(|m| m.user_id == user).unwrap();
        m.status = MemberStatus::Confirmed;
        m.clone()
    }

    pub fn set_member_role(&mut self, org: &str, user: &str, req: &SetMemberRoleRequest) -> Member {
        self.store_masters(req.sa_master_keys.as_deref().unwrap_or_default());
        let m = self.members.get_mut(org).unwrap().iter_mut().find(|m| m.user_id == user).unwrap();
        m.role = req.role.clone();
        m.clone()
    }

    pub fn remove_member(&mut self, org: &str, user: &str) {
        self.members.get_mut(org).unwrap().retain(|m| m.user_id != user);
        let p = user_principal(user);
        for v in self.vaults.values_mut().filter(|v| v.org_id.as_deref() == Some(org)) {
            if v.access.remove(&p).is_some() {
                v.rotation_required = true;
            }
        }
        for sa in self.sas.values_mut() {
            sa.masters.remove(&p);
        }
    }

    // ------------------------------------------------------------------- service accounts

    pub fn create_sa(&mut self, org: &str, req: &CreateServiceAccountRequest) {
        let p = ov_vault::keys::sa_principal(&req.id);
        self.publics.insert(p, ov_vault::keys::public_of_wrapped(&req.keyset));
        let masters = req.master_keys.iter().map(|k| (k.principal.clone(), k.sealed_key.clone())).collect();
        let secrets = [(req.secret.secret_hash.clone(), req.secret.wrapped_master.clone())].into();
        self.sas.insert(
            req.id.clone(),
            ServerSa { org_id: org.to_owned(), name: req.name.clone(), keyset: req.keyset.clone(), masters, secrets },
        );
    }

    pub fn get_sa(&self, caller: &str, id: &str) -> ServiceAccount {
        let sa = &self.sas[id];
        ServiceAccount {
            id: id.to_owned(),
            org_id: sa.org_id.clone(),
            name: sa.name.clone(),
            public: Some(ov_vault::keys::public_of_wrapped(&sa.keyset)),
            keyset: None,
            master_key: sa.masters.get(caller).cloned(),
            created_by: None,
            created_at: None,
            expires_at: None,
            disabled: None,
        }
    }

    pub fn list_sas(&self, caller: &str, org: &str) -> Vec<ServiceAccount> {
        self.sas.iter().filter(|(_, s)| s.org_id == org).map(|(id, _)| self.get_sa(caller, id)).collect()
    }

    pub fn issue_secret(&mut self, sa: &str, body: &NewSaSecret) {
        self.sas.get_mut(sa).unwrap().secrets.insert(body.secret_hash.clone(), body.wrapped_master.clone());
    }

    pub fn exchange(&self, req: &ServiceAccountExchangeRequest) -> Result<ServiceAccountExchange, OvError> {
        let sa = self.sas.get(&req.sa_id).ok_or_else(|| err(OvErrorCode::Unauthorized, 401, "unknown SA"))?;
        let secret: [u8; 32] = from_b64u(&req.secret).unwrap().try_into().unwrap();
        let wrapped = sa
            .secrets
            .get(&sa_secret_hash(&secret))
            .ok_or_else(|| err(OvErrorCode::Unauthorized, 401, "bad secret"))?;
        Ok(ServiceAccountExchange {
            access_token: "jwt".into(),
            expires_in: 900,
            wrapped_master: wrapped.clone(),
            keyset: sa.keyset.clone(),
        })
    }
}

pub fn member(u: &User, role: OrgRole, status: MemberStatus) -> Member {
    Member {
        user_id: u.id.clone(),
        email: u.email.clone(),
        name: None,
        role,
        status,
        public: Some(wire_public(&u.keyset.public)),
    }
}

// ---------------------------------------------------------------------------- blobs

pub fn entry(db: &mut Database, title: &str, username: &str, password: &str) {
    let root = db.root.uuid;
    let data = EntryData {
        title: title.into(),
        username: username.into(),
        password_value: Zeroizing::new(password.into()),
        ..EntryData::default()
    };
    add_entry(db, root, &data, NOW).unwrap();
}

/// A new vault KDBX with entries `(title, username, password)`, saved under `key`.
pub fn vault_blob(name: &str, key: &[u8; 32], entries: &[(&str, &str, &str)]) -> Vec<u8> {
    let (mut db, ck) = create_vault_kdbx(name, key, NOW).unwrap();
    for (t, u, p) in entries {
        entry(&mut db, t, u, p);
    }
    ov_kdbx::write(&db, &ck).unwrap()
}

pub fn open(server: &Server, vault: &VaultKeys) -> Result<Database, OvError> {
    open_with_key_versions(&server.blobs[vault.id()], vault.keys()).map(|(db, _)| db)
}

/// The facade's rotation, step by step (SPEC §7).
pub fn rotate(server: &mut Server, me: &User, vault: &mut VaultKeys, remove: &[Principal]) {
    let access = server.list_access(vault.id());
    let plan = plan_rotation(vault, &me.principal(), &access, remove).unwrap();
    let others: Vec<PublicPrincipal> =
        plan.principals_needing_keys().iter().map(|p| server.public_principal(p)).collect();
    let req = plan.start_request(&me.keyset.public, &others).unwrap();
    server.start_rotation(vault.id(), &req);
    vault.add_key(plan.new_key());
    let mut db = open(server, vault).unwrap();
    let new_key: KeyVersion = plan.new_key();
    let ck = rekey_to_vault_key(&mut db, &new_key.key).unwrap();
    server.blobs.insert(vault.id().to_owned(), ov_kdbx::write(&db, &ck).unwrap());
    server.activate(vault.id(), i64::from(plan.key_version()));
    server.rename(vault.id(), &plan.rename_request(&vault.info.name).unwrap());
    vault.activate(plan.key_version());
}

pub fn b64(bytes: &[u8]) -> String {
    b64u(bytes)
}
