//! The implementation behind the facade (`crate::api`). The facade only orchestrates; the logic
//! lives in the domain crates, reached through these modules.

pub(crate) mod account;
pub(crate) mod convert;
pub(crate) mod kdbx_ops;
pub(crate) mod net;
pub(crate) mod plan;
pub(crate) mod remembered;
pub(crate) mod settings;
pub(crate) mod share;
pub(crate) mod signin;
pub(crate) mod vaults;
pub(crate) mod client;
pub(crate) mod sync_glue;
pub(crate) mod tokens;
pub(crate) mod util;
pub(crate) mod vault_glue;
