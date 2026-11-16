//! `ov connect`: runs `openvireo-connect` from `PATH` with the same arguments. The TS CLI linked
//! connect in; the Rust `ov` hands over to the separate binary (connect stays on the TS SDK,
//! rust-core.md Phase 6). On Unix it `exec`s, so signals and the exit code are connect's own; on
//! Windows it waits and exits with connect's code.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::process::Command;

/// The binary `ov connect` runs.
pub const CONNECT_BIN: &str = "openvireo-connect";

/// What `ov connect` prints when `openvireo-connect` isn't on `PATH`.
pub const INSTALL_HELP: &str = "ov: `ov connect` runs openvireo-connect, which isn't installed (not found on PATH).
Install it from https://github.com/OpenVireo/openvireo-sdk/releases (openvireo-connect-<version>-<platform>),
or with Node 20+: npm install -g @openvireo/connect
";

/// Runs connect; returns the exit code to use when it couldn't take over the process.
pub fn connect(args: &[String], stderr: &mut dyn std::io::Write) -> i32 {
    run(OsString::from(CONNECT_BIN), args, stderr)
}

fn report(e: &std::io::Error, stderr: &mut dyn std::io::Write) -> i32 {
    let _ = if e.kind() == ErrorKind::NotFound {
        stderr.write_all(INSTALL_HELP.as_bytes())
    } else {
        writeln!(stderr, "ov: can't run {CONNECT_BIN}: {e}")
    };
    1
}

#[cfg(unix)]
fn run(bin: OsString, args: &[String], stderr: &mut dyn std::io::Write) -> i32 {
    use std::os::unix::process::CommandExt;
    // `exec` only returns on failure.
    let e = Command::new(bin).args(args).exec();
    report(&e, stderr)
}

#[cfg(not(unix))]
fn run(bin: OsString, args: &[String], stderr: &mut dyn std::io::Write) -> i32 {
    match Command::new(bin).args(args).status() {
        Ok(status) => status.code().unwrap_or(1),
        Err(e) => report(&e, stderr),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prints_install_help_when_missing() {
        let mut err = Vec::new();
        let code = run(OsString::from("openvireo-connect-definitely-not-installed"), &[], &mut err);
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8(err).unwrap(), INSTALL_HELP);
    }
}
