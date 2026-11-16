//! The `ov` command line, ported from `packages/cli/src/main.ts`. [`main`] returns the exit code:
//! 0 on success, 2 for bad usage (with the usage message), 1 for any other failure, or the child's
//! code for `ov run`.
//!
//! Commands that need `ov-core` parse and check their arguments exactly as the TS does, run the
//! checks that come before the core (no session, no token, bad references, bad option values),
//! and then stop with a "not implemented yet (W3-L3)" error (exit 1).

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ov_error::{OvError, OvErrorCode};

use crate::args::{parse, Parsed};
use crate::generate::{generate_password, parse_charsets};
use crate::reference::{parse_item_reference, parse_reference};
use crate::run::{run_command, Out, RunOptions, STRIPPED_ENV};
use crate::session::{self, Env};
use crate::template::parse_env_file;
use crate::{connect, js};

/// `USAGE`, byte for byte the TS CLI's (checked against `tests/golden/help.txt`).
pub const USAGE: &str = concat!(
    "ov ",
    version!(),
    r#": OpenVireo vault secrets for scripts, CI and servers

Usage:
  ov read <ov://vault/[group/…]entry/field> [-n] [-o file]
  ov inject [-i template] [-o file]          replace ov:// references ({{ ov://… }} or bare)
  ov run [--env-file .env.tpl]… [--no-masking] -- <command> [args…]
  ov item get <ov://vault/[group/…]entry> [--reveal] [--json]
  ov item list <vault> [--json]
  ov item create <ov://vault/[group/…]title> [field=value…] [--generate [--length N] [--charset S]] [--stdin-field F]
  ov item edit <ov://vault/[group/…]entry> [field=value…] [--generate [--length N] [--charset S]] [--stdin-field F]
  ov rotate <ov://vault/[group/…]entry/field> (--generate [--length N] [--charset S] | --stdin) [--print]
  ov vault list [--json]
  ov share <ov://vault/[group/…]entry> [--field F]… [--expires 7d] [--once | --max-opens N] [--passcode]
  ov share --text [--title T] [--expires 7d] [--once | --max-opens N] [--passcode]   text from stdin
  ov share list [--json]
  ov share revoke <id>                       share links open without an account (users only)
  ov login [--issuer URL] [--email E] [--secret-key K1-…]
  ov logout [--forget]                       --forget also removes the Secret Key from this machine
  ov whoami
  ov account delete [--yes --email E]        lock the account and erase it after 30 days
  ov account restore                         keep an account scheduled for deletion
  ov connect [serve | token …]               the REST server (see ov connect --help)
  ov version

Credentials: OPENVIREO_SERVICE_ACCOUNT_TOKEN (or OPENVIREO_SERVICE_ACCOUNT_TOKEN_FILE), else the session from
`ov login` unlocked with OPENVIREO_PASSWORD or a prompt. Charsets: letters, lower, upper, digits, symbols.
"#
);

/// The process around [`main`] (the TS `CliIo`).
pub struct Io {
    /// The environment.
    pub env: Env,
    /// Standard output.
    pub stdout: Out,
    /// Standard error.
    pub stderr: Out,
    /// Reads all of stdin.
    pub stdin: Box<dyn FnMut() -> std::io::Result<String> + Send>,
}

impl Io {
    /// The real process: its environment, stdout, stderr and stdin.
    pub fn process() -> Self {
        let env = std::env::vars_os()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
            .collect();
        Io {
            env,
            stdout: Arc::new(Mutex::new(Box::new(std::io::stdout()))),
            stderr: Arc::new(Mutex::new(Box::new(std::io::stderr()))),
            stdin: Box::new(|| {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)?;
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }),
        }
    }
}

/// Why a command failed.
#[derive(Debug)]
pub enum CliError {
    /// Bad usage: `ov: <message>`, exit 2.
    Usage(String),
    /// Anything else: `ov: <message>`, exit 1.
    Failed(OvError),
}

impl From<OvError> for CliError {
    fn from(e: OvError) -> Self {
        CliError::Failed(e)
    }
}

fn usage(msg: impl Into<String>) -> CliError {
    CliError::Usage(msg.into())
}

fn read_file(path: &str) -> Result<String, OvError> {
    let bytes = std::fs::read(path).map_err(|e| js::io_error(&e, "open", path))?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn args_of(p: &[&str], rest: &[String]) -> Result<Parsed, CliError> {
    parse(p, rest).map_err(CliError::Usage)
}

/// `stripNewline`: one trailing `\n` or `\r\n`.
fn strip_newline(s: &str) -> &str {
    s.strip_suffix("\r\n").or_else(|| s.strip_suffix('\n')).unwrap_or(s)
}

/// `generated(values)`: a password from `--length` / `--charset`.
fn generated(p: &Parsed) -> Result<zeroize::Zeroizing<String>, CliError> {
    let length = match p.value("length") {
        None => None,
        Some(text) => match js::number(text).filter(|n| js::is_integer(*n)) {
            Some(n) => Some(n),
            None => return Err(usage(format!("--length must be a number: {text}"))),
        },
    };
    let charsets = match p.value("charset").filter(|c| !c.is_empty()) {
        Some(spec) => Some(parse_charsets(spec)?),
        None => None,
    };
    Ok(generate_password(length, charsets.as_deref())?)
}

/// `assignments`: `field=value` pairs, in order (a repeated field keeps its first place).
fn assignments(list: &[String]) -> Result<Vec<(String, String)>, CliError> {
    let mut out: Vec<(String, String)> = Vec::new();
    for a in list {
        match a.find('=') {
            Some(i) if i > 0 => {
                let (k, v) = (a[..i].to_string(), a[i + 1..].to_string());
                match out.iter_mut().find(|(ek, _)| *ek == k) {
                    Some(slot) => slot.1 = v,
                    None => out.push((k, v)),
                }
            }
            _ => return Err(usage(format!("expected field=value, got \"{a}\""))),
        }
    }
    Ok(out)
}

/// `duration`: `1h`, `7d`, `30d` → seconds.
fn duration(text: &str) -> Result<u64, CliError> {
    let t = js::trim(text);
    let bad = || usage(format!("--expires takes hours or days, like 1h or 7d: {text}"));
    let unit = t.chars().last().ok_or_else(bad)?;
    let digits = &t[..t.len() - unit.len_utf8()];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || !matches!(unit, 'h' | 'd') {
        return Err(bad());
    }
    let n: f64 = digits.parse().map_err(|_| bad())?;
    let secs = n * if unit == 'h' { 3600.0 } else { 86400.0 };
    Ok(if secs > u64::MAX as f64 { u64::MAX } else { secs as u64 })
}

fn write(out: &Out, s: &str) {
    if let Ok(mut w) = out.lock() {
        let _ = w.write_all(s.as_bytes());
        let _ = w.flush();
    }
}

/// Runs `ov` with `argv` (without the program name) and returns the exit code.
pub async fn main(argv: &[String], io: &mut Io) -> i32 {
    match dispatch(argv, io).await {
        Ok(code) => code,
        Err(CliError::Usage(m)) => {
            write(&io.stderr, &format!("ov: {m}\n"));
            2
        }
        Err(CliError::Failed(e)) => {
            // Never anything that could hold a secret: only the message.
            write(&io.stderr, &format!("ov: {}\n", e.message));
            1
        }
    }
}

async fn dispatch(argv: &[String], io: &mut Io) -> Result<i32, CliError> {
    let out = io.stdout.clone();
    let err = io.stderr.clone();
    let Some((cmd, rest)) = argv.split_first() else {
        write(&out, USAGE);
        return Ok(2);
    };
    match cmd.as_str() {
        "help" | "-h" | "--help" => {
            write(&out, USAGE);
            Ok(0)
        }
        "version" | "--version" => {
            write(&out, &format!("ov {}\n", session::VERSION));
            Ok(0)
        }

        "read" => {
            let p = args_of(&["read"], rest)?;
            if p.positionals.len() != 1 {
                return Err(usage("usage: ov read <ov://vault/entry/field>"));
            }
            // TODO(W3-L3): readReference, then write to -o (mode 0600) or stdout (+ "\n" unless -n).
            match session::open_source(&io.env).await? {}
        }

        "inject" => {
            let p = args_of(&["inject"], rest)?;
            if !p.positionals.is_empty() {
                return Err(usage("usage: ov inject [-i template] [-o file]"));
            }
            let _template = match p.value("in-file").filter(|f| !f.is_empty()) {
                Some(f) => read_file(f)?,
                None => (io.stdin)().map_err(|e| OvError::internal(e.to_string()))?,
            };
            // TODO(W3-L3): resolve_template(src, template), then write to -o (mode 0600) or stdout.
            match session::open_source(&io.env).await? {}
        }

        "run" => {
            let dash = rest.iter().position(|a| a == "--");
            let opts = dash.map_or(rest, |d| &rest[..d]);
            let p = args_of(&["run"], opts)?;
            let mut command = p.positionals.clone();
            if let Some(d) = dash {
                command.extend(rest[d + 1..].iter().cloned());
            }
            if command.is_empty() {
                return Err(usage("usage: ov run [--env-file file]… -- <command> [args…]"));
            }
            let mut env: Vec<(String, String)> = io.env.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
            for f in p.values("env-file") {
                for (k, v) in parse_env_file(&read_file(f)?, f)? {
                    match env.iter_mut().find(|(ek, _)| *ek == k) {
                        Some(slot) => slot.1 = v,
                        None => env.push((k, v)),
                    }
                }
            }
            let secrets: Vec<String> = Vec::new();
            if env.iter().any(|(_, v)| v.contains("ov://")) {
                // TODO(W3-L3): resolve_template for each value holding ov://, collecting secrets.
                match session::open_source(&io.env).await? {}
            }
            env.retain(|(k, _)| !STRIPPED_ENV.contains(&k.as_str()));
            let code = run_command(RunOptions {
                command: command[0].clone(),
                args: command[1..].to_vec(),
                env,
                secrets: if p.flag("no-masking") { None } else { Some(secrets) },
                stdout: out,
                stderr: err,
                hold: Duration::from_millis(100),
            })
            .await
            .map_err(|m| OvError::new(OvErrorCode::Internal, m))?;
            Ok(code)
        }

        "item" => {
            let (sub, args) = rest.split_first().map_or(("", &[][..]), |(s, a)| (s.as_str(), a));
            let p = args_of(&["item"], args)?;
            if sub == "list" {
                if p.positionals.len() != 1 {
                    return Err(usage("usage: ov item list <vault>"));
                }
                // TODO(W3-L3): listItems; --json or "<id>  <group/…/title>" lines.
                match session::open_source(&io.env).await? {}
            }
            if !matches!(sub, "get" | "create" | "edit") {
                return Err(usage("usage: ov item get|list|create|edit …"));
            }
            let Some((ref_text, assigns)) = p.positionals.split_first() else {
                return Err(usage(format!("usage: ov item {sub} <ov://vault/[group/…]entry>")));
            };
            let _item = parse_item_reference(ref_text)?;
            if sub == "get" {
                if !assigns.is_empty() {
                    return Err(usage("usage: ov item get <ov://vault/[group/…]entry> [--reveal] [--json]"));
                }
                // TODO(W3-L3): itemOf(findEntry(…), {reveal}); --json or the field listing.
                match session::open_source(&io.env).await? {}
            }
            let mut fields = assignments(assigns)?;
            let mut set = |k: &str, v: String| match fields.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v,
                None => fields.push((k.to_string(), v)),
            };
            if let Some(f) = p.value("stdin-field").filter(|f| !f.is_empty()) {
                let text = (io.stdin)().map_err(|e| OvError::internal(e.to_string()))?;
                set(f, strip_newline(&text).to_string());
            }
            if p.flag("generate") {
                set("Password", generated(&p)?.to_string());
            }
            if sub == "edit" && fields.is_empty() {
                return Err(usage("nothing to change: give field=value, --generate or --stdin-field"));
            }
            // TODO(W3-L3): s.edit(vault, setItemFields(…, {create: sub == "create" ? "only" : false})),
            // then "Created|Updated <path> (<id>)" on stderr and --json on stdout.
            match session::open_source(&io.env).await? {}
        }

        "rotate" => {
            let p = args_of(&["rotate"], rest)?;
            if p.positionals.len() != 1 || p.flag("generate") == p.flag("stdin") {
                return Err(usage("usage: ov rotate <ov://vault/entry/field> (--generate | --stdin) [--print]"));
            }
            let _r = parse_reference(&p.positionals[0])?;
            let value = if p.flag("generate") {
                generated(&p)?
            } else {
                let text = (io.stdin)().map_err(|e| OvError::internal(e.to_string()))?;
                zeroize::Zeroizing::new(strip_newline(&text).to_string())
            };
            if value.is_empty() {
                return Err(usage("the new value is empty"));
            }
            // TODO(W3-L3): writeField, then "Rotated <ref>" on stderr and the value with --print.
            match session::open_source(&io.env).await? {}
        }

        "vault" => {
            let (sub, args) = rest.split_first().map_or(("", &[][..]), |(s, a)| (s.as_str(), a));
            let _p = args_of(&["vault"], args)?;
            if sub != "list" {
                return Err(usage("usage: ov vault list [--json]"));
            }
            // TODO(W3-L3): listVaults; --json or "<id>  <role padded to 6>  <name>" lines.
            match session::open_source(&io.env).await? {}
        }

        "share" => share(rest, io).await,

        "login" => {
            let p = args_of(&["login"], rest)?;
            if !p.positionals.is_empty() {
                return Err(usage("usage: ov login [--issuer URL] [--email E]"));
            }
            let line = session::login(
                &io.env,
                p.value("issuer").map(Into::into),
                p.value("email").map(Into::into),
                p.value("secret-key").map(Into::into),
            )
            .await?;
            write(&err, &format!("{line}\n"));
            Ok(0)
        }
        "logout" => {
            let p = args_of(&["logout"], rest)?;
            if !p.positionals.is_empty() {
                return Err(usage("usage: ov logout [--forget]"));
            }
            let line = session::logout(&io.env, p.flag("forget")).await?;
            write(&err, &format!("{line}\n"));
            Ok(0)
        }
        "account" => {
            let (sub, args) = rest.split_first().map_or(("", &[][..]), |(s, a)| (s.as_str(), a));
            match sub {
                "delete" => {
                    let p = args_of(&["account", "delete"], args)?;
                    if !p.positionals.is_empty() {
                        return Err(usage("usage: ov account delete [--yes --email E]"));
                    }
                    // TODO(W3-L3): deleteAccount (preview lines on stderr, confirmation prompt).
                    match session::unlocked_user(&io.env).await? {}
                }
                "restore" => {
                    if !args.is_empty() {
                        return Err(usage("usage: ov account restore"));
                    }
                    // TODO(W3-L3): restoreAccount.
                    match session::unlocked_user(&io.env).await? {}
                }
                _ => Err(usage("usage: ov account delete|restore")),
            }
        }
        "whoami" => {
            for (k, v) in session::whoami(&io.env).await? {
                write(&out, &format!("{k}: {v}\n"));
            }
            Ok(0)
        }

        "connect" => {
            write(&out, "");
            let mut stderr = std::io::stderr();
            Ok(connect::connect(rest, &mut stderr))
        }

        other => Err(usage(format!("unknown command \"{other}\" (see ov help)"))),
    }
}

async fn share(rest: &[String], io: &mut Io) -> Result<i32, CliError> {
    let p = args_of(&["share"], rest)?;
    match p.positionals.first().map(String::as_str) {
        Some("list") => {
            // TODO(W3-L3): listShares; --json or "<id>  <title padded to 24>  <opens>  <state>" lines.
            match session::open_source(&io.env).await? {}
        }
        Some("revoke") => {
            if p.positionals.len() != 2 {
                return Err(usage("usage: ov share revoke <id>"));
            }
            // TODO(W3-L3): revokeShare, then "Revoked <id>" on stderr.
            match session::open_source(&io.env).await? {}
        }
        _ => {}
    }
    let text = p.flag("text");
    if (text && !p.positionals.is_empty()) || (!text && p.positionals.len() != 1) {
        return Err(usage(
            "usage: ov share <ov://vault/[group/…]entry> [options] | ov share --text [options] | ov share list | ov share revoke <id>",
        ));
    }
    let max_opens_text = p.value("max-opens").filter(|v| !v.is_empty());
    if p.flag("once") && max_opens_text.is_some() {
        return Err(usage("use --once or --max-opens, not both"));
    }
    let _max_opens = if p.flag("once") {
        Some(1.0)
    } else if let Some(t) = max_opens_text {
        match js::number(t).filter(|n| js::is_integer(*n)) {
            Some(n) => Some(n),
            None => return Err(usage(format!("--max-opens must be a number: {t}"))),
        }
    } else {
        None
    };
    let _expires_in = duration(p.value("expires").unwrap_or("7d"))?;
    // TODO(W3-L3): the share itself: text from stdin or the item's fields, --passcode
    // (OPENVIREO_SHARE_PASSCODE or a prompt), createShare, "Expires …" on stderr, the URL on stdout.
    match session::open_source(&io.env).await? {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_helpers_match_the_ts() {
        assert_eq!(strip_newline("a\r\n"), "a");
        assert_eq!(strip_newline("a\n\n"), "a\n");
        assert_eq!(strip_newline("a\r"), "a\r");
        assert_eq!(duration("7d").unwrap(), 604_800);
        assert_eq!(duration(" 1h ").unwrap(), 3600);
        assert!(
            matches!(duration("3w"), Err(CliError::Usage(m)) if m == "--expires takes hours or days, like 1h or 7d: 3w")
        );
        assert!(duration("h").is_err() && duration("").is_err() && duration("1.5h").is_err());
        assert_eq!(
            assignments(&["a=b=c".into(), "x=".into()]).unwrap(),
            vec![("a".into(), "b=c".into()), ("x".into(), String::new())]
        );
        assert!(
            matches!(assignments(&["=x".into()]), Err(CliError::Usage(m)) if m == "expected field=value, got \"=x\"")
        );
        let e = js::io_error(&std::io::Error::from(std::io::ErrorKind::NotFound), "open", "x.env");
        assert_eq!(e.message, "ENOENT: no such file or directory, open 'x.env'");
    }
}
