//! The `ov` command line, ported from `packages/cli/src/main.ts`. [`main`] returns the exit code:
//! 0 on success, 2 for bad usage (with the usage message), 1 for any other failure, or the child's
//! code for `ov run`.
//!
//! Every command runs on `ov-core`: a service account ([`ov_core::api::ServiceAccount`]) or the
//! user session saved by `ov login` ([`ov_core::api::Account`]), through [`Source`].

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ov_core::api::{
    default_share_fields, item_share_payload, shareable_fields, text_share_payload, CancelToken, CreateMode,
    FieldInput, ShareOptions,
};
use ov_core::host::{Clock, HttpTransport};
use ov_error::{OvError, OvErrorCode};

use crate::args::{parse, Parsed};
use crate::generate::{generate_password, parse_charsets};
use crate::item::{self, item_of, item_of_summary, Item, ShareJson};
use crate::reference::{format_reference, parse_item_reference, parse_reference};
use crate::run::{run_command, Out, RunOptions, STRIPPED_ENV};
use crate::session::{self, Env};
use crate::source::{pick_vault, Source};
use crate::template::{parse_env_file, read_reference, resolve_template};
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

/// Asks a question on the terminal (`hidden`: don't echo the answer). The TS `Prompt`.
pub type Prompt = Box<dyn FnMut(&str, bool) -> Result<String, OvError> + Send>;

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
    /// Asks on the terminal; `None` when there is none (stdin isn't a TTY).
    pub prompt: Option<Prompt>,
    /// Replaces the reqwest transport (the TS `fetch`; tests use the in-memory servers).
    pub http: Option<Arc<dyn HttpTransport>>,
    /// Replaces the system clock (tests use the in-memory servers' clock).
    pub clock: Option<Arc<dyn Clock>>,
}

impl Io {
    /// The real process: its environment, stdout, stderr and stdin, and the terminal for
    /// questions when stdin is one.
    pub fn process() -> Self {
        let env: Env = std::env::vars_os()
            .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
            .collect();
        let http = crate::http::test_relay(&env);
        let prompt: Option<Prompt> = if crate::tty::can_prompt() {
            Some(Box::new(|q: &str, hidden| crate::tty::prompt(q, hidden)))
        } else {
            None
        };
        Io {
            env,
            stdout: Arc::new(Mutex::new(Box::new(std::io::stdout()))),
            stderr: Arc::new(Mutex::new(Box::new(std::io::stderr()))),
            stdin: Box::new(|| {
                let mut bytes = Vec::new();
                std::io::stdin().read_to_end(&mut bytes)?;
                Ok(String::from_utf8_lossy(&bytes).into_owned())
            }),
            prompt,
            http,
            clock: None,
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

/// `writeFile(path, text, { mode: 0o600 })`: a new file is 0600 (an existing one keeps its mode).
fn write_file(path: &str, text: &str) -> Result<(), OvError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(|e| js::io_error(&e, "open", path))?;
    f.write_all(text.as_bytes()).map_err(|e| js::io_error(&e, "write", path))
}

fn read_stdin(io: &mut Io) -> Result<zeroize::Zeroizing<String>, OvError> {
    (io.stdin)().map(zeroize::Zeroizing::new).map_err(|e| OvError::internal(e.to_string()))
}

/// The lazily opened vault source (the TS `src()`), closed when dropped.
async fn source<'a>(slot: &'a mut Option<Source>, io: &mut Io) -> Result<&'a Source, OvError> {
    if slot.is_none() {
        *slot = Some(session::open_source(io).await?);
    }
    slot.as_ref().ok_or_else(|| OvError::internal("no vault source"))
}

async fn dispatch(argv: &[String], io: &mut Io) -> Result<i32, CliError> {
    let out = io.stdout.clone();
    let err = io.stderr.clone();
    let mut opened: Option<Source> = None;
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
            let src = source(&mut opened, io).await?;
            let value = zeroize::Zeroizing::new(read_reference(src, &p.positionals[0]).await?);
            match p.value("out-file").filter(|f| !f.is_empty()) {
                Some(f) => write_file(f, &value)?,
                None if p.flag("no-newline") => write(&out, &value),
                None => write(&out, &format!("{}\n", value.as_str())),
            }
            Ok(0)
        }

        "inject" => {
            let p = args_of(&["inject"], rest)?;
            if !p.positionals.is_empty() {
                return Err(usage("usage: ov inject [-i template] [-o file]"));
            }
            let template = match p.value("in-file").filter(|f| !f.is_empty()) {
                Some(f) => zeroize::Zeroizing::new(read_file(f)?),
                None => read_stdin(io)?,
            };
            let src = source(&mut opened, io).await?;
            let (text, _secrets) = resolve_template(src, &template).await?;
            let text = zeroize::Zeroizing::new(text);
            match p.value("out-file").filter(|f| !f.is_empty()) {
                Some(f) => write_file(f, &text)?,
                None => write(&out, &text),
            }
            Ok(0)
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
            env.sort();
            for f in p.values("env-file") {
                for (k, v) in parse_env_file(&read_file(f)?, f)? {
                    match env.iter_mut().find(|(ek, _)| *ek == k) {
                        Some(slot) => slot.1 = v,
                        None => env.push((k, v)),
                    }
                }
            }
            let mut secrets: Vec<String> = Vec::new();
            if env.iter().any(|(_, v)| v.contains("ov://")) {
                let src = source(&mut opened, io).await?;
                for (_, v) in env.iter_mut() {
                    if !v.contains("ov://") {
                        continue;
                    }
                    let (text, found) = resolve_template(src, v).await?;
                    *v = text;
                    secrets.extend(found);
                }
            }
            env.retain(|(k, _)| !STRIPPED_ENV.contains(&k.as_str()));
            // Lock before the child runs: it needs only the values, not the keys.
            drop(opened.take());
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
                let vault = source(&mut opened, io).await?.open(&p.positionals[0]).await?;
                let items: Vec<Item> = vault.entries(false).iter().map(item_of_summary).collect();
                if p.flag("json") {
                    write(&out, &item::json(&items));
                } else {
                    for i in &items {
                        write(&out, &format!("{}  {}\n", i.id, i.path()));
                    }
                }
                return Ok(0);
            }
            if !matches!(sub, "get" | "create" | "edit") {
                return Err(usage("usage: ov item get|list|create|edit …"));
            }
            let Some((ref_text, assigns)) = p.positionals.split_first() else {
                return Err(usage(format!("usage: ov item {sub} <ov://vault/[group/…]entry>")));
            };
            let r = parse_item_reference(ref_text)?;
            if sub == "get" {
                if !assigns.is_empty() {
                    return Err(usage("usage: ov item get <ov://vault/[group/…]entry> [--reveal] [--json]"));
                }
                let vault = source(&mut opened, io).await?.open(&r.vault).await?;
                let item = item_of(&vault.find(ref_text.clone())?, p.flag("reveal"));
                if p.flag("json") {
                    write(&out, &item::json(&item));
                } else {
                    write(&out, &item::describe(&item));
                }
                return Ok(0);
            }
            let mut fields = assignments(assigns)?;
            let mut set = |k: &str, v: String| match fields.iter_mut().find(|(ek, _)| ek == k) {
                Some(slot) => slot.1 = v,
                None => fields.push((k.to_string(), v)),
            };
            if let Some(f) = p.value("stdin-field").filter(|f| !f.is_empty()) {
                let text = read_stdin(io)?;
                set(f, strip_newline(&text).to_string());
            }
            if p.flag("generate") {
                set("Password", generated(&p)?.to_string());
            }
            if sub == "edit" && fields.is_empty() {
                return Err(usage("nothing to change: give field=value, --generate or --stdin-field"));
            }
            let src = source(&mut opened, io).await?;
            let vault = src.open_for_edit(&r.vault).await?;
            let mode = if sub == "create" { CreateMode::CreateOnly } else { CreateMode::MustExist };
            let inputs: Vec<FieldInput> = fields
                .into_iter()
                .map(|(name, value)| FieldInput { name, value: value.into_bytes(), protected: None })
                .collect();
            let changed = vault.set_fields(ref_text.clone(), inputs, mode)?;
            src.upload(&vault).await?;
            let item = item_of(&changed.entry, false);
            let verb = if sub == "create" { "Created" } else { "Updated" };
            write(&err, &format!("{verb} {} ({})\n", item.path(), item.id));
            if p.flag("json") {
                write(&out, &item::json(&item));
            }
            Ok(0)
        }

        "rotate" => {
            let p = args_of(&["rotate"], rest)?;
            if p.positionals.len() != 1 || p.flag("generate") == p.flag("stdin") {
                return Err(usage("usage: ov rotate <ov://vault/entry/field> (--generate | --stdin) [--print]"));
            }
            let r = parse_reference(&p.positionals[0])?;
            let value = if p.flag("generate") {
                generated(&p)?
            } else {
                let text = read_stdin(io)?;
                zeroize::Zeroizing::new(strip_newline(&text).to_string())
            };
            if value.is_empty() {
                return Err(usage("the new value is empty"));
            }
            let src = source(&mut opened, io).await?;
            let vault = src.open_for_edit(&r.vault).await?;
            vault.write_field(p.positionals[0].clone(), value.as_bytes().to_vec(), false, CancelToken::new()).await?;
            write(&err, &format!("Rotated {}\n", format_reference(&r)));
            if p.flag("print") {
                write(&out, &format!("{}\n", value.as_str()));
            }
            Ok(0)
        }

        "vault" => {
            let (sub, args) = rest.split_first().map_or(("", &[][..]), |(s, a)| (s.as_str(), a));
            let p = args_of(&["vault"], args)?;
            if sub != "list" {
                return Err(usage("usage: ov vault list [--json]"));
            }
            let vaults = source(&mut opened, io).await?.list_vaults().await?;
            if p.flag("json") {
                write(&out, &item::json(&vaults));
            } else {
                for v in &vaults {
                    write(&out, &format!("{}  {:<6}  {}\n", v.id, v.role, v.name));
                }
            }
            Ok(0)
        }

        "share" => share(rest, io, &mut opened).await,

        "login" => {
            let p = args_of(&["login"], rest)?;
            if !p.positionals.is_empty() {
                return Err(usage("usage: ov login [--issuer URL] [--email E]"));
            }
            let line = session::login(
                io,
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
            let line = session::logout(io, p.flag("forget")).await?;
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
                    let print_to = err.clone();
                    let mut print = move |line: &str| write(&print_to, &format!("{line}\n"));
                    let line = session::delete_account(io, p.flag("yes"), p.value("email").map(Into::into), &mut print)
                        .await?;
                    write(&err, &format!("{line}\n"));
                    Ok(0)
                }
                "restore" => {
                    if !args.is_empty() {
                        return Err(usage("usage: ov account restore"));
                    }
                    let line = session::restore_account(io).await?;
                    write(&err, &format!("{line}\n"));
                    Ok(0)
                }
                _ => Err(usage("usage: ov account delete|restore")),
            }
        }
        "whoami" => {
            for (k, v) in session::whoami(io).await? {
                write(&out, &format!("{k}: {v}\n"));
            }
            Ok(0)
        }

        "connect" => {
            let mut stderr = std::io::stderr();
            Ok(connect::connect(rest, &mut stderr))
        }

        other => Err(usage(format!("unknown command \"{other}\" (see ov help)"))),
    }
}

/// `--max-opens` / `--once`: `None` is unlimited.
fn max_opens(p: &Parsed) -> Result<Option<u32>, CliError> {
    let text = p.value("max-opens").filter(|v| !v.is_empty());
    if p.flag("once") && text.is_some() {
        return Err(usage("use --once or --max-opens, not both"));
    }
    if p.flag("once") {
        return Ok(Some(1));
    }
    let Some(t) = text else { return Ok(None) };
    match js::number(t).filter(|n| js::is_integer(*n)) {
        // The server refuses anything under 1; a count that doesn't fit is sent as the largest.
        Some(n) if n >= 0.0 => Ok(Some(if n > f64::from(u32::MAX) { u32::MAX } else { n as u32 })),
        Some(_) => Ok(Some(0)),
        None => Err(usage(format!("--max-opens must be a number: {t}"))),
    }
}

async fn share(rest: &[String], io: &mut Io, opened: &mut Option<Source>) -> Result<i32, CliError> {
    let out = io.stdout.clone();
    let err = io.stderr.clone();
    let p = args_of(&["share"], rest)?;
    let users_only =
        || OvError::new(OvErrorCode::Forbidden, "share links are made by users, not service accounts").with_status(403);
    match p.positionals.first().map(String::as_str) {
        Some("list") => {
            let src = source(opened, io).await?;
            let account = src.account().ok_or_else(users_only)?;
            let shares = account.list_shares(CancelToken::new()).await?;
            if p.flag("json") {
                let list: Vec<ShareJson<'_>> = shares.iter().map(ShareJson).collect();
                write(&out, &item::json(&list));
            } else {
                for sh in &shares {
                    let opens = match sh.max_opens {
                        None => format!("{} opens", sh.opens),
                        Some(m) => format!("{}/{m} opens", sh.opens),
                    };
                    let state = if sh.status == "ended" {
                        format!("ended ({})", sh.end_reason.as_deref().unwrap_or("null"))
                    } else {
                        format!("until {}", sh.expires_at)
                    };
                    let title = sh.reference.as_ref().map(|r| r.title.as_str()).filter(|t| !t.is_empty());
                    write(
                        &out,
                        &format!(
                            "{}  {}  {}  {state}\n",
                            sh.id,
                            pad_end(title.unwrap_or("(untitled)"), 24),
                            pad_end(&opens, 10)
                        ),
                    );
                }
            }
            return Ok(0);
        }
        Some("revoke") => {
            if p.positionals.len() != 2 {
                return Err(usage("usage: ov share revoke <id>"));
            }
            let src = source(opened, io).await?;
            let account = src.account().ok_or_else(users_only)?;
            account.revoke_share(p.positionals[1].clone(), CancelToken::new()).await?;
            write(&err, &format!("Revoked {}\n", p.positionals[1]));
            return Ok(0);
        }
        _ => {}
    }
    let text = p.flag("text");
    if (text && !p.positionals.is_empty()) || (!text && p.positionals.len() != 1) {
        return Err(usage(
            "usage: ov share <ov://vault/[group/…]entry> [options] | ov share --text [options] | ov share list | ov share revoke <id>",
        ));
    }
    let max_opens = max_opens(&p)?;
    let expires_in = duration(p.value("expires").unwrap_or("7d"))?;
    let src = source(opened, io).await?;
    let account = src.account().ok_or_else(users_only)?.clone();
    let (payload, vault_id, entry_id) = if text {
        let input = read_stdin(io)?;
        let body = strip_newline(&input);
        if body.is_empty() {
            return Err(usage("nothing to share: pipe the text to stdin"));
        }
        (text_share_payload(body.as_bytes().to_vec(), p.value("title").map(Into::into), None), None, None)
    } else {
        let r = parse_item_reference(&p.positionals[0])?;
        let vault = src.open(&r.vault).await?;
        let entry = vault.find(p.positionals[0].clone())?;
        let names: Vec<String> =
            if p.values("field").is_empty() { default_share_fields() } else { p.values("field").to_vec() };
        let known: Vec<String> = shareable_fields(entry.clone()).into_iter().map(|f| f.name).collect();
        let missing: Vec<&str> = names.iter().filter(|n| !known.contains(n)).map(String::as_str).collect();
        if !missing.is_empty() {
            let title = item_of(&entry, false).title;
            return Err(usage(format!("{title} has no {} to share", missing.join(", "))));
        }
        let all = src.list_vaults().await?;
        let vault_id = pick_vault(&all, &r.vault, "this account")?.id.clone();
        let entry_id = entry.id.clone();
        (item_share_payload(entry, names, None), Some(vault_id), Some(entry_id))
    };
    let mut passcode = None;
    if p.flag("passcode") {
        let code = match io.env.get("OPENVIREO_SHARE_PASSCODE") {
            Some(c) => Some(zeroize::Zeroizing::new(c.clone())),
            None => match io.prompt.as_mut() {
                Some(ask) => Some(zeroize::Zeroizing::new(ask("Passcode for the link: ", true)?)),
                None => None,
            },
        };
        match code.filter(|c| !c.is_empty()) {
            Some(c) => passcode = Some(c.as_bytes().to_vec()),
            None => return Err(usage("--passcode needs OPENVIREO_SHARE_PASSCODE or a terminal to ask on")),
        }
    }
    let expires_in = u32::try_from(expires_in).unwrap_or(u32::MAX);
    let share = account
        .create_share(payload, ShareOptions { expires_in, max_opens, passcode, vault_id, entry_id }, CancelToken::new())
        .await?;
    let opens = match max_opens {
        Some(0) | None => String::new(),
        Some(1) => ", opens once".to_string(),
        Some(n) => format!(", opens {n} times"),
    };
    write(&err, &format!("Expires {}{opens}. Anyone with the link can open it.\n", share.expires_at));
    let url = zeroize::Zeroizing::new(String::from_utf8_lossy(&share.url).into_owned());
    write(&out, &format!("{}\n", url.as_str()));
    Ok(0)
}

/// `String.prototype.padEnd` (counting UTF-16 code units, as JS does).
fn pad_end(s: &str, width: usize) -> String {
    let len = js::len(s);
    if len >= width {
        return s.to_string();
    }
    format!("{s}{}", " ".repeat(width - len))
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
