//! The `ov` command tree in clap, with the TS CLI's argument rules.
//!
//! The TS CLI parses each command's arguments with Node's `util.parseArgs` (`strict: true`,
//! `allowPositionals: true`) and reports bad usage with Node's messages and exit code 2. To keep
//! every message identical, [`parse`] first runs [`node_check`], a port of the parts of
//! `parseArgs` that reject input (unknown options, missing or ambiguous values, a value given to a
//! boolean), and only then lets clap collect the values from the tree in [`command_tree`].
//!
//! The top level isn't parsed by clap: like the TS `switch`, `ov` with no command prints the usage
//! (exit 2), `help`/`-h`/`--help` print it (exit 0), and anything unknown is a usage error.

use std::collections::HashMap;

use clap::{Arg, ArgAction, Command};

/// What an option takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A flag (`type: "boolean"`).
    Bool,
    /// One value; the last one given wins (`type: "string"`).
    Str,
    /// A value that may repeat (`type: "string", multiple: true`).
    Multi,
}

/// One option of a command, as in the TS `parseArgs` options object.
#[derive(Clone, Copy, Debug)]
pub struct Opt {
    /// The long name, without `--`.
    pub long: &'static str,
    /// The short letter, if any.
    pub short: Option<char>,
    /// What it takes.
    pub kind: Kind,
}

const fn b(long: &'static str) -> Opt {
    Opt { long, short: None, kind: Kind::Bool }
}
const fn s(long: &'static str) -> Opt {
    Opt { long, short: None, kind: Kind::Str }
}
const fn m(long: &'static str) -> Opt {
    Opt { long, short: None, kind: Kind::Multi }
}

/// `ov read`.
pub const READ: &[Opt] = &[
    Opt { long: "no-newline", short: Some('n'), kind: Kind::Bool },
    Opt { long: "out-file", short: Some('o'), kind: Kind::Str },
];
/// `ov inject`.
pub const INJECT: &[Opt] = &[
    Opt { long: "in-file", short: Some('i'), kind: Kind::Str },
    Opt { long: "out-file", short: Some('o'), kind: Kind::Str },
];
/// `ov run` (the part before `--`).
pub const RUN: &[Opt] = &[m("env-file"), b("no-masking")];
/// `ov item …` (`ITEM_OPTIONS`, shared by every item subcommand).
pub const ITEM: &[Opt] = &[b("generate"), s("length"), s("charset"), s("stdin-field"), b("reveal"), b("json")];
/// `ov rotate`.
pub const ROTATE: &[Opt] = &[b("generate"), s("length"), s("charset"), b("stdin"), b("print")];
/// `ov vault …`.
pub const VAULT: &[Opt] = &[b("json")];
/// `ov share …` (`SHARE_OPTIONS`).
pub const SHARE: &[Opt] =
    &[m("field"), s("expires"), b("once"), s("max-opens"), b("passcode"), b("text"), s("title"), b("json")];
/// `ov login`.
pub const LOGIN: &[Opt] = &[s("issuer"), s("email"), s("secret-key")];
/// `ov logout`.
pub const LOGOUT: &[Opt] = &[b("forget")];
/// `ov account delete`.
pub const ACCOUNT_DELETE: &[Opt] = &[b("yes"), s("email")];

/// The id of the positionals in every leaf command.
const POSITIONALS: &str = "positionals";

fn leaf(name: &'static str, opts: &[Opt]) -> Command {
    let mut c = Command::new(name)
        .no_binary_name(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .disable_help_subcommand(true)
        .args_override_self(true)
        .arg(Arg::new(POSITIONALS).num_args(0..).action(ArgAction::Append).value_name("args"));
    for o in opts {
        let mut a = Arg::new(o.long).long(o.long);
        if let Some(sh) = o.short {
            a = a.short(sh);
        }
        a = match o.kind {
            Kind::Bool => a.action(ArgAction::SetTrue),
            Kind::Str => a.action(ArgAction::Set).value_name("value").num_args(1).allow_hyphen_values(true),
            Kind::Multi => a.action(ArgAction::Append).value_name("value").num_args(1).allow_hyphen_values(true),
        };
        c = c.arg(a);
    }
    c
}

/// A command whose arguments are passed on untouched (`ov connect`, `ov account restore`).
fn raw(name: &'static str) -> Command {
    Command::new(name).no_binary_name(true).disable_help_flag(true).disable_version_flag(true).arg(
        Arg::new(POSITIONALS).num_args(0..).action(ArgAction::Append).allow_hyphen_values(true).trailing_var_arg(true),
    )
}

/// The whole tree, matching `USAGE`. Each leaf parses the arguments after its name (and, for
/// `item`, `vault` and `share`, after the first word, which the TS reads as a subcommand or
/// positional itself).
pub fn command_tree() -> Command {
    Command::new("ov").disable_help_flag(true).disable_version_flag(true).disable_help_subcommand(true).subcommands([
        leaf("read", READ),
        leaf("inject", INJECT),
        leaf("run", RUN),
        leaf("item", ITEM),
        leaf("rotate", ROTATE),
        leaf("vault", VAULT),
        leaf("share", SHARE),
        leaf("login", LOGIN),
        leaf("logout", LOGOUT),
        leaf("whoami", &[]),
        Command::new("account").subcommands([leaf("delete", ACCOUNT_DELETE), raw("restore")]),
        raw("connect"),
        leaf("version", &[]),
        leaf("help", &[]),
    ])
}

/// The values of one parse: options by long name, and the positionals.
#[derive(Debug, Default)]
pub struct Parsed {
    values: HashMap<&'static str, Vec<String>>,
    flags: HashMap<&'static str, bool>,
    /// The positionals, in order.
    pub positionals: Vec<String>,
}

impl Parsed {
    /// A boolean option.
    pub fn flag(&self, long: &str) -> bool {
        self.flags.get(long).copied().unwrap_or(false)
    }
    /// A string option (the last one given).
    pub fn value(&self, long: &str) -> Option<&str> {
        self.values.get(long).and_then(|v| v.last()).map(String::as_str)
    }
    /// A string option that may repeat (empty when not given).
    pub fn values(&self, long: &str) -> &[String] {
        self.values.get(long).map_or(&[], Vec::as_slice)
    }
}

fn short_and_long(o: &Opt) -> String {
    match o.short {
        Some(sh) => format!("-{sh}, --{}", o.long),
        None => format!("--{}", o.long),
    }
}

/// One option occurrence, as Node's tokenizer sees it.
struct Token<'a> {
    opt: Option<&'a Opt>,
    raw_name: String,
    value: Option<String>,
    inline_value: bool,
}

/// Node's `parseArgs` checks, in its order: the first offending option wins. Returns the message
/// Node would throw, if any.
pub fn node_check(args: &[String], opts: &[Opt]) -> Option<String> {
    let by_short = |c: char| opts.iter().find(|o| o.short == Some(c));
    let by_long = |l: &str| opts.iter().find(|o| o.long == l);
    let is_str = |o: Option<&Opt>| o.is_some_and(|o| o.kind != Kind::Bool);

    let mut remaining: std::collections::VecDeque<String> = args.iter().cloned().collect();
    let mut tokens: Vec<Token<'_>> = Vec::new();
    while let Some(arg) = remaining.pop_front() {
        if arg == "--" {
            break; // everything after is positional
        }
        let chars: Vec<char> = arg.chars().collect();
        let is_short_like = chars.len() >= 2 && chars[0] == '-' && chars[1] != '-';
        if is_short_like && chars.len() == 2 {
            // lone short option
            let opt = by_short(chars[1]);
            let raw_name = arg.clone();
            let value = if is_str(opt) { remaining.pop_front() } else { None };
            tokens.push(Token { opt, raw_name, value, inline_value: false });
        } else if is_short_like && !is_str(by_short(chars[1])) {
            // short option group: expand and re-process
            let mut expanded = Vec::new();
            for (i, c) in chars.iter().enumerate().skip(1) {
                if !is_str(by_short(*c)) || i == chars.len() - 1 {
                    expanded.push(format!("-{c}"));
                } else {
                    expanded.push(format!("-{c}"));
                    expanded.push(chars[i + 1..].iter().collect());
                    break;
                }
            }
            for e in expanded.into_iter().rev() {
                remaining.push_front(e);
            }
        } else if is_short_like {
            // short option with its value attached: -ofile
            let opt = by_short(chars[1]);
            tokens.push(Token {
                opt,
                raw_name: format!("-{}", chars[1]),
                value: Some(chars[2..].iter().collect()),
                inline_value: true,
            });
        } else if arg.len() > 2 && arg.starts_with("--") {
            match arg.char_indices().find(|(i, c)| *i >= 3 && *c == '=').map(|(i, _)| i) {
                Some(eq) => {
                    let name = &arg[2..eq];
                    tokens.push(Token {
                        opt: by_long(name),
                        raw_name: format!("--{name}"),
                        value: Some(arg[eq + 1..].to_string()),
                        inline_value: true,
                    });
                }
                None => {
                    let opt = by_long(&arg[2..]);
                    let value = if is_str(opt) { remaining.pop_front() } else { None };
                    tokens.push(Token { opt, raw_name: arg.clone(), value, inline_value: false });
                }
            }
        }
        // anything else is a positional
    }

    for t in tokens {
        let Some(o) = t.opt else {
            return Some(format!(
                "Unknown option '{0}'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"{0}\"",
                t.raw_name
            ));
        };
        match (o.kind, &t.value) {
            (Kind::Bool, Some(_)) => return Some(format!("Option '{}' does not take an argument", short_and_long(o))),
            (Kind::Str | Kind::Multi, None) => {
                return Some(format!("Option '{} <value>' argument missing", short_and_long(o)))
            }
            _ => {}
        }
        if let Some(v) = &t.value {
            if !t.inline_value && v.chars().count() > 1 && v.starts_with('-') {
                let alt = match o.short {
                    Some(sh) if !t.raw_name.starts_with("--") => format!(" or '-{sh}-XYZ'"),
                    _ => String::new(),
                };
                return Some(format!(
                    "Option '{0}' argument is ambiguous.\nDid you forget to specify the option argument for '{0}'?\nTo specify an option argument starting with a dash use '--{1}=-XYZ'{alt}.",
                    t.raw_name, o.long
                ));
            }
        }
    }
    None
}

/// Parses `args` against the leaf at `path` in [`command_tree`] (e.g. `["account", "delete"]`).
/// `Err` holds the usage message (exit code 2).
pub fn parse(path: &[&str], args: &[String]) -> Result<Parsed, String> {
    let tree = command_tree();
    let mut cmd = &tree;
    for p in path {
        cmd = cmd.find_subcommand(p).ok_or_else(|| format!("no command {p}"))?;
    }
    let opts = options_for(path);
    if let Some(msg) = node_check(args, opts) {
        return Err(msg);
    }
    let matches = cmd.clone().try_get_matches_from(args).map_err(|e| e.kind().to_string())?;
    let mut parsed = Parsed {
        positionals: matches.get_many::<String>(POSITIONALS).map(|v| v.cloned().collect()).unwrap_or_default(),
        ..Parsed::default()
    };
    for o in opts {
        match o.kind {
            Kind::Bool => {
                parsed.flags.insert(o.long, matches.get_flag(o.long));
            }
            Kind::Str | Kind::Multi => {
                if let Some(v) = matches.get_many::<String>(o.long) {
                    parsed.values.insert(o.long, v.cloned().collect());
                }
            }
        }
    }
    Ok(parsed)
}

/// The option table for a leaf.
pub fn options_for(path: &[&str]) -> &'static [Opt] {
    match path {
        ["read"] => READ,
        ["inject"] => INJECT,
        ["run"] => RUN,
        ["item"] => ITEM,
        ["rotate"] => ROTATE,
        ["vault"] => VAULT,
        ["share"] => SHARE,
        ["login"] => LOGIN,
        ["logout"] => LOGOUT,
        ["account", "delete"] => ACCOUNT_DELETE,
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(args: &[&str]) -> Vec<String> {
        args.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_tree_is_valid_and_matches_usage() {
        command_tree().debug_assert();
        let usage = crate::cli::USAGE;
        let tree = command_tree();
        for sub in tree.get_subcommands() {
            assert!(
                usage.contains(&format!("ov {}", sub.get_name())) || sub.get_name() == "help",
                "{}",
                sub.get_name()
            );
            for a in sub.get_arguments() {
                if let Some(l) = a.get_long() {
                    let short = a.get_short().map(|c| format!("[-{c}"));
                    assert!(
                        usage.contains(&format!("--{l}")) || short.is_some_and(|s| usage.contains(&s)),
                        "--{l} is not in USAGE"
                    );
                }
            }
        }
    }

    #[test]
    fn collects_values_like_parse_args() {
        let p = parse(&["share"], &v(&["ov://v/e", "--field", "a", "--field=b", "--expires", "1h", "--once"])).unwrap();
        assert_eq!(p.positionals, v(&["ov://v/e"]));
        assert_eq!(p.values("field"), v(&["a", "b"]).as_slice());
        assert_eq!(p.value("expires"), Some("1h"));
        assert!(p.flag("once") && !p.flag("text"));
        let p = parse(&["read"], &v(&["-nofile", "x", "-o", "y", "--", "-z"])).unwrap();
        assert!(p.flag("no-newline"));
        assert_eq!(p.value("out-file"), Some("y"));
        assert_eq!(p.positionals, v(&["x", "-z"]));
        let p = parse(&["read"], &v(&["-o-x", "--out-file=", "-"])).unwrap();
        assert_eq!(p.value("out-file"), Some(""));
        assert_eq!(p.positionals, v(&["-"]));
    }

    #[test]
    fn rejects_like_parse_args() {
        let err = |path: &[&str], a: &[&str]| parse(path, &v(a)).unwrap_err();
        assert_eq!(err(&["read"], &["--bogus"]), "Unknown option '--bogus'. To specify a positional argument starting with a '-', place it at the end of the command after '--', as in '-- \"--bogus\"");
        assert!(err(&["read"], &["-n=1"]).starts_with("Unknown option '-='."));
        assert!(err(&["read"], &["--bogus=1"]).starts_with("Unknown option '--bogus'."));
        assert_eq!(err(&["read"], &["-o"]), "Option '-o, --out-file <value>' argument missing");
        assert_eq!(err(&["read"], &["-no"]), "Option '-o, --out-file <value>' argument missing");
        assert_eq!(err(&["read"], &["--no-newline=1"]), "Option '-n, --no-newline' does not take an argument");
        assert_eq!(
            err(&["read"], &["-o", "-n"]),
            "Option '-o' argument is ambiguous.\nDid you forget to specify the option argument for '-o'?\nTo specify an option argument starting with a dash use '--out-file=-XYZ' or '-o-XYZ'."
        );
        assert_eq!(
            err(&["read"], &["--out-file", "--x"]),
            "Option '--out-file' argument is ambiguous.\nDid you forget to specify the option argument for '--out-file'?\nTo specify an option argument starting with a dash use '--out-file=-XYZ'."
        );
        assert_eq!(err(&["share"], &["--expires"]), "Option '--expires <value>' argument missing");
        assert!(err(&["read"], &["-5"]).starts_with("Unknown option '-5'."));
        assert!(err(&["read"], &["---x"]).starts_with("Unknown option '---x'."));
        assert!(err(&["read"], &["--=x"]).starts_with("Unknown option '--=x'."));
    }
}
