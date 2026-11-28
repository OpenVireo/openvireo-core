//! KDBX corpus round-trip harness (W1-K3).
//!
//! For every file in `corpus/kdbx/manifest.tsv`: open it, save it, reopen the output and require the
//! model to be equal (`Database == Database`), then save and reopen once more (the output must be
//! stable). Each rewrite must also open in the external tools where they're installed:
//!
//! - KeePassXC's CLI: `$OV_KEEPASSXC_CLI`, else `$HOME/kpnx/openvireo/build/src/cli/openvireo-cli`
//!   (the desktop build; KeePassXC renamed), else `keepassxc-cli` on `PATH`. The rewrite must give
//!   the same `<Entry>` count in `export` as the original, and the same count as the model
//!   (entries plus history items).
//! - kdbxweb, through `corpus/kdbx/kdbxweb-open.mjs`: `node` on `PATH` and the built SDK at `$OV_SDK`,
//!   else `$HOME/kpnx/openvireo-sdk`. The rewrite must report the same groups, entries, history
//!   items, attachments and unknown (`Zz*`) elements as the original.
//!
//! A missing tool skips its check with a message, unless `OV_CORPUS_REQUIRE_TOOLS=1` (for CI jobs
//! that install them). Every file and its result is printed; run with `--nocapture` to see the table:
//!
//! ```text
//! cargo test -p openvireo-kdbx --test corpus -- --nocapture
//! ```
//!
//! Rewrites are kept in `$CARGO_TARGET_TMPDIR/corpus/` for inspection.

use std::fmt::Debug;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ov_kdbx::model::{Binary, BinaryRef, Database, Entry, Group, StringField, Uuid};
use ov_kdbx::CompositeKey;

// ---- corpus manifest ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Required,
    Optional,
    External,
}

#[derive(Clone, Debug)]
struct CorpusFile {
    /// The manifest's `file` column, used as the file's name in the output.
    name: String,
    path: PathBuf,
    writer: String,
    password: Option<String>,
    key_file: Option<PathBuf>,
    kind: Kind,
}

fn repo_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus_dir() -> PathBuf {
    repo_dir().join("corpus/kdbx")
}

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from)
}

/// The desktop repo checkout for `ext:` files (KeePass 2.x files in its `tests/data/`).
fn keepassxc_src() -> Option<PathBuf> {
    std::env::var_os("OV_KEEPASSXC_SRC").map(PathBuf::from).or_else(|| home().map(|h| h.join("kpnx/openvireo")))
}

fn manifest() -> Vec<CorpusFile> {
    let dir = corpus_dir();
    let text = fs::read_to_string(dir.join("manifest.tsv")).expect("read corpus/kdbx/manifest.tsv");
    let mut files = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols.len(), 5, "manifest.tsv line {}: expected 5 tab-separated columns: {line:?}", n + 1);
        let path = match cols[0].strip_prefix("ext:") {
            Some(rel) => keepassxc_src().map_or_else(|| PathBuf::from("<no $OV_KEEPASSXC_SRC>"), |s| s.join(rel)),
            None => dir.join(cols[0]),
        };
        let password = match cols[2] {
            "-" => None,
            "<empty>" => Some(String::new()),
            pw => Some(pw.to_owned()),
        };
        let key_file = (cols[3] != "-").then(|| dir.join(cols[3]));
        let kind = match cols[4] {
            "required" => Kind::Required,
            "optional" => Kind::Optional,
            "external" => Kind::External,
            other => panic!("manifest.tsv line {}: unknown kind {other:?}", n + 1),
        };
        files.push(CorpusFile { name: cols[0].to_owned(), path, writer: cols[1].to_owned(), password, key_file, kind });
    }
    files
}

impl CorpusFile {
    fn key(&self) -> CompositeKey {
        let mut key = CompositeKey::new();
        if let Some(pw) = &self.password {
            key = key.with_password(pw);
        }
        if let Some(kf) = &self.key_file {
            let bytes = fs::read(kf).unwrap_or_else(|e| panic!("read key file {}: {e}", kf.display()));
            key = key.with_key_file(&bytes);
        }
        key
    }
}

// ---- model comparison --------------------------------------------------------------------------

/// What a save is allowed to change: it upgrades KDBX 3.x to 4.x (ADR 0002). The writer keeps the
/// KDF salt/seed (W1-K2), so everything else, the KDF parameters included, must survive exactly.
fn normalized(db: &Database, version_of: &Database) -> Database {
    let mut db = db.clone();
    if version_of.header.version.major < 4 {
        db.header.version = version_of.header.version;
    }
    db
}

fn short<T: Debug>(v: &T) -> String {
    let s = format!("{v:?}");
    if s.chars().count() > 400 {
        format!("{}…", s.chars().take(400).collect::<String>())
    } else {
        s
    }
}

fn diff_field<T: PartialEq + Debug>(out: &mut Vec<String>, path: &str, a: &T, b: &T) {
    if a != b {
        out.push(format!("{path}:\n      before: {}\n      after:  {}", short(a), short(b)));
    }
}

fn diff_entry(out: &mut Vec<String>, path: &str, a: &Entry, b: &Entry) {
    if a == b {
        return;
    }
    let before = out.len();
    diff_field(out, &format!("{path}.uuid"), &a.uuid, &b.uuid);
    diff_field(out, &format!("{path}.icon"), &(a.icon_id, a.custom_icon), &(b.icon_id, b.custom_icon));
    diff_field(
        out,
        &format!("{path}.colours/override_url"),
        &(&a.foreground_color, &a.background_color, &a.override_url),
        &(&b.foreground_color, &b.background_color, &b.override_url),
    );
    diff_field(out, &format!("{path}.tags"), &a.tags, &b.tags);
    diff_field(out, &format!("{path}.times"), &a.times, &b.times);
    diff_field(out, &format!("{path}.strings"), &a.strings, &b.strings);
    diff_field(out, &format!("{path}.binaries"), &a.binaries, &b.binaries);
    diff_field(out, &format!("{path}.auto_type"), &a.auto_type, &b.auto_type);
    diff_field(out, &format!("{path}.custom_data"), &a.custom_data, &b.custom_data);
    diff_field(out, &format!("{path}.quality_check"), &a.quality_check, &b.quality_check);
    diff_field(out, &format!("{path}.previous_parent_group"), &a.previous_parent_group, &b.previous_parent_group);
    diff_field(out, &format!("{path}.unknown"), &a.unknown, &b.unknown);
    if a.history.len() != b.history.len() {
        out.push(format!("{path}.history: {} items before, {} after", a.history.len(), b.history.len()));
    } else {
        for (i, (ha, hb)) in a.history.iter().zip(&b.history).enumerate() {
            diff_entry(out, &format!("{path}.history[{i}]"), ha, hb);
        }
    }
    if out.len() == before {
        out.push(format!("{path}: differs (field not broken out)"));
    }
}

fn diff_group(out: &mut Vec<String>, path: &str, a: &Group, b: &Group) {
    if a == b {
        return;
    }
    let before = out.len();
    let path = format!("{path}/{}", a.name);
    diff_field(out, &format!("{path}.uuid"), &a.uuid, &b.uuid);
    diff_field(out, &format!("{path}.name/notes"), &(&a.name, &a.notes), &(&b.name, &b.notes));
    diff_field(out, &format!("{path}.icon"), &(a.icon_id, a.custom_icon), &(b.icon_id, b.custom_icon));
    diff_field(out, &format!("{path}.times"), &a.times, &b.times);
    diff_field(
        out,
        &format!("{path}.expanded/auto_type/searching"),
        &(a.is_expanded, &a.default_auto_type_sequence, a.enable_auto_type, a.enable_searching),
        &(b.is_expanded, &b.default_auto_type_sequence, b.enable_auto_type, b.enable_searching),
    );
    diff_field(out, &format!("{path}.last_top_visible_entry"), &a.last_top_visible_entry, &b.last_top_visible_entry);
    diff_field(out, &format!("{path}.tags"), &a.tags, &b.tags);
    diff_field(out, &format!("{path}.previous_parent_group"), &a.previous_parent_group, &b.previous_parent_group);
    diff_field(out, &format!("{path}.custom_data"), &a.custom_data, &b.custom_data);
    diff_field(out, &format!("{path}.unknown"), &a.unknown, &b.unknown);
    if a.entries.len() != b.entries.len() {
        out.push(format!("{path}.entries: {} before, {} after", a.entries.len(), b.entries.len()));
    } else {
        for (i, (ea, eb)) in a.entries.iter().zip(&b.entries).enumerate() {
            diff_entry(out, &format!("{path}.entries[{i}] {:?}", ea.title()), ea, eb);
        }
    }
    if a.groups.len() != b.groups.len() {
        out.push(format!("{path}.groups: {} before, {} after", a.groups.len(), b.groups.len()));
    } else {
        for (ga, gb) in a.groups.iter().zip(&b.groups) {
            diff_group(out, &path, ga, gb);
        }
    }
    if out.len() == before {
        out.push(format!("{path}: differs (field not broken out)"));
    }
}

/// Where two databases differ, as paths with both values (`Debug` redacts protected values).
fn diff_db(a: &Database, b: &Database) -> Vec<String> {
    let mut out = Vec::new();
    diff_field(&mut out, "header", &a.header, &b.header);
    diff_field(&mut out, "meta", &a.meta, &b.meta);
    diff_group(&mut out, "root", &a.root, &b.root);
    diff_field(&mut out, "deleted_objects", &a.deleted_objects, &b.deleted_objects);
    diff_field(&mut out, "binaries", &a.binaries, &b.binaries);
    diff_field(&mut out, "unknown_file", &a.unknown_file, &b.unknown_file);
    diff_field(&mut out, "unknown_root", &a.unknown_root, &b.unknown_root);
    out
}

fn count(g: &Group) -> (usize, usize, usize) {
    let mut groups = 1;
    let mut entries = g.entries.len();
    let mut history = g.entries.iter().map(|e| e.history.len()).sum();
    for sub in &g.groups {
        let (gs, es, hs) = count(sub);
        groups += gs;
        entries += es;
        history += hs;
    }
    (groups, entries, history)
}

fn count_unknown(db: &Database) -> usize {
    fn group(g: &Group) -> usize {
        let entries: usize =
            g.entries.iter().map(|e| e.unknown.len() + e.auto_type.as_ref().map_or(0, |a| a.unknown.len())).sum();
        g.unknown.len() + entries + g.groups.iter().map(group).sum::<usize>()
    }
    db.unknown_file.len() + db.unknown_root.len() + db.meta.unknown.len() + group(&db.root)
}

// ---- external tools ----------------------------------------------------------------------------

fn require_tools() -> bool {
    std::env::var("OV_CORPUS_REQUIRE_TOOLS").is_ok_and(|v| v == "1")
}

fn runs(cmd: &Path, arg: &str) -> bool {
    Command::new(cmd).arg(arg).stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success())
}

fn keepassxc_cli() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("OV_KEEPASSXC_CLI") {
        return Some(PathBuf::from(p));
    }
    if let Some(local) = home().map(|h| h.join("kpnx/openvireo/build/src/cli/openvireo-cli")) {
        if local.exists() {
            return Some(local);
        }
    }
    let path = PathBuf::from("keepassxc-cli");
    runs(&path, "--version").then_some(path)
}

/// `node` plus a built SDK (it bundles kdbxweb and wires up Argon2).
fn kdbxweb() -> Option<PathBuf> {
    let sdk = std::env::var_os("OV_SDK").map(PathBuf::from).or_else(|| home().map(|h| h.join("kpnx/openvireo-sdk")))?;
    let node = PathBuf::from("node");
    (sdk.join("packages/sdk/dist/index.js").exists() && runs(&node, "--version")).then_some(sdk)
}

fn run_with_stdin(mut cmd: Command, stdin: &str) -> Result<String, String> {
    use std::io::Write;
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn: {e}"))?;
    child.stdin.take().expect("stdin").write_all(stdin.as_bytes()).map_err(|e| format!("stdin: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
    }
}

/// `<Entry>` elements in `openvireo-cli export` of `path` (entries plus history items).
fn keepassxc_entries(cli: &Path, f: &CorpusFile, path: &Path) -> Result<usize, String> {
    let mut cmd = Command::new(cli);
    cmd.args(["export", "-q"]);
    if let Some(kf) = &f.key_file {
        cmd.arg("-k").arg(kf);
    }
    if f.password.is_none() {
        cmd.arg("--no-password");
    }
    cmd.arg(path);
    let xml = run_with_stdin(cmd, &format!("{}\n", f.password.as_deref().unwrap_or("")))?;
    Ok(xml.matches("<Entry>").count())
}

/// kdbxweb-open.mjs's JSON line, without the `version` and `generator` fields (a save may upgrade
/// 3.x to 4.x).
fn kdbxweb_summary(sdk: &Path, f: &CorpusFile, path: &Path) -> Result<String, String> {
    let mut cmd = Command::new("node");
    cmd.arg(corpus_dir().join("kdbxweb-open.mjs")).arg(path).env("OV_SDK", sdk);
    if let Some(pw) = &f.password {
        cmd.arg("--password").arg(pw);
    }
    if let Some(kf) = &f.key_file {
        cmd.arg("--key-file").arg(kf);
    }
    let line = run_with_stdin(cmd, "")?;
    let line = line.trim();
    // {"version":"4.0","generator":"…","groups":…} → {"groups":…}
    let rest = line.find("\"groups\"").map_or(line, |i| &line[i..]);
    Ok(rest.trim_end_matches('}').to_owned())
}

#[derive(Default)]
struct Tools {
    keepassxc: Option<PathBuf>,
    kdbxweb: Option<PathBuf>,
}

impl Tools {
    fn find() -> Tools {
        let tools = Tools { keepassxc: keepassxc_cli(), kdbxweb: kdbxweb() };
        match &tools.keepassxc {
            Some(p) => println!("keepassxc-cli: {}", p.display()),
            None => println!("keepassxc-cli: not found (set OV_KEEPASSXC_CLI); its checks are skipped"),
        }
        match &tools.kdbxweb {
            Some(p) => println!("kdbxweb: node + SDK at {}", p.display()),
            None => println!("kdbxweb: node or a built SDK not found (set OV_SDK); its checks are skipped"),
        }
        if require_tools() {
            assert!(tools.keepassxc.is_some(), "OV_CORPUS_REQUIRE_TOOLS=1 but keepassxc-cli wasn't found");
            assert!(tools.kdbxweb.is_some(), "OV_CORPUS_REQUIRE_TOOLS=1 but node + the SDK weren't found");
        }
        tools
    }

    /// The external checks on a rewrite: notes on success, the problem on failure.
    fn check(&self, f: &CorpusFile, original: &Path, rewrite: &Path, db: &Database) -> Result<Vec<String>, String> {
        let mut notes = Vec::new();
        if let Some(cli) = &self.keepassxc {
            match keepassxc_entries(cli, f, original) {
                // The tool can't open the original (e.g. a format it doesn't read): nothing to compare.
                Err(e) => notes.push(format!("keepassxc-cli: skipped, it can't open the original ({e})")),
                Ok(before) => {
                    let after = keepassxc_entries(cli, f, rewrite)
                        .map_err(|e| format!("keepassxc-cli can't open the rewrite: {e}"))?;
                    let (_, entries, history) = count(&db.root);
                    if after != before || after != entries + history {
                        return Err(format!(
                            "keepassxc-cli: {after} <Entry> in the rewrite, {before} in the original, model has {}",
                            entries + history
                        ));
                    }
                    notes.push(format!("keepassxc-cli ok ({after} <Entry>)"));
                }
            }
        }
        if let Some(sdk) = &self.kdbxweb {
            match kdbxweb_summary(sdk, f, original) {
                Err(e) => notes.push(format!("kdbxweb: skipped, it can't open the original ({e})")),
                Ok(before) => {
                    let after =
                        kdbxweb_summary(sdk, f, rewrite).map_err(|e| format!("kdbxweb can't open the rewrite: {e}"))?;
                    if after != before {
                        return Err(format!(
                            "kdbxweb sees a difference:\n      before: {before}\n      after:  {after}"
                        ));
                    }
                    notes.push("kdbxweb ok".into());
                }
            }
        }
        Ok(notes)
    }
}

// ---- round trip --------------------------------------------------------------------------------

fn out_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("corpus");
    fs::create_dir_all(&dir).expect("create the rewrite directory");
    dir
}

fn out_path(name: &str) -> PathBuf {
    out_dir().join(name.replace("../", "").replace(['/', ':'], "_"))
}

/// open → save → reopen equals the model, save → reopen again is stable. Returns the database as
/// first read and the rewrite's bytes.
fn round_trip(bytes: &[u8], key: &CompositeKey) -> Result<(Database, Vec<u8>), String> {
    let db1 = ov_kdbx::read(bytes, key).map_err(|e| format!("open failed: {e}"))?;
    round_trip_model(&db1, key).map(|out| (db1, out))
}

/// write → read equals the model, twice.
fn round_trip_model(db1: &Database, key: &CompositeKey) -> Result<Vec<u8>, String> {
    let out1 = ov_kdbx::write(db1, key).map_err(|e| format!("save failed: {e}"))?;
    let db2 = ov_kdbx::read(&out1, key).map_err(|e| format!("reopening the rewrite failed: {e}"))?;
    let (a, b) = (normalized(db1, db1), normalized(&db2, db1));
    if a != b {
        return Err(format!("model changed by open → save → reopen:\n    {}", diff_db(&a, &b).join("\n    ")));
    }
    let out2 = ov_kdbx::write(&db2, key).map_err(|e| format!("second save failed: {e}"))?;
    let db3 = ov_kdbx::read(&out2, key).map_err(|e| format!("reopening the second rewrite failed: {e}"))?;
    let (b, c) = (normalized(&db2, &db2), normalized(&db3, &db2));
    if b != c {
        return Err(format!("model changed by a second save:\n    {}", diff_db(&b, &c).join("\n    ")));
    }
    Ok(out1)
}

fn summary(db: &Database) -> String {
    let (groups, entries, history) = count(&db.root);
    format!(
        "KDBX {}.{}, {groups} groups, {entries} entries, {history} history, {} attachments, {} icons, {} unknown",
        db.header.version.major,
        db.header.version.minor,
        db.binaries.len(),
        db.meta.custom_icons.len(),
        count_unknown(db)
    )
}

#[test]
fn corpus_round_trips() {
    let tools = Tools::find();
    let files = manifest();
    let mut failures = Vec::new();
    let mut opened = 0;
    println!("\n{:<48} {:<8} result", "file", "kind");
    for f in &files {
        let label = format!("{:<48} {:<8}", f.name, format!("{:?}", f.kind).to_lowercase());
        let Ok(bytes) = fs::read(&f.path) else {
            if f.kind == Kind::Required {
                println!("{label} FAIL: missing {}", f.path.display());
                failures.push(format!("{}: missing", f.name));
            } else {
                println!("{label} SKIP: not present ({})", f.path.display());
            }
            continue;
        };
        let result = round_trip(&bytes, &f.key()).and_then(|(db, out)| {
            let rewrite = out_path(&f.name);
            fs::write(&rewrite, &out).map_err(|e| format!("write {}: {e}", rewrite.display()))?;
            let notes = tools.check(f, &f.path, &rewrite, &db)?;
            Ok((db, notes))
        });
        match result {
            Ok((db, notes)) => {
                opened += 1;
                let notes = if notes.is_empty() { String::new() } else { format!("; {}", notes.join("; ")) };
                println!("{label} ok: {} [{}]{notes}", summary(&db), f.writer);
            }
            Err(e) => {
                println!("{label} FAIL [{}]: {e}", f.writer);
                failures.push(format!("{}: {e}", f.name));
            }
        }
    }
    println!("{opened} of {} files round-tripped, {} failed", files.len(), failures.len());
    assert!(failures.is_empty(), "corpus failures:\n  {}", failures.join("\n  "));
}

/// Every `.kdbx` under `corpus/kdbx/` is in the manifest, so a new file can't be skipped silently.
#[test]
fn manifest_lists_every_corpus_file() {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(dir).expect("read corpus dir").flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "kdbx") {
                out.push(p);
            }
        }
    }
    let listed: Vec<PathBuf> = manifest().into_iter().map(|f| f.path).collect();
    let mut found = Vec::new();
    walk(&corpus_dir(), &mut found);
    for p in found {
        assert!(listed.contains(&p), "{} isn't in corpus/kdbx/manifest.tsv", p.display());
    }
}

/// A 5,000-entry database built in memory (always runs, no generated file needed): written, read
/// back equal, and opened by the external tools. Every 10th entry has history and every 100th an
/// attachment. `keepassxc/keepassxc-5k.kdbx` (gen-keepassxc.mjs --5k) covers a 5k file KeePassXC wrote.
#[test]
fn five_thousand_entries_round_trip() {
    let tools = Tools::find();
    let f = manifest().into_iter().find(|f| f.name == "kdbxweb/kdbxweb-unknown.kdbx").expect("base file in manifest");
    let key = f.key();
    let mut db = ov_kdbx::read(&fs::read(&f.path).expect("read base file"), &key).expect("open base file");

    let t0 = 1_763_208_000; // 2025-11-15T12:00:00Z
    let attachment = u32::try_from(db.binaries.len()).expect("pool index");
    db.binaries.push(Binary { data: b"5k attachment".to_vec().into(), protected: false });
    let mut big = Group::new(Uuid::from_u128(0x5000_0000), "5k", t0);
    for g in 0..50u32 {
        let mut group = Group::new(Uuid::from_u128(0x5100_0000 + u128::from(g)), format!("Group {g}"), t0);
        for e in 0..100u32 {
            let n = g * 100 + e;
            let mut entry = Entry::new(Uuid::from_u128(0x5200_0000 + u128::from(n)), t0 + i64::from(n));
            entry.strings = vec![
                StringField::new("Title", format!("Entry {n}"), false),
                StringField::new("UserName", format!("user{n}"), false),
                StringField::new("Password", format!("pw-{n}-✓"), true),
                StringField::new("URL", format!("https://site{n}.example"), false),
                StringField::new("Notes", if n % 10 == 0 { format!("notes {n}") } else { String::new() }, false),
            ];
            if n % 7 == 0 {
                entry.tags = vec!["seven".into()];
            }
            if n % 10 == 0 {
                let mut old = entry.clone();
                old.strings[2] = StringField::new("Password", format!("old-{n}"), true);
                old.times.last_modification -= 60;
                entry.history.push(old);
            }
            if n % 100 == 0 {
                entry.binaries.push(BinaryRef { name: format!("file{n}.txt"), index: attachment });
            }
            group.entries.push(entry);
        }
        big.groups.push(group);
    }
    db.root.groups.push(big);

    let out = round_trip_model(&db, &key).unwrap_or_else(|e| panic!("5k round trip: {e}"));
    let rewrite = out_path("model-5k.kdbx");
    fs::write(&rewrite, &out).expect("write 5k rewrite");
    let (_, entries, history) = count(&db.root);
    assert!(entries >= 5000, "{entries} entries");
    // The external tools compare the rewrite with itself here (there's no original file); this still
    // proves they open it and see the model's entry count.
    let notes = tools.check(&f, &rewrite, &rewrite, &db).unwrap_or_else(|e| panic!("5k external check: {e}"));
    println!("model-5k: ok, {} ({} bytes); {}", summary(&db), out.len(), notes.join("; "));
    assert!(history >= 500);
}
