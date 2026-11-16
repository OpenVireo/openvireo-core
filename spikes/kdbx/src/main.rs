//! W1-K1 spike: what keepass-rs 0.17.0 keeps when it reads and rewrites a .kdbx.
//!
//!   kdbx-spike xml       <in> <cred>          raw decrypted XML (keepass-rs `get_xml`) to stdout
//!   kdbx-spike roundtrip <in> <out> <cred>    open, print a summary, save as KDBX 4 to <out>
//!
//! <cred> is `pw:<password>` or `keyhex:<64 hex>` (the raw 32-byte vault key file of SPEC §7).

use std::{env, fs, io::Cursor, process::ExitCode};

use keepass::{config::DatabaseVersion, Database, DatabaseKey};

fn key(spec: &str) -> DatabaseKey {
    if let Some(pw) = spec.strip_prefix("pw:") {
        DatabaseKey::new().with_password(pw)
    } else if let Some(hex) = spec.strip_prefix("keyhex:") {
        let raw: Vec<u8> = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
            .collect();
        DatabaseKey::new().with_keyfile(&mut Cursor::new(raw)).expect("key file")
    } else {
        panic!("cred must be pw:… or keyhex:…")
    }
}

fn summary(db: &Database) {
    println!("version      {:?}", db.config.version);
    println!("outer cipher {:?}", db.config.outer_cipher_config);
    println!("inner cipher {:?}", db.config.inner_cipher_config);
    println!("kdf          {:?}", db.config.kdf_config);
    println!("public cd    {:?}", db.config.public_custom_data.as_ref().map(|_| "present"));
    println!("generator    {:?}", db.meta.generator);
    println!("db name      {:?}", db.meta.database_name);
    println!("meta cd keys {:?}", db.meta.custom_data.keys().collect::<Vec<_>>());
    println!("memprot      {:?}", db.meta.memory_protection);
    println!("recycle bin  {:?} {:?}", db.meta.recyclebin_enabled, db.meta.recyclebin_uuid);
    println!("deleted objs {}", db.deleted_objects.len());
    println!("groups       {}", db.num_groups());
    println!("entries      {}", db.num_entries());
    println!("attachments  {}", db.num_attachments());
    println!("custom icons {}", db.num_custom_icons());
    for g in db.iter_all_groups() {
        println!(
            "  group {:?} loc_changed={:?} cd={:?}",
            g.name,
            g.times.location_changed,
            g.custom_data.keys().collect::<Vec<_>>()
        );
    }
    for e in db.iter_all_entries() {
        // Field iteration order is HashMap order, not file order.
        let keys: Vec<_> = e.fields.keys().cloned().collect();
        let prot: Vec<_> = e.fields.iter().filter(|(_, v)| v.is_protected()).map(|(k, _)| k.clone()).collect();
        println!(
            "  entry {:?} fields={:?} protected={:?} history={} attachments={} tags={:?} loc_changed={:?} cd={:?} autotype={}",
            e.get_title(),
            keys,
            prot,
            e.history.as_ref().map_or(0, |h| h.get_entries().len()),
            e.attachments().count(),
            e.tags,
            e.times.location_changed,
            e.custom_data.keys().collect::<Vec<_>>(),
            e.autotype.as_ref().map_or("none".into(), |a| format!("{} assoc", a.associations.len())),
        );
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("xml") => {
            let data = fs::read(&args[2]).expect("read");
            match Database::get_xml(&mut Cursor::new(data), key(&args[3])) {
                Ok(xml) => {
                    print!("{}", String::from_utf8_lossy(&xml));
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("get_xml failed: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("roundtrip") => {
            let data = fs::read(&args[2]).expect("read");
            let mut db = match Database::parse(&data, key(&args[4])) {
                Ok(db) => db,
                Err(e) => {
                    eprintln!("OPEN FAILED: {e} ({e:?})");
                    return ExitCode::FAILURE;
                }
            };
            summary(&db);
            if db.config.version != DatabaseVersion::KDB4(1) {
                // keepass-rs 0.17 writes only KDBX 4.1 (dump_kdbx4 rejects KDB3 and KDB4(0)).
                println!("note: keepass-rs writes only KDBX 4.1; was {:?}", db.config.version);
                db.config.version = DatabaseVersion::KDB4(1);
            }
            let mut out = Vec::new();
            if let Err(e) = db.save(&mut out, key(&args[4])) {
                eprintln!("SAVE FAILED: {e}");
                return ExitCode::FAILURE;
            }
            fs::write(&args[3], &out).expect("write");
            let back = Database::parse(&out, key(&args[4])).expect("reopen own output");
            println!("reopen own output: equal on keepass-rs model = {}", back == db);
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("usage: kdbx-spike xml <in> <cred> | roundtrip <in> <out> <cred>");
            ExitCode::FAILURE
        }
    }
}
