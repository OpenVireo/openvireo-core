// contract-v1.6 through the C++ binding (docs/adr/0001-contract.md § contract-v1.6): local files
// on the Host clock, entry last use, colours, custom icons and field order, chosen ids, attachment
// flags, every record in one call, imports with a preview, file metadata and KDFs, and self-hosted
// history over a canned transport. ServiceAccount::server_config / issuer need a real token: they are
// only compiled here.

#include <ovcore.h>

#include <cstdio>
#include <map>
#include <memory>
#include <string>
#include <utility>

namespace {

int failures = 0;

void check(bool ok, const char *what) {
    std::printf("%s v1.6: %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
        ++failures;
    }
}

rust::Vec<std::uint8_t> bytes(const std::string &s) {
    rust::Vec<std::uint8_t> v;
    for (unsigned char c : s) {
        v.push_back(c);
    }
    return v;
}

ov::KdbxCredentials pw(const std::string &p) { return ov::KdbxCredentials{true, bytes(p), false, {}, false, {}}; }

ov::EntryInput no_change() {
    return ov::EntryInput{{}, {}, false, {}, false, 0, ov::EntryExpiry{ov::ExpiryKind::Keep, 0}, false, {}, false, {}, ov::CustomIconChange::Keep, {}, false, {}};
}

// Answers a self-hosted server's history routes: two versions, revision 1's bytes.
struct HistoryHttp : ov::HttpTransport {
    rust::Vec<std::uint8_t> revision1;
    ov::HttpResponse send(const ov::HttpRequest &req, ov::TransportFailure &) const override {
        const std::string url(req.url);
        auto ends = [&](const std::string &s) { return url.size() >= s.size() && url.compare(url.size() - s.size(), s.size(), s) == 0; };
        ov::HttpResponse res;
        if (ends("/databases/home/history")) {
            res.status = 200;
            res.headers.push_back(ov::Header{"content-type", "application/json"});
            res.body = bytes(R"({"versions":[{"id":"home","etag":"\"r2\"","revision":2,"size":10,"updatedAt":"2026-11-19T10:00:00Z"},)"
                             R"({"id":"home","etag":"\"r1\"","revision":1,"size":9,"updatedAt":"2026-11-18T10:00:00Z"}]})");
        } else if (ends("/databases/home/history/1")) {
            res.status = 200;
            res.headers.push_back(ov::Header{"etag", "\"r1\""});
            for (auto b : revision1) {
                res.body.push_back(b);
            }
        } else {
            res.status = 404;
            res.body = bytes(R"({"error":"not_found"})");
        }
        return res;
    }
    std::unique_ptr<ov::ByteStream> open_stream(const ov::HttpRequest &, ov::TransportFailure &failure) const override {
        failure.kind = ov::TransportErrorKind::Offline;
        return nullptr;
    }
};
struct NoStore : ov::SecureStore {
    bool get(rust::Str, rust::Vec<std::uint8_t> &) const override { return false; }
    void set(rust::Str, rust::Slice<const std::uint8_t>) const override {}
    void remove(rust::Str) const override {}
};
struct NoCache : ov::BlobCache {
    bool load(rust::Str, rust::Str, ov::CachedVault &) const override { return false; }
    void save(rust::Str, rust::Str, const ov::CachedVault &) const override {}
    void remove(rust::Str, rust::Str) const override {}
    rust::Vec<rust::String> list(rust::Str) const override { return {}; }
    bool load_meta(rust::Str, rust::Str, rust::Vec<std::uint8_t> &) const override { return false; }
    void save_meta(rust::Str, rust::Str, rust::Slice<const std::uint8_t>) const override {}
    void clear_user(rust::Str) const override {}
};
struct Clock1700 : ov::Clock {
    std::int64_t now_unix_ms() const override { return 1700000000000; }
};
struct NoLog : ov::LogSink {
    void log(ov::LogLevel, rust::Str, rust::Str) const override {}
};

rust::Box<ov::Client> client(rust::Vec<std::uint8_t> revision1 = {}) {
    ov::ClientConfig config{"", "smoke", ov::Platform::QtMacos, false, false, ov::ServerConfig{}};
    auto http = std::make_unique<HistoryHttp>();
    http->revision1 = std::move(revision1);
    return ov::call([&] {
        return ov::new_client(config, std::move(http), std::make_unique<NoStore>(), std::make_unique<NoCache>(),
                              std::make_unique<Clock1700>(), std::make_unique<NoLog>());
    });
}

// ---- a C++ Host over the in-process test servers (what the desktop's CoreHost does in its tests)
struct ServersHttp : ov::HttpTransport {
    const ov::TestServers *servers;
    explicit ServersHttp(const ov::TestServers *s) : servers(s) {}
    ov::HttpResponse send(const ov::HttpRequest &req, ov::TransportFailure &failure) const override {
        return servers->handle(req, failure);
    }
    std::unique_ptr<ov::ByteStream> open_stream(const ov::HttpRequest &, ov::TransportFailure &failure) const override {
        failure.kind = ov::TransportErrorKind::Offline;
        return nullptr;
    }
};
struct ServersClock : ov::Clock {
    const ov::TestServers *servers;
    explicit ServersClock(const ov::TestServers *s) : servers(s) {}
    std::int64_t now_unix_ms() const override { return servers->now_ms(); }
};
struct MapStore : ov::SecureStore {
    mutable std::map<std::string, rust::Vec<std::uint8_t>> items;
    bool get(rust::Str key, rust::Vec<std::uint8_t> &out) const override {
        auto it = items.find(std::string(key));
        if (it == items.end()) {
            return false;
        }
        out = it->second;
        return true;
    }
    void set(rust::Str key, rust::Slice<const std::uint8_t> value) const override {
        rust::Vec<std::uint8_t> v;
        for (auto b : value) {
            v.push_back(b);
        }
        items[std::string(key)] = std::move(v);
    }
    void remove(rust::Str key) const override { items.erase(std::string(key)); }
};
struct MapCache : ov::BlobCache {
    mutable std::map<std::string, ov::CachedVault> vaults;
    mutable std::map<std::string, rust::Vec<std::uint8_t>> meta;
    static std::string k(rust::Str a, rust::Str b) { return std::string(a) + "\n" + std::string(b); }
    bool load(rust::Str u, rust::Str v, ov::CachedVault &out) const override {
        auto it = vaults.find(k(u, v));
        if (it == vaults.end()) {
            return false;
        }
        out = it->second;
        return true;
    }
    void save(rust::Str u, rust::Str v, const ov::CachedVault &c) const override { vaults[k(u, v)] = c; }
    void remove(rust::Str u, rust::Str v) const override { vaults.erase(k(u, v)); }
    rust::Vec<rust::String> list(rust::Str u) const override {
        rust::Vec<rust::String> out;
        const std::string prefix = std::string(u) + "\n";
        for (const auto &e : vaults) {
            if (e.first.compare(0, prefix.size(), prefix) == 0) {
                out.push_back(rust::String(e.first.substr(prefix.size())));
            }
        }
        return out;
    }
    bool load_meta(rust::Str u, rust::Str n, rust::Vec<std::uint8_t> &out) const override {
        auto it = meta.find(k(u, n));
        if (it == meta.end()) {
            return false;
        }
        out = it->second;
        return true;
    }
    void save_meta(rust::Str u, rust::Str n, rust::Slice<const std::uint8_t> value) const override {
        rust::Vec<std::uint8_t> v;
        for (auto b : value) {
            v.push_back(b);
        }
        meta[k(u, n)] = std::move(v);
    }
    void clear_user(rust::Str) const override {}
};

// The desktop's contract-v1.6 calls against the in-process servers, through a C++ Host.
[[maybe_unused]] void desktop_flow() {
    auto token = ov::new_cancel_token();
    auto servers = ov::call([] { return ov::test_servers_start(0); });
    ov::ClientConfig config{"", "smoke", ov::Platform::QtMacos, true, false, ov::ServerConfig{}};
    auto c = ov::call([&] {
        return ov::new_client(config, std::make_unique<ServersHttp>(&*servers), std::make_unique<MapStore>(),
                              std::make_unique<MapCache>(), std::make_unique<ServersClock>(&*servers),
                              std::make_unique<NoLog>());
    });
    auto account = ov::call([&] { return c->connect(servers->issuer(), *token); });
    ov::RegisterInput input{"desk@example.com", bytes("pw desk"), ov::KdfOverrides{true, 19456, true, 2, true, 1}, true};
    ov::call([&] { return account->register_account(std::move(input), *token); });
    check(!std::string(ov::call([&] { return servers->user_id("desk@example.com"); })).empty(),
          "test servers: register through a C++ Host");
    auto jwt = ov::call([&] { return account->access_token(false, *token); });
    check(jwt.size() > 20, "Account::access_token lends the session token");
    ov::wipe(jwt);
    auto vault = ov::call([&] { return account->create_vault("Desk", "", *token); });
    const std::string id(ov::call([&] { return vault->id(); }));
    ov::KdbxCredentials creds = ov::call([&] { return account->vault_kdbx_credentials(id, *token); });
    check(!creds.has_password && creds.key_file.size() == 32, "Account::vault_kdbx_credentials is the raw vault key");
    auto copy = ov::call([&] { return vault->copy_without_remotes(std::move(creds)); });
    ov::call([&] { copy->set_kdf(ov::KdbxKdf{ov::KdbxKdfKind::Argon2id, 1 << 20, 2, 1, 0}); });
    auto file = ov::call([&] { return copy->save_local(*token); });
    ov::SyncOptions opts{true, false};
    ov::VaultKdbxSyncResult r = ov::call([&] { return account->sync_vault_kdbx(id, std::move(file), false, {}, opts, *token); });
    check(ov::call([&] { return servers->vault_revision(id); }) >= 1, "Account::sync_vault_kdbx syncs the file");
    ov::call([&] { servers->lose_vault(id); });
    try {
        ov::call([&] { return account->sync_vault_kdbx(id, r.kdbx, false, {}, opts, *token); });
        check(false, "a lost vault fails the sync");
    } catch (const ov::Error &e) {
        check(e.code() == "server_lost_database", "a lost vault fails with server_lost_database");
    }
    ov::SyncOptions accept{true, true};
    auto again = ov::call([&] { return account->sync_vault_kdbx(id, std::move(r.kdbx), false, {}, accept, *token); });
    check(again.report.outcome == ov::SyncOutcome::Created, "SyncOptions::accept_server_state uploads it again");
}

[[maybe_unused]] void compile_only(const ov::ServiceAccount &sa) {
    ov::ServerConfig config = sa.server_config();
    rust::String issuer = sa.issuer();
    (void)config;
    (void)issuer;
}

} // namespace

int contract_v16() {
    auto token = ov::new_cancel_token();
    auto c = client();

    // ---- entries: chosen id, colours, icon, field order, Host clock, last use
    auto v = ov::call([&] { return c->create_local("Home", pw("pw"), *token); });
    const std::string icon(ov::call([&] { return v->add_custom_icon(bytes("\x89PNG")); }));
    ov::EntryInput in = no_change();
    in.fields.push_back(ov::FieldInput{"title", bytes("Mail"), false, false});
    in.fields.push_back(ov::FieldInput{"B", bytes("b"), false, false});
    in.fields.push_back(ov::FieldInput{"A", bytes("a"), false, false});
    in.has_foreground_color = true;
    in.foreground_color = "#112233";
    in.custom_icon_change = ov::CustomIconChange::Set;
    in.custom_icon = icon;
    in.has_field_order = true;
    in.field_order.push_back("A");
    in.field_order.push_back("B");
    const std::string id(ov::call(
        [&] { return v->add_entry_with_id("0123456789ABCDEF0123456789ABCDEF", v->root_group_id(), std::move(in)); }));
    check(id == "0123456789abcdef0123456789abcdef", "Vault::add_entry_with_id returns the normalized id");
    try {
        ov::call([&] { return v->add_entry_with_id(id, v->root_group_id(), no_change()); });
        check(false, "a second add_entry_with_id with the same id fails");
    } catch (const ov::Error &e) {
        check(e.code() == "conflict", "a second add_entry_with_id with the same id fails with conflict");
    }
    ov::EntryRecord e = ov::call([&] { return v->entry(id); });
    check(e.modified_at == 1700000000, "Client::create_local stamps edits with the Host clock");
    check(std::string(e.foreground_color) == "#112233" && std::string(e.custom_icon) == icon,
          "EntryInput sets the colour and custom icon");
    const auto n = e.fields.size();
    check(n >= 2 && std::string(e.fields[n - 2].name) == "A" && std::string(e.fields[n - 1].name) == "B",
          "EntryInput::field_order orders the custom fields");
    check(!e.has_last_access_at && e.usage_count == 0, "a new entry was never used");
    ov::EntryInput clear = no_change();
    clear.custom_icon_change = ov::CustomIconChange::Clear;
    ov::call([&] { v->edit_entry(id, std::move(clear)); });
    check(std::string(ov::call([&] { return v->entry(id); }).custom_icon).empty(), "CustomIconChange::Clear clears it");

    // ---- attachments, entry_records
    ov::call([&] { v->set_attachment_with(id, "plain.txt", bytes("hi"), true, false); });
    ov::call([&] { v->set_attachment(id, "secret.bin", bytes("s")); });
    e = ov::call([&] { return v->entry(id); });
    check(e.attachments.size() == 2 && !e.attachments[0].is_protected && e.attachments[1].is_protected,
          "AttachmentInfo::is_protected follows set_attachment_with");
    check(ov::call([&] { return v->entry_records(false); }).size() == ov::call([&] { return v->entries(false); }).size(),
          "Vault::entry_records has every entry");

    // ---- imports
    auto source = ov::call([&] { return c->create_local("Work", pw("pw"), *token); });
    const std::string servers(ov::call([&] { return source->ensure_group("Servers"); }));
    ov::EntryInput db = no_change();
    db.fields.push_back(ov::FieldInput{"title", bytes("db"), false, false});
    ov::call([&] { return source->add_entry(servers, std::move(db)); });
    const ov::ImportPreview preview = ov::call([&] { return source->import_preview(); });
    check(preview.entries == 1 && preview.groups == 1, "Vault::import_preview counts entries and groups");
    const std::string into(ov::call([&] { return v->ensure_group("Imported"); }));
    check(ov::call([&] { return v->import_targets(); }).size() == 2, "Vault::import_targets lists the groups");
    ov::LocalImportMode copies{ov::LocalImportKind::Copies, into};
    const ov::ImportSummary s = ov::call([&] { return v->import_from(*source, copies); });
    check(s.added == 1 && s.groups_added == 2, "Vault::import_from copies under a chosen group");
    ov::LocalImportMode merge{ov::LocalImportKind::Merge, ""};
    check(ov::call([&] { return v->import_from(*source, merge); }).added == 1, "Vault::import_from merges by UUID");

    // ---- metadata, copies, KDFs
    ov::call([&] { v->set_name("Family"); });
    check(std::string(ov::call([&] { return v->name(); })) == "Family", "Vault::set_name renames a local file");
    ov::call([&] { v->set_meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS", true, R"([{"type":"syncServer"}])"); });
    check(ov::call([&] { return v->meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS"); }).has, "meta custom data is set");
    auto copy = ov::call([&] { return v->copy_without_remotes(ov::KdbxCredentials{false, {}, false, {}, false, {}}); });
    check(!ov::call([&] { return copy->meta_custom_data("KPXC_REMOTE_SYNC_SETTINGS"); }).has,
          "Vault::copy_without_remotes drops the sync-server remote");
    ov::call([&] { copy->set_kdf(ov::KdbxKdf{ov::KdbxKdfKind::Argon2id, 1 << 20, 3, 1, 0}); });
    auto saved = ov::call([&] { return copy->save_local(*token); });
    auto reopened = ov::call([&] { return c->open_local(std::move(saved), pw("pw"), *token); });
    check(std::string(ov::call([&] { return reopened->name(); })) == "Family", "the copy saves with its own password");
    try {
        ov::call([&] { copy->set_kdf(ov::KdbxKdf{ov::KdbxKdfKind::AesKdf, 0, 0, 0, 0}); });
        check(false, "AES-KDF with 0 rounds fails");
    } catch (const ov::Error &err) {
        check(err.code() == "invalid_request", "AES-KDF with 0 rounds fails with invalid_request");
    }
    auto exported = ov::call(
        [&] { return v->export_kdbx_with(pw("ex"), {}, ov::KdbxKdf{ov::KdbxKdfKind::AesKdf, 0, 0, 0, 100}, *token); });
    check(ov::call([&] { return c->open_local(std::move(exported), pw("ex"), *token); })->entries(false).size() >= 2,
          "Vault::export_kdbx_with exports with a chosen KDF");

    // ---- self-hosted history
    auto old = ov::call([&] { return c->create_local("Home", pw("pw"), *token); });
    ov::EntryInput wifi = no_change();
    wifi.fields.push_back(ov::FieldInput{"title", bytes("Wifi"), false, false});
    ov::call([&] { return old->add_entry(old->root_group_id(), std::move(wifi)); });
    auto rev1 = ov::call([&] { return old->save_local(*token); });
    auto hc = client(std::move(rev1));
    auto sh = ov::call([&] { return ov::self_hosted_connect(*hc, "https://sync.test", bytes("dev")); });
    auto history = ov::call([&] { return sh->history("home", *token); });
    check(history.size() == 2 && history[0].revision == 2 && history[0].is_current && !history[1].is_current,
          "SelfHosted::history lists the kept versions");
    auto version = ov::call([&] { return sh->open_version("home", 1, pw("pw"), *token); });
    check(ov::call([&] { return version->is_read_only(); }) && version->entries(false).size() == 1,
          "SelfHosted::open_version opens a read-only version");

    // ---- contract-v1.7: the password hash, sync_database_with
    auto hashed = ov::call([&] { return c->create_local("Hashed", pw("pw v17"), *token); });
    auto hbytes = ov::call([&] { return hashed->save_local(*token); });
    const std::string pwtext = "pw v17";
    auto hash = ov::sha256(rust::Slice<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>(pwtext.data()), pwtext.size()));
    ov::KdbxCredentials by_hash{false, {}, false, {}, true, std::move(hash)};
    auto hcopy = hbytes;
    auto opened = ov::call([&] { return ov::vault_open_local(std::move(hcopy), std::move(by_hash), *token); });
    check(std::string(ov::call([&] { return opened->name(); })) == "Hashed", "v1.7: vault_open_local with password_hash");
    try {
        auto wrong_hash = ov::sha256(rust::Slice<const std::uint8_t>(reinterpret_cast<const std::uint8_t *>("no"), 2));
        auto copy2 = hbytes;
        ov::call([&] {
            return ov::vault_open_local(std::move(copy2), ov::KdbxCredentials{false, {}, false, {}, true, std::move(wrong_hash)},
                                        *token);
        });
        check(false, "v1.7: a wrong hash fails");
    } catch (const ov::Error &e) {
        check(e.code() == "vault_key_mismatch", "v1.7: a wrong key is vault_key_mismatch");
    }
    try {
        // The canned transport has no databases/home: the first upload is refused
        ov::call([&] {
            return sh->sync_database_with("home", std::move(hbytes), pw("pw v17"), ov::SyncOptions{false, false}, *token);
        });
        check(false, "v1.7: sync_database_with reaches the transport");
    } catch (const ov::Error &e) {
        check(e.code() == "not_found", "v1.7: SelfHosted::sync_database_with reaches the transport");
    }

    // ---- the in-process test servers (feature test-server)
#if OV_EXPECT_TEST_SERVER
    desktop_flow();
#else
    try {
        ov::call([] { return ov::test_servers_start(0); });
        check(false, "test_servers_start fails without test-server");
    } catch (const ov::Error &e) {
        check(e.code() == "internal", "test_servers_start fails with internal without test-server");
    }
#endif

    return failures;
}
