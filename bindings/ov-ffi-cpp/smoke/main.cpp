// Calls the core through the OpenVireoCore package: version(), one primitive (SHA-256 "abc",
// FIPS 180-2), cancellation, at least one method of every bridged area, and (below_facade.cpp)
// every function below the facade against the contract vectors. There is no server:
// network calls must come back as an ov::Error (any code but internal), never crash; local work
// (a local vault, TOTP, share payloads, record helpers) is checked for its values.

#include <ovcore.h>

#include <cstdio>
#include <memory>
#include <string>
#include <utility>

// below_facade.cpp: the crypto, OPAQUE and merge functions against the vectors; failed checks.
int below_facade(bool test_server);

namespace {

std::string hex(const rust::Vec<std::uint8_t> &bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (auto b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 0xf];
    }
    return out;
}

// A Host that is never reached: OvClient::new does no I/O and the facade bodies are stubs.
struct NoHttp : ov::HttpTransport {
    ov::HttpResponse send(const ov::HttpRequest &, ov::TransportFailure &failure) const override {
        failure.kind = ov::TransportErrorKind::Offline;
        return ov::HttpResponse{};
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
struct FixedClock : ov::Clock {
    std::int64_t now_unix_ms() const override { return 1763200000000; }
};
struct StderrLog : ov::LogSink {
    void log(ov::LogLevel, rust::Str target, rust::Str msg) const override {
        std::fprintf(stderr, "[%s] %s\n", std::string(target).c_str(), std::string(msg).c_str());
    }
};

int failures = 0;

void check(bool ok, const char *what) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) {
        ++failures;
    }
}

// Runs a call into the core that has no server to talk to. It may succeed or fail with any
// ov::Error code (network_error, signed_out, invalid_request, ...); it must not crash or throw
// anything else. Returns whether it succeeded.
template <class F>
bool survives(const char *what, F &&f) {
    try {
        ov::call(std::forward<F>(f));
        check(true, (std::string(what) + " -> returned").c_str());
        return true;
    } catch (const ov::Error &e) {
        check(!e.code().empty(), (std::string(what) + " -> ov::Error " + e.code()).c_str());
    } catch (const std::exception &e) {
        check(false, (std::string(what) + " -> not an ov::Error: " + e.what()).c_str());
    }
    return false;
}

// Like survives(), but the call needs a server, so it must fail with an ov::Error.
template <class F>
void fails_cleanly(const char *what, F &&f) {
    try {
        ov::call(std::forward<F>(f));
        check(false, (std::string(what) + " -> returned without a server").c_str());
    } catch (const ov::Error &e) {
        check(!e.code().empty() && e.code() != "internal", (std::string(what) + " -> ov::Error " + e.code()).c_str());
    } catch (const std::exception &e) {
        check(false, (std::string(what) + " -> not an ov::Error: " + e.what()).c_str());
    }
}

std::string str(const rust::Vec<std::uint8_t> &v) {
    return std::string(reinterpret_cast<const char *>(v.data()), v.size());
}

rust::Vec<std::uint8_t> vec(const std::string &s) {
    rust::Vec<std::uint8_t> v;
    for (unsigned char c : s) {
        v.push_back(c);
    }
    return v;
}

// Never called: it only has to compile, so more of the C++ API is checked against the generated
// header than main() can run without a server (a ServiceAccount needs a real token).
[[maybe_unused]] void compile_only(const ov::Account &account, const ov::Vault &vault, const ov::ServiceAccount &sa,
                                   const ov::SelfHosted &server, const ov::CancelToken &cancel) {
    // register + recovery
    ov::RegisterInput input{"a@example.com", vec("pw"), ov::KdfOverrides{}, true};
    ov::NewAccount created = account.register_account(std::move(input), cancel);
    ov::wipe(created.secret_key);
    (void)account.recovery_status(cancel);
    // settings, devices, deletion
    (void)account.me(cancel);
    (void)account.devices(cancel);
    (void)account.deletion_preview(cancel);
    // sharing and orgs
    ov::Grantee grantee{ov::GranteeKind::Email, "b@example.com"};
    (void)account.share_vault("v", grantee, ov::VaultRole::Read, cancel);
    (void)account.orgs(cancel);
    (void)account.audit_log("o", "", true, 50, cancel);
    // plans
    ov::OptionalPlan plan = account.plan(cancel);
    (void)ov::plan_limit(plan.value, "members");
    (void)account.upgrade_url(ov::ErrorInfo{});
    // service-account admin + service accounts
    (void)account.service_accounts("o", cancel);
    (void)sa.read("ov://v/e/password", cancel);
    // share links
    (void)account.list_shares(cancel);
    // signed-out flows, sessions
    (void)account.signed_out(cancel);
    (void)account.park_session();
    // Vault edit, history, version diff, export
    ov::EntryInput entry{{}, {}, false, {}, false, 0, ov::EntryExpiry{ov::ExpiryKind::Keep, 0}};
    (void)vault.add_entry(vault.root_group_id(), std::move(entry));
    (void)vault.history("e");
    (void)vault.version_difference(vault, "e");
    (void)vault.export_plain(ov::ExportFormat::Csv, {});
    ov::ImportMode mode{ov::ImportModeKind::Merge, "", "", "v"};
    ov::ImportOutcome outcome = account.import_vault(vault, mode, cancel);
    (void)outcome.vault->name();
    // self-hosted
    (void)server.list_databases(cancel);
}

} // namespace

int main() {
    const std::string version(ov::version());
    std::printf("openvireo-core %s\n", version.c_str());
    check(!version.empty(), "version() is not empty");

    const std::string abc = "abc";
    rust::Slice<const std::uint8_t> data(reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
    const std::string digest = hex(ov::sha256(data));
    std::printf("sha256(\"abc\") = %s\n", digest.c_str());
    check(digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256 matches FIPS 180-2");

    // A wrong-length key is an OvError, carried through ov::call as ov::Error.
    try {
        ov::call([&] { return ov::aead_encrypt(data, data, data, data); });
        check(false, "aead_encrypt with a 3-byte key fails");
    } catch (const ov::Error &e) {
        check(e.code() == "invalid_request", "aead_encrypt with a 3-byte key fails with invalid_request");
    }

    ov::ClientConfig config{};
    config.device_name = "smoke";
    config.platform = ov::Platform::QtMacos;
    config.offline = true;
    auto client = ov::call([&] {
        return ov::new_client(config, std::make_unique<NoHttp>(), std::make_unique<NoStore>(),
                              std::make_unique<NoCache>(), std::make_unique<FixedClock>(),
                              std::make_unique<StderrLog>());
    });
    auto cancel = ov::new_cancel_token();
    try {
        ov::call([&] { return client->discover("https://accounts.example", *cancel); });
        check(false, "discover() without a server fails");
    } catch (const ov::Error &e) {
        std::printf("discover() -> %s\n", e.what());
        check(e.code() != "internal", "discover() without a server comes back as an ov::Error (not internal)");
    }

    // A cancelled token stops the call before it starts.
    auto gui_copy = cancel->clone();
    gui_copy->cancel();
    try {
        ov::call([&] { return client->discover("https://accounts.example", *cancel); });
        check(false, "a cancelled call fails");
    } catch (const ov::Error &e) {
        check(e.code() == "aborted", "a cancelled call fails with aborted");
    }

    // One call (or more) per bridged area. There is no server: the Host is offline, so network
    // calls come back as ov::Error; local work (vaults, TOTP, share payloads, record helpers) is
    // checked for its values.
    auto token = ov::new_cancel_token();

    // ---- client, remembered accounts, signed-out share links
    const ov::ClientConfig round = ov::call([&] { return client->config(); });
    check(std::string(round.device_name) == "smoke" && round.platform == ov::Platform::QtMacos && round.offline,
          "Client::config returns the config it was made with");
    survives("Client::remember_account (remembered accounts)",
             [&] { client->remember_account("a@example.com", "https://accounts.example", "u1"); });
    fails_cleanly("Client::share_info (share links, signed out)",
                  [&] { return client->share_info("https://accounts.example/api/v1", "s1", *token); });
    fails_cleanly("Client::open_share (share links, signed out)", [&] {
        ov::OpenShareInput input{vec("https://share.example/s/1#k"), false, {}, false, ov::ShareInfo{}};
        return client->open_share("https://accounts.example/api/v1", std::move(input), *token);
    });

    // ---- Account: a client with a known server connects without the network (signed out)
    ov::ClientConfig with_server = config;
    with_server.has_server = true;
    with_server.server.issuer = "https://accounts.example";
    with_server.server.api = "https://accounts.example/api/v1";
    with_server.server.sync = "https://sync.example/api/v1";
    with_server.server.jwks_uri = "https://accounts.example/.well-known/jwks.json";
    with_server.server.opaque_lib = "opaque-ke";
    with_server.server.opaque_version = "4";
    with_server.server.opaque_context = "ov-opaque-v1";
    with_server.server.opaque_ids = "accounts.example";
    auto server_client = ov::call([&] {
        return ov::new_client(with_server, std::make_unique<NoHttp>(), std::make_unique<NoStore>(),
                              std::make_unique<NoCache>(), std::make_unique<FixedClock>(),
                              std::make_unique<StderrLog>());
    });
    // A handle, or null when the call failed with an ov::Error (any code but internal).
    auto open = [&](const char *what, auto &&make) {
        using Box = decltype(make());
        std::unique_ptr<Box> out;
        try {
            out.reset(new Box(ov::call(make)));
            check(true, (std::string(what) + " -> returned").c_str());
        } catch (const ov::Error &e) {
            check(e.code() != "internal", (std::string(what) + " -> ov::Error " + e.code()).c_str());
        }
        return out;
    };
    auto account = open("connect (Account)", [&] { return server_client->connect("https://accounts.example", *token); });
    if (account != nullptr) {
        const ov::Account &a = **account;
        check(!ov::call([&] { return a.is_signed_in(); }), "Account is signed out without a stored session");
        survives("Account::stored_session (signed-out flows)", [&] { return a.stored_session(); });
        survives("Account::park_session (several accounts)", [&] { return a.park_session(); });
        fails_cleanly("Account::register_account (register)", [&] {
            ov::RegisterInput input{"a@example.com", vec("correct horse"), ov::KdfOverrides{}, true};
            return a.register_account(std::move(input), *token);
        });
        fails_cleanly("Account::recover_info (recovery)", [&] { return a.recover_info(vec("ov_rc_x"), *token); });
        fails_cleanly("Account::me (settings)", [&] { return a.me(*token); });
        fails_cleanly("Account::devices (devices)", [&] { return a.devices(*token); });
        fails_cleanly("Account::deletion_preview (deletion)", [&] { return a.deletion_preview(*token); });
        fails_cleanly("Account::share_vault (vault sharing)", [&] {
            ov::Grantee grantee{ov::GranteeKind::Email, "b@example.com"};
            return a.share_vault("v", grantee, ov::VaultRole::Read, *token);
        });
        fails_cleanly("Account::orgs (orgs)", [&] { return a.orgs(*token); });
        fails_cleanly("Account::plan (plans)", [&] { return a.plan(*token); });
        survives("Account::upgrade_url (plans)", [&] { return a.upgrade_url(ov::ErrorInfo{}); });
        fails_cleanly("Account::service_accounts (service-account admin)",
                      [&] { return a.service_accounts("o", *token); });
        fails_cleanly("Account::list_shares (share links)", [&] { return a.list_shares(*token); });
        fails_cleanly("Account::vault_history (history)", [&] { return a.vault_history("v", *token); });
    }

    // ---- Vault: a local database exercises edit, history, version diff and export for real
    ov::KdbxCredentials creds{true, vec("pw"), false, {}};
    auto vault = ov::call([&] { return ov::vault_create_local("Local", std::move(creds), *token); });
    check(std::string(ov::call([&] { return vault->name(); })) == "Local", "vault_create_local names the vault");
    const std::string group = std::string(ov::call([&] { return vault->add_group("", "Work"); }));
    ov::EntryInput input{{}, {}, false, {}, false, 0, ov::EntryExpiry{ov::ExpiryKind::Keep, 0}};
    input.fields.push_back(ov::FieldInput{"title", vec("Mail"), false, false});
    input.fields.push_back(ov::FieldInput{"password", vec("s3cret"), false, false});
    const std::string entry = std::string(ov::call([&] { return vault->add_entry(group, std::move(input)); }));
    check(!entry.empty(), "Vault::add_entry returns an id");
    const ov::EntryRecord record = ov::call([&] { return vault->entry(entry); });
    check(record.fields.size() >= 2, "Vault::entry returns the fields");
    ov::EntryInput edit{{}, {}, false, {}, false, 0, ov::EntryExpiry{ov::ExpiryKind::Keep, 0}};
    edit.fields.push_back(ov::FieldInput{"password", vec("n3w"), false, false});
    ov::call([&] { vault->edit_entry(entry, std::move(edit)); });
    check(ov::call([&] { return vault->history(entry); }).size() == 1, "Vault::edit_entry keeps one history version");
    survives("Vault::version_difference (version diff)", [&] { return vault->version_difference(*vault, entry); });
    rust::Vec<std::uint8_t> csv = ov::call([&] { return vault->export_plain(ov::ExportFormat::Csv, {}); });
    check(str(csv).find("Mail") != std::string::npos, "Vault::export_plain includes the entry");
    ov::wipe(csv);
    ov::call([&] { vault->delete_entry(entry); });
    check(ov::call([&] { return vault->is_in_recycle_bin(entry); }), "Vault::delete_entry moves it to the Recycle Bin");
    rust::Vec<std::uint8_t> kdbx = ov::call([&] { return vault->save_local(*token); });
    ov::KdbxCredentials again{true, vec("pw"), false, {}};
    auto reopened = ov::call([&] { return ov::vault_open_local(std::move(kdbx), std::move(again), *token); });
    check(ov::call([&] { return reopened->groups(); }).size() >= 2, "save_local + vault_open_local round-trip");

    // ---- service accounts, self-hosted
    fails_cleanly("service_account_from_token (service accounts)",
                  [&] { return ov::service_account_from_token(*client, vec("ov_sa_x"), *token); });
    auto server = open("self_hosted_connect (self-hosted)",
                       [&] { return ov::self_hosted_connect(*client, "https://sync.example", vec("device-token")); });
    if (server) {
        fails_cleanly("SelfHosted::list_databases (self-hosted)", [&] { return (*server)->list_databases(*token); });
    }
    survives("self_hosted_restore (self-hosted)", [&] { return ov::self_hosted_restore(*client, "https://sync.example"); });

    // ---- TOTP helpers: RFC 6238 appendix B, SHA-1, T = 59 s
    ov::TotpParams params = ov::call([&] {
        return ov::parse_totp_uri(vec("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8"));
    });
    ov::TotpCode code = ov::call([&] { return ov::totp_code(params, 59000); });
    check(str(code.code) == "94287082", "parse_totp_uri + totp_code give the RFC 6238 SHA-1 code at 59 s");
    ov::wipe(code.code);
    check(!ov::call([&] { return ov::entry_totp_uri({}, "label"); }).has, "entry_totp_uri of no fields is none");

    // ---- share payload helpers, deletion
    check(ov::call([] { return ov::default_share_fields(); }).size() == 3, "default_share_fields has 3 fields");
    check(std::string(ov::call([&] { return ov::text_share_payload(vec("hi"), "", ""); }).kind) == "text",
          "text_share_payload makes a text payload");
    check(!ov::call([] { return ov::deletion_expired("", 0); }), "deletion_expired without a date is false");

    // Record helpers.
    ov::Plan plan{};
    plan.id = "premium";
    plan.limits.push_back(ov::PlanLimit{"members", true, 6});
    const ov::OptionalI64 members = ov::call([&] { return ov::plan_limit(plan, "members"); });
    check(members.has && members.value == 6, "plan_limit(members) == 6 (plans)");
    check(!ov::call([&] { return ov::plan_has(plan, "audit_days"); }), "plan_has(audit_days) is false");
    check(ov::call([&] { return ov::plan_has_billing(plan); }), "plan_has_billing for a plan with an id");
    check(std::string(ov::call([&] { return ov::platform_as_str(ov::Platform::QtMacos); })) == "qt-macos",
          "platform_as_str(QtMacos) == qt-macos");
    check(survives("CancelToken::check on a fresh token", [&] { token->check(); }), "a fresh token isn't cancelled");

    failures += below_facade(OV_EXPECT_TEST_SERVER != 0);

    std::printf("%s\n", failures == 0 ? "smoke: all passed" : "smoke: FAILED");
    return failures == 0 ? 0 : 1;
}
