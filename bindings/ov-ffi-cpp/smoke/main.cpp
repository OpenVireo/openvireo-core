// Calls the core through the OpenVireoCore package: version(), one primitive (SHA-256 "abc",
// FIPS 180-2), and the Host + error path (a facade stub's panic must come back as ov::Error
// "internal", not crash the process), for one entry point of every bridged area. The record
// helpers (plan_limit, platform_as_str) are real code and are checked for their values.

#include <ovcore.h>

#include <cstdio>
#include <memory>
#include <string>
#include <utility>

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

// Runs a call into a facade stub: it must come back as ov::Error "internal", not crash.
template <class F>
void expect_internal(const char *what, F &&f) {
    try {
        ov::call(std::forward<F>(f));
        check(false, what);
    } catch (const ov::Error &e) {
        const std::string label = std::string(what) + " -> " + e.code();
        check(e.code() == "internal", label.c_str());
    }
}

rust::Vec<std::uint8_t> vec(const std::string &s) {
    rust::Vec<std::uint8_t> v;
    for (unsigned char c : s) {
        v.push_back(c);
    }
    return v;
}

// Never called: it only has to compile, so the C++ side of one method per bridged area is checked
// against the generated header. (Account, Vault, ServiceAccount and SelfHosted handles come only
// from facade constructors, which are still todo!() stubs, so these can't run yet.)
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
        check(false, "discover() on the stub facade fails");
    } catch (const ov::Error &e) {
        std::printf("discover() -> %s\n", e.what());
        check(e.code() == "internal", "a panicking stub comes back as ov::Error internal");
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

    // One call per newly bridged area that can run without an Account or Vault handle. Each
    // reaches a facade todo!() stub and must come back as ov::Error "internal".
    auto token = ov::new_cancel_token();
    const ov::ClientConfig round = ov::call([&] { return client->config(); });
    check(std::string(round.device_name) == "smoke" && round.platform == ov::Platform::QtMacos && round.offline,
          "Client::config returns the config it was made with");
    expect_internal("Client::remember_account (remembered accounts)",
                    [&] { client->remember_account("a@example.com", "https://accounts.example", "u1"); });
    expect_internal("Client::share_info (share links, signed out)",
                    [&] { return client->share_info("https://accounts.example/api/v1", "s1", *token); });
    expect_internal("Client::open_share (share links, signed out)", [&] {
        ov::OpenShareInput input{vec("https://share.example/s/1#k"), false, {}, false, ov::ShareInfo{}};
        return client->open_share("https://accounts.example/api/v1", std::move(input), *token);
    });
    expect_internal("connect (Account signed-out flows)",
                    [&] { return client->connect("https://accounts.example", *token); });
    expect_internal("vault_create_local (Vault edit)", [&] {
        ov::KdbxCredentials creds{true, vec("pw"), false, {}};
        return ov::vault_create_local("Local", std::move(creds), *token);
    });
    expect_internal("service_account_from_token (service accounts)",
                    [&] { return ov::service_account_from_token(*client, vec("ov_sa_x"), *token); });
    expect_internal("self_hosted_connect (self-hosted)", [&] {
        return ov::self_hosted_connect(*client, "https://sync.example", vec("device-token"));
    });
    expect_internal("self_hosted_restore (self-hosted)",
                    [&] { return ov::self_hosted_restore(*client, "https://sync.example"); });
    expect_internal("parse_totp_uri (TOTP helpers)",
                    [&] { return ov::parse_totp_uri(vec("otpauth://totp/x?secret=GEZDGNBV")); });
    expect_internal("entry_totp_uri (TOTP helpers)", [&] { return ov::entry_totp_uri({}, "label"); });
    expect_internal("text_share_payload (share links)", [&] { return ov::text_share_payload(vec("hi"), "", ""); });
    expect_internal("default_share_fields (share links)", [&] { return ov::default_share_fields(); });
    expect_internal("deletion_expired (account deletion)", [&] { return ov::deletion_expired("", 0); });

    // Record helpers (and Client::config above) are plain Rust, not stubs: they work now.
    ov::Plan plan{};
    plan.id = "premium";
    plan.limits.push_back(ov::PlanLimit{"members", true, 6});
    const ov::OptionalI64 members = ov::call([&] { return ov::plan_limit(plan, "members"); });
    check(members.has && members.value == 6, "plan_limit(members) == 6 (plans)");
    check(!ov::call([&] { return ov::plan_has(plan, "audit_days"); }), "plan_has(audit_days) is false");
    check(ov::call([&] { return ov::plan_has_billing(plan); }), "plan_has_billing for a plan with an id");
    check(std::string(ov::call([&] { return ov::platform_as_str(ov::Platform::QtMacos); })) == "qt-macos",
          "platform_as_str(QtMacos) == qt-macos");
    check([&] {
        try {
            ov::call([&] { token->check(); });
            return true;
        } catch (const ov::Error &) {
            return false;
        }
    }(), "CancelToken::check on a fresh token");

    std::printf("%s\n", failures == 0 ? "smoke: all passed" : "smoke: FAILED");
    return failures == 0 ? 0 : 1;
}
