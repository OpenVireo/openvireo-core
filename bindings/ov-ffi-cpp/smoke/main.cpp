// Calls the core through the OpenVireoCore package: version(), one primitive (SHA-256 "abc",
// FIPS 180-2), and the Host + error path (a facade stub's panic must come back as ov::Error
// "internal", not crash the process).

#include <ovcore.h>

#include <cstdio>
#include <memory>
#include <string>

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

    std::printf("%s\n", failures == 0 ? "smoke: all passed" : "smoke: FAILED");
    return failures == 0 ? 0 : 1;
}
