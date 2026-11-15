// The Host interfaces the desktop implements in Qt (rust-core-tasks.md §2.2, crates/ov-core/src/host.rs).
//
// Each class is a pure-virtual C++ mirror of one Rust Host trait. Implement them, hand them to
// ov::new_client() as std::unique_ptr, and the core calls them back through cxx.
//
// Rules for implementations:
// - Thread safety: the core may call any method from any thread that is inside a core call,
//   and concurrently. Guard shared state. (Qt: don't touch QObjects owned by another thread
//   without a queued/blocking connection.)
// - Blocking: methods are synchronous. A call returns when the work is done (e.g. the HTTP
//   response has fully arrived). The core calls them from the worker thread that made the core
//   call, never from the thread that owns the UI unless the app calls the core from there.
// - Errors: HttpTransport/ByteStream report transport failures through `failure` (kind + text)
//   and return a default-constructed value. Everything else reports errors by throwing; the
//   exception's what() may start with an ov wire code and ": " (e.g. "forbidden: keychain
//   locked") to choose the OvError code, otherwise the code is "internal".
// - Secrets: values passed to SecureStore::set are secrets; wipe your copies.
//
// This header is included by the generated bridge before the shared structs are defined, so it
// only forward-declares them. Include "ovcore.h" in your own code, not this file.

#pragma once

#include <cstdint>
#include <memory>

#include "rust/cxx.h"

namespace ov {

struct HttpRequest;
struct HttpResponse;
struct TransportFailure;
struct CachedVault;
enum class LogLevel : std::uint8_t;

// The body of an open server-sent-events stream (Rust `ByteStream`).
class ByteStream {
public:
    virtual ~ByteStream() = default;
    // The status the stream was opened with.
    virtual std::uint16_t status() const = 0;
    // Fills `chunk` with the next bytes and returns true, or returns false when the server
    // closed the stream. On a transport failure, set `failure` and return false.
    virtual bool next_chunk(rust::Vec<std::uint8_t> &chunk, TransportFailure &failure) const = 0;
    // Closes the stream; later next_chunk calls return false.
    virtual void close() const = 0;
};

// HTTP (Rust `HttpTransport`): QNetworkAccessManager on the desktop. Must not follow redirects,
// add cookies or log header values (they carry bearer tokens).
class HttpTransport {
public:
    virtual ~HttpTransport() = default;
    // Sends one request and returns the whole response (any status). On a transport failure
    // (offline, timeout, TLS, cancelled), set `failure.kind` and return HttpResponse{}.
    virtual HttpResponse send(const HttpRequest &req, TransportFailure &failure) const = 0;
    // Opens a server-sent-events stream. On failure set `failure` and return nullptr.
    virtual std::unique_ptr<ByteStream> open_stream(const HttpRequest &req, TransportFailure &failure) const = 0;
};

// Small persistent secrets (Rust `SecureStore`): the keychain / DPAPI / libsecret.
class SecureStore {
public:
    virtual ~SecureStore() = default;
    // Fills `value` and returns true, or returns false if `key` is missing. Throw if the store
    // can't be read (that is not the same as missing).
    virtual bool get(rust::Str key, rust::Vec<std::uint8_t> &value) const = 0;
    virtual void set(rust::Str key, rust::Slice<const std::uint8_t> value) const = 0;
    // Removing a missing key is not an error. (Rust `delete`, a C++ keyword.)
    virtual void remove(rust::Str key) const = 0;
};

// The offline cache (Rust `BlobCache`, SPEC §20): AccountOfflineCache on the desktop.
class BlobCache {
public:
    virtual ~BlobCache() = default;
    // Fills `out` and returns true, or returns false when nothing is cached.
    virtual bool load(rust::Str user_id, rust::Str vault_id, CachedVault &out) const = 0;
    virtual void save(rust::Str user_id, rust::Str vault_id, const CachedVault &v) const = 0;
    virtual void remove(rust::Str user_id, rust::Str vault_id) const = 0;
    virtual rust::Vec<rust::String> list(rust::Str user_id) const = 0;
    virtual bool load_meta(rust::Str user_id, rust::Str name, rust::Vec<std::uint8_t> &value) const = 0;
    virtual void save_meta(rust::Str user_id, rust::Str name, rust::Slice<const std::uint8_t> value) const = 0;
    virtual void clear_user(rust::Str user_id) const = 0;
};

// Wall-clock time (Rust `Clock`).
class Clock {
public:
    virtual ~Clock() = default;
    // Milliseconds since the Unix epoch.
    virtual std::int64_t now_unix_ms() const = 0;
};

// Log lines (Rust `LogSink`): qDebug and friends. The core never logs secrets.
class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void log(LogLevel level, rust::Str target, rust::Str msg) const = 0;
};

} // namespace ov
