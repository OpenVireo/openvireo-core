// openvireo-core for C++: include this header (installed as <ovcore.h>).
//
// - ov::version(), the crypto primitives, the functions below the facade (ov v1 crypto, OPAQUE
//   steps, ov::merge_kdbx; README.md), ov::new_client() and the handles (ov::Client,
//   ov::Account, ov::Vault, ov::ServiceAccount, ov::SelfHosted, ov::EventStream, ov::TotpChallenge,
//   ov::LoginStep, ov::CancelToken)
//   come from the generated bridge (ov-ffi-cpp/src/lib.rs.h).
// - The Host interfaces to implement are in ov-ffi-cpp/include/host.h.
// - Calls that fail throw rust::Error. Wrap them in ov::call() to get an ov::Error that carries
//   the full OvError (wire code, status, retry-after, details, server code).
//
// Every call that can touch the network or run a KDF blocks the calling thread until it is done:
// call them from a worker thread (QThreadPool / QtConcurrent), never the GUI thread, and cancel
// from anywhere with CancelToken::cancel() on a clone() of the token. See README.md.

#pragma once

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#include "ov-ffi-cpp/src/lib.rs.h"

namespace ov {

// An OvError from the core.
class Error : public std::runtime_error {
public:
    explicit Error(ErrorInfo info)
        : std::runtime_error(std::string(info.code) + ": " + std::string(info.message)), info_(std::move(info)) {}

    // The stable wire code, e.g. "plan_limit", "aborted", "internal" (rust-core-tasks.md §2.4).
    std::string code() const { return std::string(info_.code); }
    // Human-readable, English, may change. Never contains secrets.
    std::string message() const { return std::string(info_.message); }
    // All fields (status 0 = none; details is a JSON object string or empty).
    const ErrorInfo &info() const { return info_; }

private:
    ErrorInfo info_;
};

// Runs `f` (a call into the core) and turns a failure into ov::Error. The core records the
// failing call's OvError on the calling thread; this reads it right away, on the same thread.
template <class F>
auto call(F &&f) -> decltype(std::forward<F>(f)()) {
    try {
        return std::forward<F>(f)();
    } catch (const rust::Error &) {
        throw Error(take_last_error());
    }
}

// Wipes a byte buffer the core returned (secrets cross as bytes; the caller wipes them).
inline void wipe(rust::Vec<std::uint8_t> &bytes) {
    volatile std::uint8_t *p = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        p[i] = 0;
    }
    bytes.clear();
}

} // namespace ov
