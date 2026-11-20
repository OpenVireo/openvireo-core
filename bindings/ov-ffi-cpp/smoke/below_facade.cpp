// The functions below the facade (README.md, "Desktop swap"), each against the contract vectors:
// vectors/test-vectors.json (crypto), vectors/opaque-transcripts.json (OPAQUE, including the replay
// of a login to an account libopaque registered) and vectors/merge-fixtures (merge_kdbx on the
// .kdbx copies in smoke/fixtures, checked by opening the result with the facade).
//
// The seeded OPAQUE steps and the server half need a package built with the test-server feature
// (`cargo xtask cpp --features test-server`); without it they must fail with `internal`.

#include "json.h"

#include <ovcore.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#ifndef OV_VECTORS_DIR
#error "OV_VECTORS_DIR must point at openvireo-core/vectors"
#endif
#ifndef OV_SMOKE_FIXTURES_DIR
#error "OV_SMOKE_FIXTURES_DIR must point at bindings/ov-ffi-cpp/smoke/fixtures"
#endif

using smoke::Json;
using Bytes = std::vector<std::uint8_t>;

namespace {

int failures = 0;

void check(bool ok, const std::string &what) {
    std::printf("%s %s\n", ok ? "ok  " : "FAIL", what.c_str());
    if (!ok) {
        ++failures;
    }
}

// Runs a check body; an exception counts as a failure of that check.
void guarded(const std::string &what, const std::function<void()> &body) {
    try {
        body();
    } catch (const ov::Error &e) {
        check(false, what + " threw ov::Error " + e.what());
    } catch (const std::exception &e) {
        check(false, what + " threw " + e.what());
    }
}

// The wire code a call fails with, or "" when it succeeds.
template <class F>
std::string fails_with(F &&f) {
    try {
        ov::call(std::forward<F>(f));
        return "";
    } catch (const ov::Error &e) {
        return e.code();
    }
}

Bytes from_hex(const std::string &h) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(h.substr(i, 2), nullptr, 16)));
    }
    return out;
}

Bytes from_b64u(const std::string &s) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '-' || c == '+') return 62;
        if (c == '_' || c == '/') return 63;
        return -1;
    };
    Bytes out;
    std::uint32_t acc = 0;
    int bits = 0;
    for (char c : s) {
        const int v = val(c);
        if (v < 0) {
            continue;
        }
        acc = (acc << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((acc >> bits) & 0xff));
        }
    }
    return out;
}

Bytes bytes(const std::string &s) { return Bytes(s.begin(), s.end()); }
Bytes bytes(const rust::Vec<std::uint8_t> &v) { return Bytes(v.begin(), v.end()); }

rust::Slice<const std::uint8_t> sl(const Bytes &b) { return {b.data(), b.size()}; }
rust::Slice<const std::uint8_t> sl(const std::string &s) {
    return {reinterpret_cast<const std::uint8_t *>(s.data()), s.size()};
}

rust::Vec<std::uint8_t> rvec(const Bytes &b) {
    rust::Vec<std::uint8_t> v;
    for (auto c : b) {
        v.push_back(c);
    }
    return v;
}

Bytes read_file(const std::string &path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("can't open " + path);
    }
    return Bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool exists(const std::string &path) { return std::ifstream(path).good(); }

// "YYYY-MM-DDTHH:MM:SSZ" → Unix seconds (days_from_civil).
std::int64_t utc_seconds(const std::string &t) {
    int y = std::stoi(t.substr(0, 4));
    const unsigned m = static_cast<unsigned>(std::stoi(t.substr(5, 2)));
    const unsigned d = static_cast<unsigned>(std::stoi(t.substr(8, 2)));
    const int hh = std::stoi(t.substr(11, 2)), mm = std::stoi(t.substr(14, 2)), ss = std::stoi(t.substr(17, 2));
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    const std::int64_t days = static_cast<std::int64_t>(era) * 146097 + static_cast<std::int64_t>(doe) - 719468;
    return days * 86400 + hh * 3600 + mm * 60 + ss;
}

std::string bare_id(std::string s) {
    s.erase(std::remove(s.begin(), s.end(), '-'), s.end());
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// ------------------------------------------------------------------------------------- crypto

void crypto(const Json &tv) {
    guarded("secret key", [&] {
        for (const auto &k : tv["secret_key"].array()) {
            const Bytes raw = from_hex(k["raw_hex"].str());
            check(std::string(ov::call([&] { return ov::format_secret_key(sl(raw)); })) == k["display"].str(),
                  "format_secret_key " + k["display"].str());
            check(bytes(ov::call([&] { return ov::parse_secret_key(k["display"].str()); })) == raw,
                  "parse_secret_key " + k["display"].str());
        }
        check(fails_with([] { return ov::parse_secret_key("K1-nope"); }) == "invalid_secret_key",
              "parse_secret_key of junk fails with invalid_secret_key");
        rust::Vec<std::uint8_t> fresh = ov::call([] { return ov::generate_secret_key(); });
        const Bytes f = bytes(fresh);
        check(f.size() == 16 && bytes(ov::parse_secret_key(ov::format_secret_key(sl(f)))) == f,
              "generate_secret_key gives 16 bytes that format and parse back");
        ov::wipe(fresh);
    });

    guarded("nfkc_utf8", [&] {
        for (const auto &a : tv["auk"].array()) {
            check(bytes(ov::call([&] { return ov::nfkc_utf8(sl(a["password"].str())); })) ==
                      from_hex(a["password_nfkc_hex"].str()),
                  "nfkc_utf8 matches auk.password_nfkc_hex");
        }
        const Bytes bad{0xff};
        check(fails_with([&] { return ov::nfkc_utf8(sl(bad)); }) == "invalid_request",
              "nfkc_utf8 of invalid UTF-8 fails with invalid_request");
    });

    guarded("keyset", [&] {
        const Json &k = tv["keyset"];
        const Bytes enc_sk = from_hex(k["enc_sk_hex"].str()), seed = from_hex(k["sign_seed_hex"].str());
        const ov::PublicKeys pk = ov::call([&] { return ov::keyset_from_secrets(sl(enc_sk), sl(seed)); });
        const Json &pub = k["public"];
        check(bytes(pk.enc_pk) == from_b64u(pub["enc_pk"].str()) && bytes(pk.sign_pk) == from_b64u(pub["sign_pk"].str()) &&
                  bytes(pk.sig) == from_b64u(pub["sig"].str()),
              "keyset_from_secrets matches keyset.public");
        check(std::string(pk.fingerprint) == pub["fingerprint"].str(), "keyset_from_secrets fingerprint");
        const Bytes epk = bytes(pk.enc_pk), spk = bytes(pk.sign_pk), sig = bytes(pk.sig);
        check(std::string(ov::fingerprint(sl(epk), sl(spk))) == pub["fingerprint"].str(), "fingerprint matches");
        check(ov::verify_public_keys(sl(epk), sl(spk), sl(sig)), "verify_public_keys accepts keyset.public");
        check(!ov::verify_public_keys(sl(spk), sl(epk), sl(sig)), "verify_public_keys rejects swapped keys");
        for (const auto &c : tv["public_keys"].array()) {
            const Bytes e = from_hex(c["enc_sk_hex"].str()), s = from_hex(c["sign_seed_hex"].str());
            const ov::PublicKeys p = ov::call([&] { return ov::keyset_from_secrets(sl(e), sl(s)); });
            check(std::string(p.fingerprint) == c["fingerprint"].str() && bytes(p.sig) == from_b64u(c["sig"].str()),
                  "keyset_from_secrets matches public_keys " + c["principal"].str());
        }

        // The AUK-wrapped keyset: wrap(enc_sk ‖ sign_seed) with the vector's nonce
        const Bytes auk = from_hex(k["auk_hex"].str()), nonce = from_hex(k["nonce_hex"].str());
        Bytes plain = enc_sk;
        plain.insert(plain.end(), seed.begin(), seed.end());
        const std::string &aad = k["aad"].str();
        const Bytes wrapped = bytes(ov::call([&] { return ov::wrap(sl(auk), sl(plain), sl(aad), sl(nonce)); }));
        check(wrapped == from_b64u(k["wrapped"].str()), "wrap with a fixed nonce matches keyset.wrapped");
        check(bytes(ov::call([&] { return ov::unwrap(sl(auk), sl(wrapped), sl(aad)); })) == plain,
              "unwrap opens keyset.wrapped");
        check(fails_with([&] { return ov::unwrap(sl(auk), sl(wrapped), sl(std::string("ov-other"))); }) ==
                  "decryption_failed",
              "unwrap with the wrong AAD fails with decryption_failed");
        const Bytes none;
        const Bytes random = bytes(ov::call([&] { return ov::wrap(sl(auk), sl(plain), sl(aad), sl(none)); }));
        check(random != wrapped && bytes(ov::unwrap(sl(auk), sl(random), sl(aad))) == plain,
              "wrap with an empty nonce takes a fresh one");

        // Curves
        check(bytes(ov::call([&] { return ov::x25519_public_key(sl(enc_sk)); })) == epk, "x25519_public_key");
        check(bytes(ov::call([&] { return ov::ed25519_public_key(sl(seed)); })) == spk, "ed25519_public_key");
    });

    guarded("ed25519 (restore proof)", [&] {
        // SPEC §18: the proof is the archived keyset's Ed25519 signature over the message
        const Json &r = tv["restore_proof"];
        const Bytes seed = from_hex(tv["keyset"]["sign_seed_hex"].str());
        const Bytes msg = from_hex(r["message_hex"].str());
        const Bytes proof = from_b64u(r["proof"].str());
        const Bytes pk = from_b64u(r["old_sign_pk"].str());
        check(bytes(ov::call([&] { return ov::ed25519_sign(sl(seed), sl(msg)); })) == proof,
              "ed25519_sign matches restore_proof.proof");
        check(ov::ed25519_verify(sl(pk), sl(msg), sl(proof)), "ed25519_verify accepts restore_proof.proof");
        const Bytes wrong = from_b64u(r["invalid"][0]["proof"].str());
        check(!ov::ed25519_verify(sl(pk), sl(msg), sl(wrong)), "ed25519_verify rejects " + r["invalid"][0]["case"].str());
    });

    guarded("seal", [&] {
        for (const auto &s : tv["seal"].array()) {
            const Bytes pk = from_b64u(s["recipient_enc_pk"].str()), sk = from_hex(s["recipient_enc_sk_hex"].str());
            const Bytes esk = from_hex(s["ephemeral_sk_hex"].str()), nonce = from_hex(s["nonce_hex"].str());
            const Bytes plain = from_hex(s["plaintext_hex"].str());
            const std::string &aad = s["aad"].str();
            const Bytes sealed =
                bytes(ov::call([&] { return ov::seal(sl(pk), sl(plain), sl(aad), sl(esk), sl(nonce)); }));
            check(sealed == from_b64u(s["sealed"].str()), "seal with fixed randomness matches " + aad);
            check(bytes(ov::call([&] { return ov::unseal(sl(sk), sl(sealed), sl(aad)); })) == plain, "unseal " + aad);
            check(bytes(ov::call([&] { return ov::seal_derived_key(sl(sk), sl(sealed)); })) ==
                      from_hex(s["derived_key_hex"].str()),
                  "seal_derived_key " + aad);
            const Bytes epk = from_hex(s["ephemeral_pk_hex"].str());
            check(bytes(ov::call([&] { return ov::x25519_shared(sl(sk), sl(epk)); })) ==
                      bytes(ov::call([&] { return ov::x25519_shared(sl(esk), sl(pk)); })),
                  "x25519_shared agrees both ways");
            const Bytes none;
            const Bytes fresh = bytes(ov::call([&] { return ov::seal(sl(pk), sl(plain), sl(aad), sl(none), sl(none)); }));
            check(fresh != sealed && bytes(ov::unseal(sl(sk), sl(fresh), sl(aad))) == plain,
                  "seal with empty randomness takes fresh values");
        }
        for (const auto &n : tv["seal_negative"].array()) {
            const Bytes sk = from_hex(n["recipient_enc_sk_hex"].str()), sealed = from_b64u(n["sealed"].str());
            const std::string code = fails_with([&] { return ov::unseal(sl(sk), sl(sealed), sl(n["aad"].str())); });
            check(!code.empty() && code != "internal", "unseal rejects: " + n["case"].str() + " (" + code + ")");
        }
        const Bytes one(32, 1), zero(32, 0);
        check(fails_with([&] { return ov::x25519_shared(sl(one), sl(zero)); }) == "low_order_point",
              "x25519_shared with a low-order point fails with low_order_point");
    });

    guarded("vault name, tokens", [&] {
        const Json &v = tv["vault_name"];
        const Bytes vk = from_hex(v["vault_key_hex"].str());
        check(bytes(ov::call([&] { return ov::vault_name_key(sl(vk)); })) == from_hex(v["name_key_hex"].str()),
              "vault_name_key matches vault_name.name_key_hex");

        const Json &sa = tv["service_account"];
        const ov::ServiceAccountToken t = ov::call([&] { return ov::parse_service_account_token(sa["token"].str()); });
        check(std::string(t.sa_id) == sa["sa_id"].str() && bytes(t.kek) == from_hex(sa["kek_hex"].str()),
              "parse_service_account_token");
        const Bytes secret = bytes(t.secret), kek = bytes(t.kek);
        check(std::string(ov::call([&] {
                  return ov::build_service_account_token(std::string(t.url), std::string(t.sa_id), sl(secret), sl(kek));
              })) == sa["token"].str(),
              "build_service_account_token gives the vector's token back");
        check(std::string(ov::call([&] { return ov::service_account_secret_hash(sl(secret)); })) ==
                  sa["secret_hash_hex"].str(),
              "service_account_secret_hash");
        check(std::string(ov::call([&] { return ov::service_account_secret_prefix(sl(secret)); })) ==
                  sa["secret_prefix"].str(),
              "service_account_secret_prefix");
        check(fails_with([] { return ov::parse_service_account_token("ov_sa_junk"); }) == "invalid_token",
              "parse_service_account_token of junk fails with invalid_token");
        // The SA master key wrapped under the token's KEK (SPEC §15) with the vector's nonce
        const Bytes master = from_hex(sa["master_key_hex"].str()), nonce = from_hex(sa["wrapped_master_nonce_hex"].str());
        const Bytes wm = bytes(ov::call(
            [&] { return ov::wrap(sl(kek), sl(master), sl(sa["wrapped_master_aad"].str()), sl(nonce)); }));
        check(wm == from_b64u(sa["wrapped_master"].str()), "wrap matches service_account.wrapped_master");

        const Json &rt = tv["refresh_token"];
        check(std::string(ov::refresh_token_hash(rt["token"].str())) == rt["stored_hash_hex"].str(),
              "refresh_token_hash matches refresh_token.stored_hash_hex");
    });
}

// ------------------------------------------------------------------------------------- OPAQUE

std::string hex(const rust::Vec<std::uint8_t> &v) {
    static const char d[] = "0123456789abcdef";
    std::string out;
    for (auto b : v) {
        out += d[b >> 4];
        out += d[b & 0xf];
    }
    return out;
}

void opaque(const Json &tr, bool test_server) {
    const Json &lo = tr["libopaque"];
    const std::string &pw = lo["password"].str(), &u = lo["id_u"].str(), &s = lo["id_s"].str(), &c = lo["context"].str();

    guarded("OPAQUE client", [&] {
        check(hex(ov::call([&] { return ov::nfkc_utf8(sl(pw)); })) == lo["password_nfkc_hex"].str(),
              "nfkc_utf8 of the transcript password (ligature → fi)");
        // Fresh randomness can't reproduce a transcript, but the steps run and a stale KE2 fails
        const Json &l = lo["login_opaque_ke_client"];
        ov::OpaqueStart start = ov::call([&] { return ov::opaque_start_login(sl(pw)); });
        check(hex(start.message).size() == l["ke1_hex"].str().size(), "opaque_start_login gives a KE1");
        const Bytes state = bytes(start.state), ke2 = from_hex(l["ke2_hex"].str());
        check(fails_with([&] { return ov::opaque_finish_login(sl(state), sl(ke2), sl(u), sl(s), sl(c)); }) ==
                  "opaque_failed",
              "opaque_finish_login with someone else's KE2 fails with opaque_failed");
        ov::wipe(start.state);
        const Json &r = lo["opaque_ke_registration"];
        ov::OpaqueStart reg = ov::call([&] { return ov::opaque_start_registration(sl(pw)); });
        const Bytes rstate = bytes(reg.state), resp = from_hex(r["response_hex"].str());
        const auto record = ov::call([&] { return ov::opaque_finish_registration(sl(rstate), sl(resp), sl(u), sl(s)); });
        check(hex(record).size() == r["record_hex"].str().size(),
              "opaque_start_registration + opaque_finish_registration give a record");
    });

    check(ov::test_server_enabled() == test_server,
          std::string("test_server_enabled() is ") + (test_server ? "true" : "false"));
    if (!test_server) {
        const Bytes seed(32, 0);
        check(fails_with([&] { return ov::opaque_start_login_seeded(sl(pw), sl(seed)); }) == "internal",
              "opaque_start_login_seeded fails with internal without test-server");
        check(fails_with([&] { return ov::opaque_server_registration_response(sl(pw)); }) == "internal",
              "opaque_server_registration_response fails with internal without test-server");
        return;
    }

    guarded("OPAQUE libopaque replay", [&] {
        // The opaque-ke client logging in to an account libopaque registered (W3-ID's acceptance)
        const Json &l = lo["login_opaque_ke_client"];
        const Bytes s1 = from_hex(l["client_start_seed_hex"].str()), s2 = from_hex(l["client_finish_seed_hex"].str());
        ov::OpaqueStart start = ov::call([&] { return ov::opaque_start_login_seeded(sl(pw), sl(s1)); });
        check(hex(start.message) == l["ke1_hex"].str(), "libopaque replay: KE1 matches");
        const Bytes state = bytes(start.state), ke2 = from_hex(l["ke2_hex"].str());
        ov::OpaqueLogin fin =
            ov::call([&] { return ov::opaque_finish_login_seeded(sl(state), sl(ke2), sl(u), sl(s), sl(c), sl(s2)); });
        check(hex(fin.auth_u) == l["auth_u_hex"].str() && l["auth_u_hex"].str() == l["expected_auth_u_hex"].str(),
              "libopaque replay: auth_u is the one libopaque expects");
        check(hex(fin.session_key) == l["session_key_hex"].str(), "libopaque replay: session key matches");
        check(hex(fin.export_key) == lo["registration"]["export_key_hex"].str(),
              "libopaque replay: export key is the registration's");
        ov::wipe(fin.session_key);
        ov::wipe(fin.export_key);
        ov::OpaqueStart wrong = ov::opaque_start_login_seeded(sl(std::string("wrong")), sl(s1));
        const Bytes wstate = bytes(wrong.state);
        check(fails_with([&] { return ov::opaque_finish_login_seeded(sl(wstate), sl(ke2), sl(u), sl(s), sl(c), sl(s2)); }) ==
                  "opaque_failed",
              "libopaque replay: the wrong password fails with opaque_failed");

        // The opaque-ke client registering on the libopaque server
        const Json &r = lo["opaque_ke_registration"];
        const Bytes r1 = from_hex(r["client_start_seed_hex"].str()), r2 = from_hex(r["client_finish_seed_hex"].str());
        ov::OpaqueStart reg = ov::call([&] { return ov::opaque_start_registration_seeded(sl(pw), sl(r1)); });
        check(hex(reg.message) == r["request_hex"].str(), "libopaque registration: request matches");
        const Bytes rstate = bytes(reg.state), resp = from_hex(r["response_hex"].str());
        check(hex(ov::call([&] {
                  return ov::opaque_finish_registration_seeded(sl(rstate), sl(resp), sl(u), sl(s), sl(r2));
              })) == r["record_hex"].str(),
              "libopaque registration: record matches");
    });

    guarded("OPAQUE opaque-ke transcript", [&] {
        const Json &t = tr["opaque_ke"];
        const std::string &tpw = t["password"].str(), &tu = t["id_u"].str(), &ts = t["id_s"].str(),
                          &tc = t["context"].str();
        const Json &reg = t["registration"];
        auto seed = [](const Json &j, const char *k) { return from_hex(j[k].str()); };
        const Bytes rs1 = seed(reg, "client_start_seed_hex"), rss = seed(reg, "server_seed_hex"),
                    rs2 = seed(reg, "client_finish_seed_hex");
        ov::OpaqueStart start = ov::call([&] { return ov::opaque_start_registration_seeded(sl(tpw), sl(rs1)); });
        const Bytes req = bytes(start.message), state = bytes(start.state);
        ov::OpaqueServerStep srv =
            ov::call([&] { return ov::opaque_server_registration_response_seeded(sl(req), sl(rss)); });
        check(hex(srv.message) == reg["response_hex"].str() && hex(srv.state) == reg["server_setup_hex"].str(),
              "opaque_server_registration_response_seeded matches");
        const Bytes resp = bytes(srv.message), setup = bytes(srv.state);
        const auto record =
            ov::call([&] { return ov::opaque_finish_registration_seeded(sl(state), sl(resp), sl(tu), sl(ts), sl(rs2)); });
        check(hex(record) == reg["record_hex"].str(), "opaque_finish_registration_seeded matches");
        const Bytes rec = bytes(record);
        const auto stored = ov::call([&] { return ov::opaque_server_store_record(sl(setup), sl(rec)); });
        check(hex(stored) == reg["stored_record_hex"].str(), "opaque_server_store_record matches");
        const Bytes st = bytes(stored);

        for (const char *which : {"login", "login_wrong_password"}) {
            const Json &l = t[which];
            const std::string &lpw = l.has("password") ? l["password"].str() : tpw;
            const Bytes l1 = seed(l, "client_start_seed_hex"), ls = seed(l, "server_seed_hex"),
                        l2 = seed(l, "client_finish_seed_hex");
            ov::OpaqueStart ls1 = ov::call([&] { return ov::opaque_start_login_seeded(sl(lpw), sl(l1)); });
            check(hex(ls1.message) == l["ke1_hex"].str(), std::string(which) + ": opaque_start_login_seeded KE1");
            const Bytes ke1 = bytes(ls1.message), cstate = bytes(ls1.state);
            ov::OpaqueServerStep cr = ov::call([&] {
                return ov::opaque_server_credential_response_seeded(sl(ke1), sl(st), sl(tu), sl(ts), sl(tc), sl(ls));
            });
            check(hex(cr.message) == l["ke2_hex"].str(), std::string(which) + ": opaque_server_credential_response_seeded KE2");
            const Bytes ke2 = bytes(cr.message), sstate = bytes(cr.state);
            if (std::string(which) == "login") {
                ov::OpaqueLogin fin = ov::call(
                    [&] { return ov::opaque_finish_login_seeded(sl(cstate), sl(ke2), sl(tu), sl(ts), sl(tc), sl(l2)); });
                check(hex(fin.auth_u) == l["auth_u_hex"].str() && hex(fin.session_key) == l["session_key_hex"].str() &&
                          hex(fin.export_key) == l["export_key_hex"].str(),
                      "login: opaque_finish_login_seeded matches");
                const Bytes auth = bytes(fin.auth_u);
                check(hex(ov::call([&] { return ov::opaque_server_user_auth(sl(sstate), sl(auth)); })) ==
                          l["session_key_hex"].str(),
                      "login: opaque_server_user_auth gives the same session key");
            } else {
                check(fails_with([&] {
                          return ov::opaque_finish_login_seeded(sl(cstate), sl(ke2), sl(tu), sl(ts), sl(tc), sl(l2));
                      }) == "opaque_failed",
                      "login_wrong_password: opaque_finish_login_seeded fails with opaque_failed");
            }
        }

        // The unseeded server half, end to end
        ov::OpaqueStart a = ov::opaque_start_registration(sl(tpw));
        const Bytes areq = bytes(a.message), ast = bytes(a.state);
        ov::OpaqueServerStep b = ov::call([&] { return ov::opaque_server_registration_response(sl(areq)); });
        const Bytes bresp = bytes(b.message), bsetup = bytes(b.state);
        const Bytes rec2 = bytes(ov::opaque_finish_registration(sl(ast), sl(bresp), sl(tu), sl(ts)));
        const Bytes st2 = bytes(ov::opaque_server_store_record(sl(bsetup), sl(rec2)));
        ov::OpaqueStart l = ov::opaque_start_login(sl(tpw));
        const Bytes ke1 = bytes(l.message), lst = bytes(l.state);
        ov::OpaqueServerStep cr =
            ov::call([&] { return ov::opaque_server_credential_response(sl(ke1), sl(st2), sl(tu), sl(ts), sl(tc)); });
        const Bytes ke2 = bytes(cr.message), sst = bytes(cr.state);
        ov::OpaqueLogin fin = ov::opaque_finish_login(sl(lst), sl(ke2), sl(tu), sl(ts), sl(tc));
        const Bytes auth = bytes(fin.auth_u);
        check(bytes(ov::opaque_server_user_auth(sl(sst), sl(auth))) == bytes(fin.session_key),
              "unseeded register + login against opaque_server_* agree on the session key");
    });
}

// ------------------------------------------------------------------------------------- merge

// Opens a merged copy with the facade and compares it with the fixture's expected projection.
void compare(const std::string &what, const Bytes &kdbx, const std::string &password, const Json &expected) {
    auto cancel = ov::new_cancel_token();
    ov::KdbxCredentials creds{true, rvec(bytes(password)), false, {}, false, {}};
    auto vault = ov::call([&] { return ov::vault_open_local(rvec(kdbx), std::move(creds), *cancel); });
    const std::string root = bare_id(std::string(vault->root_group_id()));
    const auto entries = ov::call([&] { return vault->entries(true); });
    const auto &want = expected["entries"].array();
    check(entries.size() == want.size(), what + ": " + std::to_string(want.size()) + " entries");
    for (const auto &w : want) {
        const std::string id = bare_id(w["uuid"].str());
        const auto it = std::find_if(entries.begin(), entries.end(),
                                     [&](const ov::EntrySummary &e) { return bare_id(std::string(e.id)) == id; });
        if (it == entries.end()) {
            check(false, what + ": entry " + w["uuid"].str() + " is there");
            continue;
        }
        const std::string group = w.has("group") ? bare_id(w["group"].str()) : root;
        check(bare_id(std::string(it->group_id)) == group, what + ": entry is in its group");
        const ov::EntryRecord rec = ov::call([&] { return vault->entry(std::string(it->id)); });
        bool fields_ok = true;
        for (const auto &kv : w["attributes"].object()) {
            const auto f = std::find_if(rec.fields.begin(), rec.fields.end(), [&](const ov::FieldRecord &r) {
                return lower(std::string(r.name)) == lower(kv.first);
            });
            const bool ok = f != rec.fields.end() && bytes(f->value) == bytes(kv.second.str());
            if (!ok) {
                std::printf("     field %s differs\n", kv.first.c_str());
            }
            fields_ok = fields_ok && ok;
        }
        check(fields_ok, what + ": every field has the expected value");
        const std::int64_t modified = utc_seconds(w["modified"].str());
        check(rec.modified_at == modified || rec.modified_at == modified * 1000, what + ": modification time");
        check(rec.history_count == static_cast<std::uint32_t>(w["history_count"].number()),
              what + ": history count " + std::to_string(rec.history_count));
    }
}

void merge(const std::string &fixtures_dir, const std::string &vectors_dir) {
    // The smoke fixtures' password (tests/merge_kdbx.rs); the key component is its SHA-256
    const std::string password = "ov-ffi-cpp merge fixture";
    const Bytes key = bytes(ov::sha256(sl(password)));
    for (const char *name : {"07-no-base-newer-wins", "11-moved-here-edited-there"}) {
        guarded(std::string("merge_kdbx ") + name, [&] {
            const Json fx = Json::parse_file(vectors_dir + "/merge-fixtures/" + name + ".json");
            const std::string prefix = fixtures_dir + "/" + name;
            const Bytes local = read_file(prefix + ".local.kdbx"), remote = read_file(prefix + ".remote.kdbx");
            const Bytes base = exists(prefix + ".base.kdbx") ? read_file(prefix + ".base.kdbx") : Bytes{};
            const bool has_base = fx.has("base") && fx["base"].kind() != Json::Kind::Null;
            check(base.empty() == !has_base, std::string(name) + ": base copy present iff the fixture has one");
            const Bytes base_key = base.empty() ? Bytes{} : key;
            const ov::KdbxMergeResult r = ov::call([&] {
                return ov::merge_kdbx(sl(local), sl(key), sl(remote), sl(key), sl(base), sl(base_key),
                                      utc_seconds(fx["now"].str()));
            });
            check(r.local_changed == !r.local.empty() && r.remote_changed == !r.remote.empty(),
                  std::string(name) + ": a copy comes back iff it changed");
            check(!r.changes.empty(), std::string(name) + ": the merge reports its changes");
            for (const auto &c : r.changes) {
                const bool db = c.subject == ov::ChangeSubject::Database;
                if (db ? !c.uuid.empty() : c.uuid.size() != 16) {
                    check(false, std::string(name) + ": change uuid has 16 bytes (or none for the database)");
                }
            }
            check(r.conflicts.size() == fx["expected"]["conflicts"].object().size(),
                  std::string(name) + ": conflicts match");
            const Json &want = fx["expected"]["result"];
            compare(std::string(name) + " local", r.local_changed ? bytes(r.local) : local, password, want);
            compare(std::string(name) + " remote", r.remote_changed ? bytes(r.remote) : remote, password, want);
        });
    }
    const Bytes junk = bytes(std::string("not a kdbx"));
    const Bytes short_key(31, 0);
    check(fails_with([&] { return ov::merge_kdbx(sl(junk), sl(short_key), sl(junk), sl(short_key), {}, {}, 0); }) ==
              "invalid_request",
          "merge_kdbx with a 31-byte key fails with invalid_request");
    const std::string code = fails_with([&] { return ov::merge_kdbx(sl(junk), sl(key), sl(junk), sl(key), {}, {}, 0); });
    check(!code.empty() && code != "internal", "merge_kdbx of junk fails cleanly (" + code + ")");
}

} // namespace

// Returns the number of failed checks.
int below_facade(bool test_server) {
    std::printf("-- below the facade (test-server %s)\n", test_server ? "on" : "off");
    try {
        const Json tv = Json::parse_file(std::string(OV_VECTORS_DIR) + "/test-vectors.json");
        const Json tr = Json::parse_file(std::string(OV_VECTORS_DIR) + "/opaque-transcripts.json");
        crypto(tv);
        opaque(tr, test_server);
        merge(OV_SMOKE_FIXTURES_DIR, OV_VECTORS_DIR);
    } catch (const std::exception &e) {
        check(false, std::string("reading the vectors: ") + e.what());
    }
    return failures;
}
