// A minimal JSON reader for the smoke test, so it reads the contract vectors (vectors/*.json)
// without a third-party library. It handles what those files use: objects, arrays, strings (with
// \uXXXX escapes and surrogate pairs), numbers, true/false/null. It throws std::runtime_error on
// malformed input and on a missing key or wrong type.

#pragma once

#include <cstdint>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace smoke {

class Json {
public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    static Json parse_file(const std::string &path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            throw std::runtime_error("can't open " + path);
        }
        std::stringstream buf;
        buf << in.rdbuf();
        const std::string text = buf.str();
        std::size_t at = 0;
        Json v = parse_value(text, at);
        skip_ws(text, at);
        if (at != text.size()) {
            throw std::runtime_error(path + ": trailing data");
        }
        return v;
    }

    Kind kind() const { return kind_; }
    bool has(const std::string &key) const { return kind_ == Kind::Object && object_.count(key) != 0; }

    const Json &operator[](const std::string &key) const {
        if (kind_ != Kind::Object) {
            throw std::runtime_error("not an object (looking up \"" + key + "\")");
        }
        auto it = object_.find(key);
        if (it == object_.end()) {
            throw std::runtime_error("no key \"" + key + "\"");
        }
        return it->second;
    }
    const Json &operator[](std::size_t i) const { return array().at(i); }

    const std::vector<Json> &array() const {
        if (kind_ != Kind::Array) {
            throw std::runtime_error("not an array");
        }
        return array_;
    }
    const std::map<std::string, Json> &object() const {
        if (kind_ != Kind::Object) {
            throw std::runtime_error("not an object");
        }
        return object_;
    }
    const std::string &str() const {
        if (kind_ != Kind::String) {
            throw std::runtime_error("not a string");
        }
        return string_;
    }
    double number() const {
        if (kind_ != Kind::Number) {
            throw std::runtime_error("not a number");
        }
        return number_;
    }

private:
    Kind kind_ = Kind::Null;
    bool bool_ = false;
    double number_ = 0;
    std::string string_;
    std::vector<Json> array_;
    std::map<std::string, Json> object_;

    static void skip_ws(const std::string &t, std::size_t &at) {
        while (at < t.size() && (t[at] == ' ' || t[at] == '\n' || t[at] == '\r' || t[at] == '\t')) {
            ++at;
        }
    }

    static void expect(const std::string &t, std::size_t &at, char c) {
        skip_ws(t, at);
        if (at >= t.size() || t[at] != c) {
            throw std::runtime_error(std::string("JSON: expected '") + c + "' at offset " + std::to_string(at));
        }
        ++at;
    }

    static void utf8(std::string &out, std::uint32_t cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xc0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xe0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        } else {
            out += static_cast<char>(0xf0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3f));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3f));
            out += static_cast<char>(0x80 | (cp & 0x3f));
        }
    }

    static std::uint32_t hex4(const std::string &t, std::size_t &at) {
        if (at + 4 > t.size()) {
            throw std::runtime_error("JSON: short \\u escape");
        }
        const std::uint32_t v = static_cast<std::uint32_t>(std::stoul(t.substr(at, 4), nullptr, 16));
        at += 4;
        return v;
    }

    static std::string parse_string(const std::string &t, std::size_t &at) {
        expect(t, at, '"');
        std::string out;
        while (true) {
            if (at >= t.size()) {
                throw std::runtime_error("JSON: unterminated string");
            }
            const char c = t[at++];
            if (c == '"') {
                return out;
            }
            if (c != '\\') {
                out += c;
                continue;
            }
            const char e = t[at++];
            switch (e) {
            case '"': out += '"'; break;
            case '\\': out += '\\'; break;
            case '/': out += '/'; break;
            case 'b': out += '\b'; break;
            case 'f': out += '\f'; break;
            case 'n': out += '\n'; break;
            case 'r': out += '\r'; break;
            case 't': out += '\t'; break;
            case 'u': {
                std::uint32_t cp = hex4(t, at);
                if (cp >= 0xd800 && cp < 0xdc00 && at + 2 <= t.size() && t[at] == '\\' && t[at + 1] == 'u') {
                    at += 2;
                    const std::uint32_t lo = hex4(t, at);
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                }
                utf8(out, cp);
                break;
            }
            default: throw std::runtime_error("JSON: bad escape");
            }
        }
    }

    static Json parse_value(const std::string &t, std::size_t &at) {
        skip_ws(t, at);
        if (at >= t.size()) {
            throw std::runtime_error("JSON: unexpected end");
        }
        Json v;
        const char c = t[at];
        if (c == '{') {
            v.kind_ = Kind::Object;
            ++at;
            skip_ws(t, at);
            if (t[at] == '}') {
                ++at;
                return v;
            }
            while (true) {
                std::string key = parse_string(t, at);
                expect(t, at, ':');
                v.object_.emplace(std::move(key), parse_value(t, at));
                skip_ws(t, at);
                if (t[at] == ',') {
                    ++at;
                    continue;
                }
                expect(t, at, '}');
                return v;
            }
        }
        if (c == '[') {
            v.kind_ = Kind::Array;
            ++at;
            skip_ws(t, at);
            if (t[at] == ']') {
                ++at;
                return v;
            }
            while (true) {
                v.array_.push_back(parse_value(t, at));
                skip_ws(t, at);
                if (t[at] == ',') {
                    ++at;
                    continue;
                }
                expect(t, at, ']');
                return v;
            }
        }
        if (c == '"') {
            v.kind_ = Kind::String;
            v.string_ = parse_string(t, at);
            return v;
        }
        if (t.compare(at, 4, "true") == 0 || t.compare(at, 5, "false") == 0) {
            v.kind_ = Kind::Bool;
            v.bool_ = t[at] == 't';
            at += v.bool_ ? 4 : 5;
            return v;
        }
        if (t.compare(at, 4, "null") == 0) {
            at += 4;
            return v;
        }
        std::size_t end = at;
        while (end < t.size() && std::string("+-0123456789.eE").find(t[end]) != std::string::npos) {
            ++end;
        }
        if (end == at) {
            throw std::runtime_error("JSON: unexpected character at offset " + std::to_string(at));
        }
        v.kind_ = Kind::Number;
        v.number_ = std::stod(t.substr(at, end - at));
        at = end;
        return v;
    }
};

} // namespace smoke
