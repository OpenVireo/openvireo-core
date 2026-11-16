// The Corrosion-built core: version() and one primitive.

#include <ovcore.h>

#include <cstdio>
#include <string>

int main() {
    const std::string abc = "abc";
    rust::Slice<const std::uint8_t> data(reinterpret_cast<const std::uint8_t *>(abc.data()), abc.size());
    std::string digest;
    for (auto b : ov::sha256(data)) {
        static const char digits[] = "0123456789abcdef";
        digest += digits[b >> 4];
        digest += digits[b & 0xf];
    }
    std::printf("openvireo-core %s (Corrosion)\nsha256(\"abc\") = %s\n", std::string(ov::version()).c_str(), digest.c_str());
    return digest == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ? 0 : 1;
}
