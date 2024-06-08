#include "./base64.hpp"

#include <openssl/evp.h>

auto utility::base64_encode(const char* input, std::size_t input_size,
                            char* output) noexcept(true) -> int {
    return EVP_EncodeBlock((unsigned char*)output, (const unsigned char*)input,
                           input_size);
}
auto utility::base64_decode(const char* input, std::size_t input_size,
                            char* output) noexcept(true) -> int {
    return EVP_DecodeBlock((unsigned char*)output, (const unsigned char*)input,
                           input_size);
}

std::string utility::base64_encode(std::string_view view) {
    std::string __ret;
    __ret.resize(base64_encode_length(view));
    base64_encode(view.begin(), view.size(), __ret.data());
    return std::move(__ret);
}
std::string utility::base64_decode(std::string_view view) {
    std::string __ret;
    __ret.resize(base64_decode_length(view));
    int s = base64_decode(view.begin(), view.size(), __ret.data());
    if (s != -1) {
        __ret.resize(s);
        return std::move(__ret);
    } else {
        throw std::runtime_error("chxhttp: base64_decode failed");
    }
}
