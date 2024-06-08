#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <netinet/in.h>

namespace chx::http::h2::detail {
template <typename CharT>
std::uint32_t from_network4(CharT* ptr, std::size_t len = 4) {
    std::uint32_t t = 0;
    std::memcpy((std::uint8_t*)&t + 4 - len, ptr, len);
    return ntohl(t);
}
template <typename CharT>
std::uint16_t from_network2(CharT* ptr, std::size_t len = 2) {
    std::uint16_t t = 0;
    std::memcpy((std::uint8_t*)&t + 2 - len, ptr, len);
    return ntohs(t);
}
template <typename CharT>
void to_network4(std::uint32_t v, CharT* dest, std::size_t len = 4) {
    std::uint32_t c = htonl(v);
    std::memcpy(dest, (std::uint8_t*)&c + 4 - len, len);
}
template <typename CharT>
void to_network2(std::uint16_t v, CharT* dest, std::size_t len = 2) {
    std::uint16_t c = htons(v);
    std::memcpy(dest, (std::uint8_t*)&c + 2 - len, len);
}
}  // namespace chx::http::h2::detail
