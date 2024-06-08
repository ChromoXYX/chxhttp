#pragma once

#include <cstddef>
#include <iterator>

namespace utility {
template <typename Container>
constexpr std::size_t base64_encode_length(Container&& view) noexcept(true) {
    const std::size_t _sz = std::size(view);
    return _sz != 0 ? (1 + ((_sz - 1) / 3)) * 4 : 0;
}
int base64_encode(const char* input, std::size_t input_size,
                  char* output) noexcept(true);
template <typename Container>
constexpr std::size_t base64_decode_length(Container&& view) noexcept(true) {
    const std::size_t _sz = std::size(view);
    return std::size(view) / 4 * 3;
}
int base64_decode(const char* input, std::size_t input_size,
                  char* output) noexcept(true);

std::string base64_encode(std::string_view input);
std::string base64_decode(std::string_view input);
}  // namespace utility
