#pragma once

#include <cstddef>

namespace utility {
int sha256(const unsigned char* input, std::size_t input_size,
           unsigned char* output, std::size_t& output_size) noexcept(true);
}