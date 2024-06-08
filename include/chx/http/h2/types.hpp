#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace chx::http::h2 {
using length_type = std::uint32_t;
using stream_id_type = std::uint32_t;
using flags_type = std::uint8_t;

using fields_type = std::map<std::string, std::string>;
}  // namespace chx::http::h2
