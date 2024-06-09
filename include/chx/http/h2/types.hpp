#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "../header.hpp"

namespace chx::http::h2 {
using length_type = std::uint32_t;
using stream_id_type = std::uint32_t;
using flags_type = std::uint8_t;

using fields_type = http::fields_type;
}  // namespace chx::http::h2
