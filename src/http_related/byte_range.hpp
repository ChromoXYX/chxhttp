#pragma once

#include <string_view>
#include <vector>

bool parse_byte_range(std::string_view view,
                      std::vector<std::pair<std::size_t, std::size_t>>& ret);