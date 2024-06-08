#pragma once

#include <string_view>

bool wildcard_match(std::string_view pattern,
                    std::string_view str) noexcept(true);
