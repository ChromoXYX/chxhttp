#include "./wildcard.hpp"

#include <fnmatch.h>

bool wildcard_match(std::string_view pattern,
                    std::string_view str) noexcept(true) {
    return fnmatch(pattern.data(), str.data(), 0) == 0;
}
