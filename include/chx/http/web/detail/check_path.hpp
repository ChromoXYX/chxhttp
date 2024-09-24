#pragma once

#include <string_view>

namespace chx::http::web::detail {
constexpr bool check_path(std::string_view request_target) noexcept(true) {
    for (std::size_t i = 0; i < request_target.size(); ++i) {
        if (request_target[i] == 0 ||
            (request_target[i] == '%' && i + 2 < request_target.size() &&
             request_target[i + 1] == '0' && request_target[i + 2] == '0')) {
            return false;
        }
    }
    return true;
}
}  // namespace chx::http::web::detail