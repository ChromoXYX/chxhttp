#pragma once

#include "../co_middleware.hpp"

namespace chx::http::web::middleware {
inline net::future<> block(control cntl) noexcept(true) {
    for (;;) {
        co_await cntl.schedule();
    }
}
}  // namespace chx::http::web::middleware
