#pragma once

#include <chx/http/response.hpp>
#include <chx/net/coroutine2.hpp>
#include <chx/net/detached.hpp>

namespace chx::http {
inline void co_spawn(response& resp, net::future<>&& future) {
    if (resp.get_guard()) {
        net::co_spawn(
            *resp.get_associated_io_context(),
            [](net::future<> f) -> net::task {
                co_return co_await f;
            }(std::move(future)),
            net::detached);
    }
}
}  // namespace chx::http
