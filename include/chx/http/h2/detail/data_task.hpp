#pragma once

#include "./types.hpp"
#include "../../detail/payload.hpp"
#include <numeric>

namespace chx::http::h2::detail {
struct data_task_t {
    flags_t flags = 0;
    std::size_t sz = 0;
    std::unique_ptr<http::detail::payload_store> payload;
    std::vector<net::iovec_buffer> iovec;

    template <typename... Ts>
    static data_task_t create(flags_t flags, Ts&&... ts) {
        data_task_t task = {};
        task.flags = flags;

        std::unique_ptr payload =
            http::detail::payload_store::create(std::forward<Ts>(ts)...);
        task.iovec = http::detail::create_iovec_vector(payload->data);
        task.sz = std::accumulate(
            task.iovec.begin(), task.iovec.end(), std::size_t{0},
            [](std::size_t r, const net::iovec_buffer& a) {
                return r + a.size();
            });
        task.payload = std::move(payload);
        return std::move(task);
    }
};
}  // namespace chx::http::h2::detail
