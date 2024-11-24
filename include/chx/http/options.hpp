#pragma once

#include <chrono>

namespace chx::http {
struct options_t {
    // timeout
    union {
        std::chrono::milliseconds keepalive_timeout;
        std::chrono::milliseconds lingering_timeout;
    };
    std::chrono::milliseconds backend_timeout;

    // max stream id for single connection
    std::size_t max_stream_id;
    std::size_t max_concurrent_stream;

    std::size_t max_header_size;
    std::size_t max_payload_size;
};

namespace detail {
constexpr inline options_t make_default_options() noexcept(true) {
    options_t options = {};
    options.keepalive_timeout = std::chrono::seconds(3);
    options.backend_timeout = std::chrono::seconds(30);
    options.max_stream_id = -2;
    options.max_concurrent_stream = -1;
    options.max_header_size = 1024;
    options.max_payload_size = -1;
    return options;
}
}  // namespace detail

constexpr inline options_t default_options = detail::make_default_options();
}  // namespace chx::http
