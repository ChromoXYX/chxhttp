#pragma once

#include <chx/net/detail/tracker.hpp>
#include "./h2_stream.hpp"

namespace chx::http::h2::detail {
template <typename Session> struct frame {
    length_t length = 0;
    frame_type_t type = 0;
    flags_t flags = 0;
    stream_id_t stream_id = 0;

    // optional
    net::detail::weak_ptr<h2_stream<Session>> strm;

    // misc
    union {
        std::uint8_t padding;  // for DATA and HEADERS
        struct {
            std::uint8_t settings_consumed;  // for SETTINGS
            std::uint16_t settings_key;
        };
    };

    constexpr const auto& const_self() const noexcept(true) { return *this; }
};
}  // namespace chx::http::h2::detail