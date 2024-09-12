#pragma once

#include <cstdint>

namespace chx::http::h2::detail {
using length_t = std::uint32_t;
using frame_type_t = std::uint8_t;
using flags_t = std::uint8_t;
using stream_id_t = std::uint32_t;

enum FrameType : std::uint8_t {
    DATA = 0x00,
    HEADERS = 0x01,
    PRIORITY = 0x02,
    RST_STREAM = 0x03,
    SETTINGS = 0x04,
    PUSH_PROMISE = 0x05,
    PING = 0x06,
    GOAWAY = 0x07,
    WINDOW_UPDATE = 0x08,
    CONTINUATION = 0x09
};

struct Flags {
    enum impl : flags_t {
        ACK = 0x01,
        END_STREAM = 0x01,
        END_HEADERS = 0x04,
        PADDED = 0x08,
        PRIORITY = 0x20,
        NO_FLAG = 0
    };
};
}  // namespace chx::http::h2::detail