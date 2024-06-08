#pragma once

#include <cstdint>

namespace chx::http::h2 {
enum Settings : std::uint16_t {
    SETTINGS_HEADER_TABLE_SIZE = 0x01,
    SETTINGS_ENABLE_PUSH = 0x02,
    SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    SETTINGS_MAX_FRAME_SIZE = 0x05,
    SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,

    SETTINGS_NO_RFC7540_PRIORITIES = 0x09
};
}  // namespace chx::http::h2
