#pragma once

#include <cstdint>

namespace chx::ws {
struct frame {
    enum FrameType : std::uint8_t {
        Continuation = 0x0,
        Text = 0x1,
        Binary = 0x2,
        ConnectionClose = 0x8,
        Ping = 0x9,
        Pong = 0xa
    };
    static constexpr std::uint8_t FIN = 0x80;
    static constexpr std::uint8_t Extension1 = 0x40;
    static constexpr std::uint8_t Extension2 = 0x20;
    static constexpr std::uint8_t Extension3 = 0x10;

    static constexpr std::uint8_t FrameTypeMask = 0x0F;
    static constexpr std::uint8_t FrameExtensionMask = 0x70;

    std::uint8_t opcode = 0;
    std::size_t payload_length = 0;
    unsigned char masking_key[4] = {};
};
}  // namespace chx::ws
