#pragma once

#include <cstdint>

namespace chx::ws {
enum [[nodiscard]] StatusCodes : std::uint16_t {
    NoError = 0,

    NormalClosure = 1000,
    GoingAway = 1001,
    ProtocolError = 1002,
    UnacceptableDataType = 1003,
    BadDataType = 1007,
    BadMessage = 1008,
    NeedExtension = 1010,
    InternalServerError = 1011,
};
}
