#pragma once

namespace chx::http::h2::detail {
enum class StreamStates : int {
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
};
}
