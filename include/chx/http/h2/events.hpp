#pragma once

#include "../events.hpp"

namespace chx::http::h2 {
struct ev : http::ev {
    struct frame_start {};
    struct frame_complete {};
};
}  // namespace chx::http::h2