#pragma once

#include "./app/global_ctx.hpp"
#include <chx/net/basic_fixed_timer.hpp>

inline thread_local chx::net::fixed_timeout_timer global_timer(global_ctx);
