#pragma once

#include <chx/net/io_context.hpp>
#include <chx/net/file.hpp>

inline thread_local chx::net::io_context global_ctx;
