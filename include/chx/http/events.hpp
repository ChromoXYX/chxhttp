#pragma once

namespace chx::http {
struct connection_start {};
struct message_begin {};
struct header_complete {};
struct message_complete {};

struct bad_request {};
struct bad_network {};
}  // namespace chx::http