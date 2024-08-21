#pragma once

namespace chx::http {
struct connection_start {};
struct message_start {};
struct header_complete {};
struct data_block {};
struct message_complete {};

struct bad_request {};
struct bad_network {};
}  // namespace chx::http