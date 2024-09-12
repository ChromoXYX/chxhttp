#pragma once

namespace chx::http {
struct ev {
    struct connection_start {};
    struct message_start {};
    struct header_complete {};
    struct data_block {};
    struct message_complete {};
};

using connection_start = ev::connection_start;
using message_start = ev::message_start;
using header_complete = ev::header_complete;
using data_block = ev::data_block;
using message_complete = ev::message_complete;
}  // namespace chx::http