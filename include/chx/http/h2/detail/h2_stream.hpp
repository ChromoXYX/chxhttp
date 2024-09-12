#pragma once

#include <chx/net/detail/tracker.hpp>
#include <map>
#include <queue>

#include "./stream_states.hpp"
#include "./data_task.hpp"

namespace chx::http::h2::detail {
template <typename Session>
struct h2_stream : net::detail::enable_weak_from_this<h2_stream<Session>>,
                   Session {
    template <typename Connection>
    h2_stream(Connection& conn) : Session(conn.create_session()) {}

    using container_type = std::map<stream_id_t, h2_stream>;

    typename container_type::iterator self_pos = {};

    StreamStates state = StreamStates::Open;
    std::int32_t client_wnd = 0;
    std::int32_t server_wnd = 0;

    std::queue<data_task_t> pending_DATA_tasks;

    constexpr Session& session() noexcept(true) { return *this; }
};
}  // namespace chx::http::h2::detail
