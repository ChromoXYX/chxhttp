#pragma once

#include <chx/net/detail/tracker.hpp>
#include <chx/net/utility.hpp>
#include <map>
#include <queue>
#include <variant>

#include "./stream_states.hpp"
#include "./types.hpp"

namespace chx::http::h2::detail {
struct data_task_t {
    flags_t flags = 0;
    using carrier_type =
        std::variant<net::offset_carrier<net::const_buffer>,
                     net::offset_carrier<std::string>,
                     net::offset_carrier<std::vector<unsigned char>>,
                     net::carrier<net::mapped_file>,
                     net::offset_carrier<net::vcarrier>>;

    carrier_type carrier;

    const void* data() const noexcept(true) {
        return std::visit([](auto& i) { return i.data(); }, carrier);
    }
    std::size_t size() const noexcept(true) {
        return std::visit([](auto& i) { return i.size(); }, carrier);
    }

    net::const_buffer remove_prefix(std::size_t n) noexcept(true) {
        assert(n < size());
        net::const_buffer r(data(), n);
        std::visit([&](auto& i) { i.remove_prefix(n); }, carrier);
        return r;
    }

    template <typename Container>
    static inline data_task_t create(flags_t flags,
                                     net::carrier<Container> container) {
        return {flags, carrier_type(std::move(container))};
    }

    template <typename Container>
    static inline data_task_t create(flags_t flags,
                                     net::offset_carrier<Container> container) {
        return {flags, carrier_type(std::move(container))};
    }
};

template <typename Session>
struct h2_stream : net::detail::enable_weak_from_this<h2_stream<Session>>,
                   Session {
    CHXNET_NONCOPYABLE;
    CHXNET_NONMOVEABLE;

    template <typename Connection>
    h2_stream(Connection& conn) : Session(conn.create_session()) {}

    using container_type = std::map<stream_id_t, h2_stream>;

    typename container_type::iterator self_pos = {};

    StreamStates state = StreamStates::Open;
    std::int32_t client_wnd = 0;
    std::int32_t server_wnd = 0;

    // std::queue<data_task_t> pending_DATA_tasks;

    std::queue<data_task_t> pending_DATA_tasks;

    constexpr Session& session() noexcept(true) { return *this; }
};
}  // namespace chx::http::h2::detail
