#include "./utility.hpp"

#include <chx/log.hpp>

namespace log = chx::log;
using namespace log::literals;

template <typename Conn>
static net::task ignite(session& ses, http::request_type req, Conn& conn) {
    if (co_await request_preprocess(ses, req, conn)) {
        co_await static_file_find(ses, req, conn);
    }
}

net::task session::work(http::request_type req, norm_conn_type& conn) {
    return ignite(*this, std::move(req), conn);
}
net::task session::work(http::request_type req, ssl_conn_type& conn) {
    return ignite(*this, std::move(req), conn);
}