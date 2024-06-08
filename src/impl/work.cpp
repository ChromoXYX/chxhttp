#include "./utility.hpp"

template <typename Conn>
static net::task ignite(session& ses, http::request_type req,
                        http::response_type<Conn> resp) {
    co_await request_preprocess(ses, req, resp);
    co_return co_await static_file_find(ses, req, resp);
}

net::task session::work(http::request_type req,
                        http::response_type<norm_conn_type> resp) {
    return ignite(*this, std::move(req), resp);
}
net::task session::work(http::request_type req,
                        http::response_type<ssl_conn_type> resp) {
    return ignite(*this, std::move(req), resp);
}