#include "../session.hpp"
#include "./send_byte_range.hpp"
#include "../http_related/etag.hpp"

namespace log = chx::log;

template <typename Conn>
static net::future<> ignite(session& ses, net::file f, std::string_view mime,
                            struct stat64 st, const http::request_type& req,
                            http::response_type<Conn> resp) {
    std::error_code e = {};
    std::size_t s = 0;

    if (req.fields.contains("Range")) {
        co_return send_byte_range(ses, std::move(f), mime, st, req, resp);
    }

    std::string&& et = etag(st.st_mtim);
    if (if_none_match(req, et)) {
        http::fields_type h;
        h.add_field("Server", "chxhttp");
        h.add_field("Content-Length",
                    log::format(CHXLOG_STR("%lu"), st.st_size));
        h.add_field("Content-Type", mime);
        h.add_field("Accept-Ranges", "bytes");
        if (!ses.connection_close) {
            h.add_field("Connection", "keep-alive");
            h.add_field("Keep-Alive", "timeout=3");
        } else {
            h.add_field("Connection", "close");
        }
        h.add_field("ETag", std::move(et));
        log_norm_resp(req, resp.stream(), http::status_code::OK);
        if (st.st_size <= 2 * 1024 * 1024) {
            std::vector<unsigned char> buf(st.st_size);
            std::tie(e, s) = co_await f.async_read_some(
                net::buffer(buf), resp.next_then(net::as_tuple(net::use_coro)));
            if (!e) {
                if (!ses.connection_close) {
                    ses.reset_timer(3s);
                    co_return resp.end(http::status_code::OK, h,
                                       std::move(buf));
                } else {
                    co_return resp.end(http::status_code::OK, h, std::move(buf),
                                       resp.deferred_shutdown());
                }
            } else {
                log_warn_resp(req, resp.stream(),
                              log::format("Tear down: read file failed: %s"_str,
                                          e.message()));
                co_return ses.tear_down(resp);
            }
        } else {
            net::mapped_file mapped;
            mapped.map(f, st.st_size, PROT_READ, MAP_SHARED, 0, e);
            if (!e) {
                if (!ses.connection_close) {
                    ses.reset_timer(3s);
                    co_return resp.end(http::status_code::OK, h,
                                       std::move(mapped), resp.cntl().next());
                } else {
                    co_return resp.end(http::status_code::OK, h,
                                       std::move(mapped),
                                       resp.deferred_shutdown());
                }
            } else {
                log_warn_resp(
                    req, resp.stream(),
                    log::format("Failed to map file: %s"_str, e.message()));
                ses.shutdown_recv(resp.conn());
                co_return resp.end(ses.ise_raw, resp.deferred_shutdown());
            }
        }
    } else {
        http::fields_type header;
        header.add_field("Server", "chxhttp");
        header.add_field("Accept-Ranges", "bytes");
        if (!ses.connection_close) {
            header.add_field("Connection", "keep-alive");
            header.add_field("Keep-Alive", "timeout=3");
        } else {
            header.add_field("Connection", "close");
        }
        header.add_field("Content-Type", mime);
        header.add_field("ETag", std::move(et));
        log_norm_resp(req, resp.stream(), http::status_code::Not_Modified);
        if (!ses.connection_close) {
            ses.reset_timer(3s);
            co_return resp.end_without_body(http::status_code::Not_Modified,
                                            header);
        } else {
            co_return resp.end_without_body(http::status_code::Not_Modified,
                                            header, resp.deferred_shutdown());
        }
    }
}

net::future<>
static_file_resp(session& ses, net::file f, std::string_view mime,
                 struct stat64 st, const http::request_type& req,
                 http::response_type<session::norm_conn_type> resp) {
    return ignite(ses, std::move(f), mime, std::move(st), req, resp);
}
net::future<>
static_file_resp(session& ses, net::file f, std::string_view mime,
                 struct stat64 st, const http::request_type& req,
                 http::response_type<session::ssl_conn_type> resp) {
    return ignite(ses, std::move(f), mime, std::move(st), req, resp);
}