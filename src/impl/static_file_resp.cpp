#include "../session.hpp"
#include "./send_byte_range.hpp"
#include "../http_related/etag.hpp"

namespace log = chx::log;

template <typename Conn>
static net::future<> ignite(session& ses, net::file f, std::string_view mime,
                            struct stat64 st, const http::request_type& req,
                            Conn& conn) {
    if (!conn.get_guard()) {
        co_return;
    }

    std::error_code e = {};
    std::size_t s = 0;

    if (req.fields.contains("Range")) {
        co_return send_byte_range(ses, std::move(f), mime, st, req, conn);
    }

    std::string&& et = etag(st.st_mtim);
    if (if_none_match(req, et)) {
        http::fields_type h;
        h.add_field("Server", "chxhttp");
        h.add_field("Content-Length",
                    log::format(CHXLOG_STR("%lu"), st.st_size));
        h.add_field("Content-Type", mime);
        h.add_field("Accept-Ranges", "bytes");
        if (!conn.h11_would_close()) {
            h.add_field("Connection", "keep-alive");
            h.add_field("Keep-Alive", "timeout=3");
        } else {
            h.add_field("Connection", "close");
        }
        h.add_field("ETag", std::move(et));
        log_norm_resp(req, conn.stream(), http::status_code::OK);
        if (st.st_size <= 2 * 1024 * 1024) {
            std::vector<unsigned char> buf(st.st_size);
            std::tie(e, s) = co_await f.async_read_some(
                net::buffer(buf),
                conn.cntl().next_then(net::as_tuple(net::use_coro)));
            if (!conn.get_guard()) {
                co_return;
            }
            if (!e) {
                if (!conn.h11_would_close()) {
                    ses.reset_keepalive_timer(3s);
                }
                co_return conn.response(http::status_code::OK, h,
                                        std::move(buf));
            } else {
                log_warn_resp(req, conn.stream(),
                              log::format("Tear down: read file failed: %s"_str,
                                          e.message()));
                co_return conn.terminate_now();
            }
        } else {
            net::mapped_file mapped;
            mapped.map(f, st.st_size, PROT_READ, MAP_SHARED, 0, e);
            if (!e) {
                if (!conn.h11_would_close()) {
                    ses.reset_keepalive_timer(3s);
                }
                co_return conn.response(http::status_code::OK, h,
                                        std::move(mapped));
            } else {
                log_warn_resp(
                    req, conn.stream(),
                    log::format("Failed to map file: %s"_str, e.message()));
                co_return conn.response(
                    http::status_code::Internal_Server_Error, ses.ise_raw);
            }
        }
    } else {
        http::fields_type header;
        header.add_field("Server", "chxhttp");
        header.add_field("Accept-Ranges", "bytes");
        if (!conn.h11_would_close()) {
            header.add_field("Connection", "keep-alive");
            header.add_field("Keep-Alive", "timeout=3");
        } else {
            header.add_field("Connection", "close");
        }
        header.add_field("Content-Type", mime);
        header.add_field("ETag", std::move(et));
        log_norm_resp(req, conn.stream(), http::status_code::Not_Modified);
        if (!conn.h11_would_close()) {
            ses.reset_keepalive_timer(3s);
        }
        co_return conn.response(http::status_code::Not_Modified, header);
    }
}

net::future<> static_file_resp(session& ses, net::file f, std::string_view mime,
                               struct stat64 st, const http::request_type& req,
                               session::norm_conn_type& conn) {
    return ignite(ses, std::move(f), mime, std::move(st), req, conn);
}
net::future<> static_file_resp(session& ses, net::file f, std::string_view mime,
                               struct stat64 st, const http::request_type& req,
                               session::ssl_conn_type& conn) {
    return ignite(ses, std::move(f), mime, std::move(st), req, conn);
}