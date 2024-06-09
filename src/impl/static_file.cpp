#include "./utility.hpp"
#include "../http_related/mime.hpp"

template <typename Conn>
static net::future<> ignite(session& ses, http::request_type& req, Conn& conn) {
    if (!conn.get_guard()) {
        co_return;
    }

    std::error_code e;
    std::size_t s = 0;
    int r = 0;
    net::file f(co_await net::this_context);

    std::string target = req.request_target;
    std::tie(e, f) = co_await net::async_openat(
        co_await net::this_context, ses.info.root, target,
        {.resolve = RESOLVE_IN_ROOT},
        conn.cntl().next_then(net::as_tuple(net::use_coro)));
    if (!conn.get_guard()) {
        co_return;
    }
    if (!e) {
        // there is such file or dir
        struct stat64 st = {};
        r = fstat64(f.native_handler(), &st);
        if (r != 0) {
            log_warn_resp(req, conn.stream(),
                          http::status_code::Internal_Server_Error,
                          strerror(errno));
            // half_tear_down(resp);
            co_return conn.response(http::status_code::Internal_Server_Error,
                                    ses.ise_raw);
        }
        if (S_ISREG(st.st_mode)) {
            // file found
            co_return co_await static_file_resp(
                ses, std::move(f),
                query_mime(std::filesystem::path(target).extension().c_str()),
                st, req, conn);
        } else if (S_ISDIR(st.st_mode)) {
            net::detail::assign_ec(e, ENOENT);
            for (const auto& i : ses.info.conf.index_list) {
                f.openat(f, i.c_str(), {.resolve = RESOLVE_IN_ROOT}, e);
                if (!e) {
                    break;
                }
            }

            if (!e) {
                // there is such file or dir
                r = fstat64(f.native_handler(), &st);
                if (r != 0) {
                    log_warn_resp(req, conn.stream(),
                                  http::status_code::Internal_Server_Error,
                                  strerror(errno));
                    co_return conn.response(
                        http::status_code::Internal_Server_Error, ses.ise_raw);
                }
                if (S_ISREG(st.st_mode)) {
                    // file found
                    co_return co_await static_file_resp(
                        ses, std::move(f), "text/html", st, req, conn);
                } else {
                    // index.html is a dir or something else
                    log_norm_resp(req, conn.stream(),
                                  http::status_code::Forbidden);
                    if (!conn.h11_would_close()) {
                        ses.reset_timer(3s);
                        co_return conn.response(http::status_code::Forbidden,
                                                ses.forbidden_raw);
                    } else {
                        co_return conn.response(http::status_code::Forbidden,
                                                ses.forbidden_close);
                    }
                }
            } else {
                // index.html not found
                log_norm_resp(req, conn.stream(), http::status_code::Not_Found);
                if (!conn.h11_would_close()) {
                    ses.reset_timer(3s);
                    co_return conn.response(http::status_code::Forbidden,
                                            ses.forbidden_raw);
                } else {
                    co_return conn.response(http::status_code::Forbidden,
                                            ses.forbidden_close);
                }
            }
        } else {
            // target is neither a file or dir
            log_norm_resp(req, conn.stream(), http::status_code::Forbidden);
            if (!conn.h11_would_close()) {
                ses.reset_timer(3s);
                co_return conn.response(http::status_code::Forbidden,
                                        ses.forbidden_raw);
            } else {
                co_return conn.response(http::status_code::Forbidden,
                                        ses.forbidden_close);
            }
        }
    } else {
        // simply failed
        if (e == net::errc::no_such_file_or_directory) {
            log_norm_resp(req, conn.stream(), http::status_code::Not_Found);
            if (!conn.h11_would_close()) {
                ses.reset_timer(3s);
                co_return conn.response(http::status_code::Not_Found,
                                        ses.not_found_close);
            } else {
                co_return conn.response(http::status_code::Not_Found,
                                        ses.not_found_close);
            }
        } else if (e == net::errc::cross_device_link) {
            log_norm_resp(req, conn.stream(), http::status_code::Forbidden);
            if (!conn.h11_would_close()) {
                ses.reset_timer(3s);
                co_return conn.response(http::status_code::Forbidden,
                                        ses.forbidden_raw);
            } else {
                co_return conn.response(http::status_code::Forbidden,
                                        ses.forbidden_close);
            }
        } else {
            log_warn_resp(req, conn.stream(),
                          http::status_code::Internal_Server_Error,
                          strerror(errno));
            co_return conn.response(http::status_code::Internal_Server_Error,
                                    ses.ise_raw);
        }
    }
}

net::future<> static_file_find(session& ses, http::request_type& req,
                               session::norm_conn_type& conn) {
    return ignite(ses, req, conn);
}
net::future<> static_file_find(session& ses, http::request_type& req,
                               session::ssl_conn_type& conn) {
    return ignite(ses, req, conn);
}