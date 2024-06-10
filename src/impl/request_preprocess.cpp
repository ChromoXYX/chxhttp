#include "./utility.hpp"

#include "../wildcard.hpp"

template <typename Conn>
static net::future<bool> ignite(session& ses, http::request_type& req,
                                Conn& conn) {
    if (!conn.get_guard()) {
        co_return false;
    }

    if (!ses.info.conf.server_name.empty()) {
        if (req.fields.contains("host")) {
            const auto& req_host = req.fields.find("host")->second;
            bool found = false;
            for (const auto& srv_pattern : ses.info.conf.server_name) {
                if (wildcard_match(srv_pattern, req_host)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                log_norm_resp(req, conn.stream(), http::status_code::Forbidden);
                if (!conn.h11_would_close()) {
                    ses.reset_keepalive_timer(3s);
                    conn.response(http::status_code::Forbidden,
                                  ses.forbidden_raw);
                } else {
                    conn.response(http::status_code::Forbidden,
                                  ses.forbidden_close);
                }
                co_return false;
            }
        } else {
            log_norm_resp(req, conn.stream(), http::status_code::Forbidden);
            if (!conn.h11_would_close()) {
                ses.reset_keepalive_timer(3s);
                conn.response(http::status_code::Forbidden, ses.forbidden_raw);
            } else {
                conn.response(http::status_code::Forbidden,
                              ses.forbidden_close);
            }
            co_return false;
        }
    }
    co_return true;
}

auto request_preprocess(session& ses, http::request_type& req,
                        session::norm_conn_type& conn) -> net::future<bool> {
    return ignite(ses, req, conn);
}

auto request_preprocess(session& ses, http::request_type& req,
                        session::ssl_conn_type& conn) -> net::future<bool> {
    return ignite(ses, req, conn);
}
