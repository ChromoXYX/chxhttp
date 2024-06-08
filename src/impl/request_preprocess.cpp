#include "./utility.hpp"

#include "../wildcard.hpp"

template <typename Conn>
static net::future<> ignite(session& ses, http::request_type& req,
                            http::response_type<Conn> resp) {
    if (req.fields.exactly_contains("Connection", "close")) {
        ses.shutdown_recv(resp.conn());
        ses.connection_close = true;
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
                log_norm_resp(req, resp.stream(), http::status_code::Forbidden);
                if (!ses.connection_close) {
                    ses.reset_timer(3s);
                    co_return resp.end(ses.forbidden_raw);
                } else {
                    co_return resp.end(ses.forbidden_close,
                                       resp.deferred_shutdown());
                }
            }
        } else {
            log_norm_resp(req, resp.stream(), http::status_code::Forbidden);
            if (!ses.connection_close) {
                ses.reset_timer(3s);
                co_return resp.end(ses.forbidden_raw);
            } else {
                co_return resp.end(ses.forbidden_close,
                                   resp.deferred_shutdown());
            }
        }
    }
}

auto request_preprocess(session& ses, http::request_type& req,
                        http::response_type<session::norm_conn_type> resp)
    -> net::future<> {
    return ignite(ses, req, resp);
}

auto request_preprocess(session& ses, http::request_type& req,
                        http::response_type<session::ssl_conn_type> resp)
    -> net::future<> {
    return ignite(ses, req, resp);
}
