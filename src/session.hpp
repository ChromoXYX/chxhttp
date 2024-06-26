#pragma once

#include <chx/http/async_http.hpp>
#include <chx/net.hpp>
#include <chx/net/ssl/ssl.hpp>
#include <chx/log/chrono.hpp>
#include <netinet/tcp.h>

#include "./info_type.hpp"
#include "./log.hpp"
#include "./tail_fn.hpp"
#include "./global_timer.hpp"

namespace http = chx::http;
namespace net = chx::net;
using namespace chx::log::literals;
using namespace std::literals;

struct session {
    struct ssl_operation {
        const info_type& info;

        struct handshake {};
        struct handshake_ddl {};
        struct http_ {};

        template <typename CntlType> using rebind = ssl_operation;

        ssl_operation(const info_type& i, net::ssl::context& ssl_ctx,
                      net::ip::tcp::socket&& sock)
            : info(i), stream(ssl_ctx, std::move(sock)) {}

        net::ssl::stream<net::ip::tcp::socket> stream;
        net::cancellation_signal ssl_handshake_ddl_cncl;

        template <typename Cntl> void operator()(Cntl& cntl) {
            stream.async_do_handshake(cntl.template next_with_tag<handshake>());
            global_timer.async_register(
                3s, bind_cancellation_signal(
                        ssl_handshake_ddl_cncl,
                        cntl.template next_with_tag<handshake_ddl>()));
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, handshake) {
            if (ssl_handshake_ddl_cncl) {
                ssl_handshake_ddl_cncl.emit();
                ssl_handshake_ddl_cncl.clear();
                if (!e) {
                    http::async_http(stream, session(info),
                                     cntl.template next_with_tag<http_>());
                }
            }
            cntl.complete(e);
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, handshake_ddl) {
            if (ssl_handshake_ddl_cncl) {
                ssl_handshake_ddl_cncl.clear();
                if (e == net::errc::operation_canceled) {
                } else if (!e) {
                    log_warn("SSL_handshake timeout\n"_str);
                }
            }
            cntl.complete(e);
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, http_) {
            cntl.complete(e);
        }
    };
    using ssl_conn_type = http::detail::operation<
        net::ssl::stream<net::ip::tcp::socket>&, session,
        net::detail::async_combine_impl<
            http::detail::operation<net::ssl::stream<net::ip::tcp::socket>&,
                                    session, int>,
            net::detail::async_combine_impl<
                session::ssl_operation, tail_fn_t,
                std::integral_constant<bool, true>>::
                next_guard_with_tag<ssl_operation::http_>,
            std::integral_constant<bool, true>>>;
    using norm_conn_type = http::detail::operation<
        net::ip::tcp::socket, session,
        net::detail::async_combine_impl<
            http::detail::operation<net::ip::tcp::socket, session, int>,
            tail_fn_t, std::integral_constant<bool, true>>>;

    // timer to shutdown RECV gracefully
    // deferred_shutdown to shutdown BOTH
    // so,
    // keepalive -> timer and async_http operation take care of the lifecycle.
    // close     -> deferred_shutdown() takes care of it, and all operations
    //              will be cancelled.
    const info_type& info;
    net::cancellation_signal keepalive_ddl_cncl;

    session(const info_type& i) : info(i) {}

    template <typename Conn>
    void operator()(http::connection_start, Conn& conn) {
        log_info("Connection start with %s\n"_str,
                 get_remote_address(conn.stream()));
        global_timer.async_register(
            3s, bind_cancellation_signal(
                    keepalive_ddl_cncl,
                    conn.cntl().template next_then(
                        [&conn](const std::error_code& e) {
                            conn.h11_close_connection();
                            if (!e) {
                                log_info("Session timeout\n"_str);
                            }
                            conn.cntl().complete(e);
                        })));
    }

    template <typename Rep, typename Per>
    void reset_keepalive_timer(const std::chrono::duration<Rep, Per>& dur) {
        auto* cncl =
            net::safe_fixed_timer_controller(global_timer, keepalive_ddl_cncl);
        cncl->update(dur);
    }

    template <typename Conn>
    void operator()(http::header_complete, http::request_type& req,
                    Conn& conn) {
        if (req.method != http::method_type::GET) {
            static const http::fields_type not_implemented_header = {
                {"Connection", "close"}, {"Content-Length", "22"}};
            conn.response(http::status_code::Not_Implemented,
                          not_implemented_header,
                          std::string_view{"<p>not implemented</p>"});
            conn.h11_shutdown_both();
        }
    }

    template <typename Conn>
    void operator()(http::message_complete, http::request_type& req,
                    Conn& conn) {
        reset_keepalive_timer(0s);
        co_spawn(
            global_ctx, work(std::move(req), conn),
            conn.cntl().next_then([&conn](const std::error_code& e) mutable {
                conn.cntl().complete(e);
            }));
    }

    static constexpr std::string_view not_found_raw =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: chxhttp\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 16\r\n"
        "Connection: keep-alive\r\n"
        "Keep-Alive: timeout=3\r\n"
        "\r\n"
        "<p>Not Found</p>";
    static constexpr std::string_view ise_raw =
        "HTTP/1.1 500 Internal Server Error\r\n"
        "Server: chxhttp\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 28\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<p>Internal Server Error</p>";
    static constexpr std::string_view forbidden_raw =
        "HTTP/1.1 403 Forbidden\r\n"
        "Server: chxhttp\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 16\r\n"
        "Connection: keep-alive\r\n"
        "Keep-Alive: timeout=3\r\n"
        "\r\n"
        "<p>Forbidden</p>";
    static constexpr std::string_view not_found_close =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: chxhttp\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 16\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<p>Not Found</p>";
    static constexpr std::string_view forbidden_close =
        "HTTP/1.1 403 Forbidden\r\n"
        "Server: chxhttp\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 16\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<p>Forbidden</p>";

    net::task work(http::request_type req, norm_conn_type& conn);
    net::task work(http::request_type req, ssl_conn_type& conn);
};
