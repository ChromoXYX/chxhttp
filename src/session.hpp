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
        struct handshake_timeout {};
        struct http_ {};

        template <typename CntlType> using rebind = ssl_operation;

        ssl_operation(const info_type& i, net::ssl::context& ssl_ctx,
                      net::ip::tcp::socket&& sock)
            : info(i), stream(ssl_ctx, std::move(sock)) {
            // stream.set_option(SOL_TCP, TCP_ULP, "tls");
        }

        net::ssl::stream<net::ip::tcp::socket> stream;
        net::cancellation_signal cncl_cgnl;

        template <typename Cntl> void operator()(Cntl& cntl) {
            global_timer.async_register(
                3s, bind_cancellation_signal(
                        cncl_cgnl,
                        cntl.template next_with_tag<handshake_timeout>()));
            stream.async_do_handshake(cntl.template next_with_tag<handshake>());
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e, handshake) {
            cncl_cgnl.emit();
            if (!e) {
                http::async_http(stream, session(info),
                                 cntl.template next_with_tag<http_>());
            }
            cntl.complete(e);
        }

        template <typename Cntl>
        void operator()(Cntl& cntl, const std::error_code& e,
                        handshake_timeout) {
            if (!e) {
                stream.cancel();
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
    bool connection_close = false;
    net::cancellation_signal timer_cncl;

    session(const info_type& i) : info(i) {}

    template <typename Rep, typename Period>
    void reset_timer(const std::chrono::duration<Rep, Period>& dur) {
        auto* h = net::fixed_timer_controller(global_timer, timer_cncl);
        if (h && h->valid()) {
            h->update(dur);
        }
    }

    template <typename Conn> static void shutdown_recv(Conn& conn) {
        if constexpr (http::is_norm_socket<
                          std::decay_t<decltype(conn.stream())>>::value) {
            std::error_code e;
            conn.stream().shutdown(conn.stream().shutdown_receive, e);
        }
        conn.should_stop(true);
    }

    template <typename Conn>
    void operator()(http::bad_request, http::response_type<Conn> resp) {
        resp.cntl().cancel_all();
    }

    template <typename Conn>
    void operator()(http::connection_start, Conn& conn) {
        log_info("Connection start with %s\n"_str,
                 get_remote_address(conn.stream()));

        global_timer.async_register(
            3s, bind_cancellation_signal(
                    timer_cncl,
                    conn.cntl().next_then(
                        [&conn](const std::error_code& e) mutable {
                            conn.should_stop(true);
                            if (!e) {
                                log_info(CHXLOG_STR("Session timeout\n"));
                                std::error_code e;
                                shutdown_recv(conn);
                            }
                            conn.cntl().complete(e);
                        })));
    }

    template <typename Conn>
    void operator()(http::header_complete, http::request_type& req,
                    http::response_type<Conn> resp) {
        if (req.method != http::method_type::GET) {
            resp.conn().should_stop(true);
            static const http::fields_type not_implemented_header = {
                {"Connection", "close"}, {"Content-Length", "22"}};
            resp.end(http::status_code::Not_Implemented, not_implemented_header,
                     std::string_view{"<p>not implemented</p>"},
                     resp.deferred_shutdown());
        }
    }

    template <typename Conn> void tear_down(http::response_type<Conn> resp) {
        resp.conn().should_stop(true);
        resp.conn().cancel_all();
        std::error_code e;
        resp.stream().shutdown(resp.stream().shutdown_both, e);
    }
    template <typename Conn, typename... Ts>
    void resume(http::response_type<Conn> resp, Ts&&... ts) {
        resp.conn()(resp.cntl(), std::forward<Ts>(ts)...);
    }

    template <typename Conn>
    void operator()(http::message_complete, http::request_type& req,
                    http::response_type<Conn> resp) {
        reset_timer(0s);
        co_spawn(global_ctx, work(std::move(req), resp),
                 resp.next_then([resp](const std::error_code& e) mutable {
                     resp.cntl().complete(e);
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

    net::task work(http::request_type req,
                   http::response_type<norm_conn_type> resp);
    net::task work(http::request_type req,
                   http::response_type<ssl_conn_type> resp);
};