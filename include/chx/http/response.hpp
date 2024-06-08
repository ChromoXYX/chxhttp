#pragma once

#include "./header.hpp"
#include "./status_code.hpp"

#include <chx/net/managed.hpp>
#include <chx/log.hpp>
#include <chx/net/async_sendfile.hpp>
#include <chx/net/tcp.hpp>
#include <chx/net/async_write_sequence_exactly.hpp>
#include <chx/net/async_write_some_exactly.hpp>

namespace chx::http {
template <typename T> struct is_norm_socket : std::false_type {};
template <> struct is_norm_socket<net::ip::tcp::socket> : std::true_type {};

namespace detail {
struct response_write {};
}  // namespace detail

template <typename Conn> class response_type {
    Conn& __M_conn;

  public:
    using conn_type = Conn;
    using cntl_type = typename conn_type::cntl_type;

    constexpr response_type(Conn& c) noexcept(true) : __M_conn(c) {}
    constexpr response_type(const response_type&) noexcept(true) = default;

    constexpr conn_type& conn() noexcept(true) { return __M_conn; }
    constexpr cntl_type& cntl() noexcept(true) { return conn().cntl(); }
    decltype(auto) stream() { return conn().stream(); }

    template <typename CompletionToken>
    constexpr decltype(auto) next_then(CompletionToken&& completion_token) {
        return cntl().next_then(
            std::forward<CompletionToken>(completion_token));
    }
    constexpr decltype(auto) deferred_shutdown() {
        if constexpr (is_norm_socket<std::decay_t<decltype(stream())>>::value) {
            return next_then(
                [*this](const std::error_code& e, auto&&... ts) mutable {
                    conn().should_stop(true);
                    std::error_code _e;
                    stream().shutdown(stream().shutdown_both, _e);
                    conn().cancel_all();
                    // cntl().complete(e ? e : _e);
                    conn()(cntl(), _e, std::forward<decltype(ts)>(ts)...);
                });
        } else {
            return next_then(
                [*this](const std::error_code& e, auto&&... ts) mutable {
                    stream().async_shutdown(
                        next_then([*this](const std::error_code& e) mutable {
                            conn().should_stop(true);
                            std::error_code _e;
                            stream().shutdown(stream().shutdown_both, _e);
                            conn().cancel_all();
                            // cntl().complete(e ? e : _e);
                            conn()(cntl(), e ? e : _e, 0);
                        }));
                });
        }
    }

    template <typename CompletionToken>
    decltype(auto) write(status_code st, const fields_type& header,
                         CompletionToken&& completion_token) {
        return net::async_write_sequence_exactly(
            stream().lowest_layer(),
            std::tuple<std::string_view, std::string, std::string,
                       std::string_view>(
                "HTTP/1.1 ",
                log::format(CHXLOG_STR("%u %s\r\n"),
                            static_cast<unsigned short>(st),
                            status_code_name(st)),
                header.to_string(), "\r\n"),
            std::forward<CompletionToken>(completion_token));
    }
    template <typename Container, typename CompletionToken>
    decltype(auto) write(status_code st, const fields_type& header,
                         Container&& body, CompletionToken&& completion_token) {
        return net::async_write_sequence_exactly(
            stream().lowest_layer(),
            std::tuple<std::string_view, std::string, std::string,
                       std::string_view, std::remove_reference_t<Container>>(
                "HTTP/1.1 ",
                log::format(CHXLOG_STR("%u %s\r\n"),
                            static_cast<unsigned short>(st),
                            status_code_name(st)),
                header.to_string(), "\r\n", std::forward<Container>(body)),
            std::forward<CompletionToken>(completion_token));
    }

    template <typename CompletionToken>
    decltype(auto) end_without_body(status_code st, const fields_type& header,
                                    CompletionToken&& completion_token) {
        return net::async_write_sequence_exactly(
            stream().lowest_layer(),
            std::tuple<std::string_view, std::string, std::string,
                       std::string_view>(
                "HTTP/1.1 ",
                log::format(CHXLOG_STR("%u %s\r\n"),
                            static_cast<unsigned short>(st),
                            status_code_name(st)),
                header.to_string(), "\r\n"),
            std::forward<CompletionToken>(completion_token));
    }
    decltype(auto) end_without_body(status_code st, const fields_type& header) {
        return net::async_write_sequence_exactly(
            stream().lowest_layer(),
            std::tuple<std::string_view, std::string, std::string,
                       std::string_view>(
                "HTTP/1.1 ",
                log::format(CHXLOG_STR("%u %s\r\n"),
                            static_cast<unsigned short>(st),
                            status_code_name(st)),
                header.to_string(), "\r\n"),
            cntl().template next_with_tag<detail::response_write>());
    }

    template <typename Container, typename CompletionToken>
    decltype(auto) end(status_code st, const fields_type& header,
                       Container&& body, CompletionToken&& completion_token) {
        return write(st, header, std::forward<Container>(body),
                     std::forward<CompletionToken>(completion_token));
    }
    template <typename Container>
    decltype(auto) end(status_code st, const fields_type& header,
                       Container&& body) {
        return net::async_write_sequence_exactly(
            stream().lowest_layer(),
            std::tuple<std::string_view, std::string, std::string,
                       std::string_view, std::remove_reference_t<Container>>(
                "HTTP/1.1 ",
                log::format(CHXLOG_STR("%u %s\r\n"),
                            static_cast<unsigned short>(st),
                            status_code_name(st)),
                header.to_string(), "\r\n", std::forward<Container>(body)),
            cntl().template next_with_tag<detail::response_write>());
    }

    template <typename Container> decltype(auto) end(Container&& body) {
        return net::async_write_some_exactly(
            stream().lowest_layer(), std::forward<Container>(body),
            cntl().template next_with_tag<detail::response_write>());
    }
    template <typename Container, typename CompletionToken>
    decltype(auto) end(Container&& body, CompletionToken&& completion_token) {
        return net::async_write_some_exactly(
            stream().lowest_layer(), std::forward<Container>(body),
            std::forward<CompletionToken>(completion_token));
    }
};
}  // namespace chx::http
