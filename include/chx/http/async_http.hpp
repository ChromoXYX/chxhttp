#pragma once

#include "./request.hpp"
#include "./status_code.hpp"
#include "./events.hpp"
#include "./detail/payload.hpp"

#include <chx/log.hpp>
#include <chx/net.hpp>

namespace chx::http {
class connection_closed : public net::exception {
  public:
    using exception::exception;
};
}  // namespace chx::http

namespace chx::http::detail {
// template <typename T> struct identity {
//     using type = T;
//     template <typename R> constexpr R&& operator()(R&& r) const
//     noexcept(true) {
//         return std::forward<R>(r);
//     }
// };
template <typename Event, typename T, typename... Args>
void on(T&& t, Args&&... args) {
    if constexpr (std::is_invocable_v<T&&, Event, Args...>) {
        std::forward<T>(t)(Event(), std::forward<Args>(args)...);
    }
}

template <typename Stream, typename Session,
          /*typename StreamAccessor = identity<Stream>,*/ typename CntlType =
              int>
struct operation : CHXNET_NONCOPYABLE /*, StreamAccessor*/ {
    using cntl_type = CntlType;
    template <typename T>
    using rebind = operation<Stream, Session, /*StreamAccessor,*/ T>;
    struct internal_read {};
    struct internal_write {};
    struct internal_write_final {};

    template <typename Str, typename Ses>
    operation(Str&& str, Ses&& ses)
        : __M_nstream(std::forward<Str>(str)),
          __M_session(std::forward<Ses>(ses)) {
        __M_inbuf.resize(4096);
        llhttp_init(&__M_parser, HTTP_REQUEST, &settings.s);
        __M_parser.data = this;
    }

    auto& stream() { return __M_nstream; }
    const auto& stream() const { return __M_nstream; }
    constexpr CntlType& cntl() noexcept(true) {
        return static_cast<CntlType&>(*this);
    }
    constexpr const CntlType& cntl() const noexcept(true) {
        return static_cast<const CntlType&>(*this);
    }
    constexpr Session& session() noexcept(true) { return __M_session; }
    constexpr const Session& session() const noexcept(true) {
        return __M_session;
    }

    void cancel_all() { cntl()(nullptr); }

    template <typename Cntl> void operator()(Cntl& cntl) {
        on<connection_start>(session(), *this);
        do_read();
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_read) {
        io_cntl.unset_recving();
        if (!e || e == net::errc::operation_canceled) {
            if (io_cntl.want_recv()) {
                __M_next = __M_inbuf.data();
                __M_avail = s;
                feed();
                do_read();
                do_send();
            }
        } else {
            // network failure
            terminate_now();
        }
        cntl.complete(e);
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_write) {
        io_cntl.unset_sending();
        // internal_write would never get cancelled, except for terminate_now()
        if (!e) {
            if (!io_cntl.goaway_sent()) {
                do_send();
            } else {
                cancel_all();
                if (can_send()) {
                    io_cntl.set_sending();
                    net::async_write_sequence_exactly(
                        stream().lowest_layer(),
                        std::move(__M_pending_response),
                        cntl.template next_with_tag<internal_write_final>());
                }
            }
        } else {
            terminate_now();
        }
        cntl.complete(e);
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_write_final) {
        io_cntl.unset_sending();
        if (e) {
            terminate_now();
        }
        cntl.complete(e);
    }

  private:
    Stream __M_nstream;
    Session __M_session;

    std::vector<std::variant<
        std::tuple<std::string_view, std::string, std::string,
                   std::string_view>,  // header-only
        std::tuple<std::string_view, std::string, std::string, std::string_view,
                   detail::payload_rep,
                   std::vector<struct net::iovec_buffer>>,  // with payload
        std::tuple<std::string_view, std::string, std::string, std::string_view,
                   std::vector<unsigned char>>,
        std::tuple<std::string_view, std::string, std::string, std::string_view,
                   std::vector<net::iovec_buffer>>,
        std::tuple<std::string_view, std::string, std::string, std::string_view,
                   std::string_view>,
        std::string_view>>
        __M_pending_response;

    template <std::size_t Idx, typename... Ts>
    void __response_emplace(status_code code, const fields_type& fields,
                            Ts&&... ts) {
        __M_pending_response.emplace_back(
            std::in_place_index_t<Idx>{}, std::string_view{"HTTP/1.1 "},
            chx::log::format(CHXLOG_STR("%u %s\r\n"),
                             static_cast<unsigned short>(code),
                             status_code_name(code)),
            fields.to_string(), std::string_view{"\r\n"},
            std::forward<Ts>(ts)...);
    }

    template <typename... Ts>
    void __response(status_code code, const fields_type& fields, Ts&&... ts) {
        if constexpr (sizeof...(Ts) > 1) {
            return __response_multi(code, fields, std::forward<Ts>(ts)...);
        } else if constexpr (sizeof...(Ts) == 1) {
            return __response_single(code, fields, std::forward<Ts>(ts)...);
        } else {
            return __response0(code, fields);
        }
    }
    void __response0(status_code code, const fields_type& fields) {
        __response_emplace<0>(code, fields);
    }
    template <typename... Ts>
    void __response_multi(status_code code, const fields_type& fields,
                          Ts&&... ts) {
        std::unique_ptr store =
            detail::payload_store::create(std::forward<Ts>(ts)...);
        std::vector<net::iovec_buffer> iov =
            detail::create_iovec_vector(store->data);
        __response_emplace<1>(code, fields, std::move(store), std::move(iov));
    }
    template <typename T>
    void __response_single(status_code code, const fields_type& fields, T&& t) {
        if constexpr (std::is_lvalue_reference_v<T> &&
                      !std::is_same_v<std::decay_t<T>, std::string_view>) {
            return __response_multi(code, fields, std::forward<T>(t));
        } else {
            using __dct = std::decay_t<T>;
            if constexpr (std::is_same_v<__dct, std::vector<unsigned char>>) {
                __response_emplace<2>(code, fields, std::move(t));
            } else if constexpr (std::is_same_v<__dct, std::string_view>) {
                __response_emplace<4>(code, fields, t);
            } else if constexpr (std::is_same_v<
                                     __dct, std::vector<net::iovec_buffer>>) {
                __response_emplace<3>(code, fields, std::move(t));
            } else {
                return __response_multi(code, fields, std::forward<T>(t));
            }
        }
    }

  public:
    constexpr auto& guard() {
        if (!io_cntl.goaway_sent()) {
            return *this;
        } else {
            throw connection_closed();
        }
    }
    constexpr bool get_guard() noexcept(true) { return !io_cntl.goaway_sent(); }

    template <typename... Ts>
    void response(status_code code, const fields_type& fields, Ts&&... ts) {
        __response(code, fields, std::forward<Ts>(ts)...);
        if (code == status_code::Bad_Request ||
            static_cast<unsigned short>(code) >= 500) {
            io_cntl.send_goaway();
        }
        do_send();
    }
    void response(status_code code, std::string_view sv) {
        __M_pending_response.emplace_back(std::in_place_index_t<5>{}, sv);
        if (code == status_code::Bad_Request ||
            static_cast<unsigned short>(code) >= 500) {
            io_cntl.send_goaway();
        }
        do_send();
    }

    // h11_shutdown_recv and h11_shutdown_both shall not be invoked out of
    // async_combine::operator() scope!
    constexpr void h11_shutdown_recv() noexcept(true) {
        io_cntl.shutdown_recv();
    }
    constexpr void h11_shutdown_both() noexcept(true) {
        h11_shutdown_recv();
        io_cntl.send_goaway();
    }

    constexpr bool h11_would_close() noexcept(true) {
        return !io_cntl.want_recv();
    }
    void h11_close_connection() {
        h11_shutdown_both();
        if (!io_cntl.is_sending() && __M_pending_response.empty()) {
            cancel_all();
        } else {
            do_send();
        }
    }

    void terminate_now() {
        io_cntl.shutdown_both();
        cancel_all();
    }

  private:
    struct settings_t {
        llhttp_settings_t s = {};

        static int consume(llhttp_t* c, const char* p, std::size_t s) {
            operation* self = static_cast<operation*>(c->data);
            if (self->__M_parse_state.current_size + s <=
                self->__M_parse_state.current_max) {
                self->__M_parse_state.current_size += s;
                self->__M_pbuf.append(p, s);
                return HPE_OK;
            } else {
                return -1;
            }
        }

        constexpr settings_t() {
            s.on_body = [](llhttp_t* c, const char* p, std::size_t s) -> int {
                operation* self = static_cast<operation*>(c->data);
                if (self->__M_parse_state.want_data) {
                    if (self->__M_parse_state.current_size + s <=
                        self->__M_parse_state.current_max) {
                        self->__M_parse_state.current_size += s;
                        self->__M_request.body.insert(
                            self->__M_request.body.end(), p, p + s);
                    } else {
                        return -1;
                    }
                }
                return HPE_OK;
            };
            s.on_url = consume;
            s.on_header_field = consume;
            s.on_header_value = consume;

            s.on_method_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_request.method =
                    detail::method_from_h1(llhttp_get_method(c));
                return HPE_OK;
            };
            s.on_url_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_request.request_target = std::move(self->__M_pbuf);
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_field_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_request.fields.emplace_back(
                    std::move(self->__M_pbuf));
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_value_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_request.fields.back().second =
                    std::move(self->__M_pbuf);
                self->__M_pbuf.clear();
                return HPE_OK;
            };

            s.on_message_begin = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                on<message_begin>(self->session(), *self);
                return HPE_OK;
            };
            s.on_headers_complete = [](llhttp_t* c) -> int {
                static_cast<operation*>(c->data)->__M_parse_state.why =
                    parse_state::HeadersComplete;
                return HPE_PAUSED;
            };
            s.on_message_complete = [](llhttp_t* c) -> int {
                static_cast<operation*>(c->data)->__M_parse_state.why =
                    parse_state::MsgComplete;
                return HPE_PAUSED;
            };
        }
    } constexpr static inline settings = {};

    std::vector<char> __M_inbuf;
    std::size_t __M_avail = 0;
    const char* __M_next = nullptr;
    std::string __M_pbuf;

    request_type __M_request;
    struct parse_state {
        enum Why { Waiting, HeadersComplete, MsgComplete, Error } why = Waiting;
        bool want_data = true;
        bool need_exec = true;
        std::size_t current_max = 4096;
        ssize_t current_size = 0;
    } __M_parse_state;
    llhttp_t __M_parser;

    struct {
        // whether server want to recv or process next frame
        constexpr bool want_recv() const noexcept(true) { return v & 1; }
        // whether server CAN send any frame
        constexpr bool want_send() const noexcept(true) { return v & 2; }
        // whether is an outstanding send task
        constexpr bool is_sending() const noexcept(true) { return v & 4; }
        // whether there is an outstanding recv task
        constexpr bool is_recving() const noexcept(true) { return v & 8; }

        // to make server unable to process any frame or send any frame
        constexpr void shutdown_both() noexcept(true) {
            shutdown_recv();
            shutdown_send();
        }
        constexpr void shutdown_recv() noexcept(true) { v &= ~1; }
        constexpr void shutdown_send() noexcept(true) { v &= ~2; }

        constexpr void set_sending() noexcept(true) { v |= 4; }
        constexpr void unset_sending() noexcept(true) { v &= ~4; }

        constexpr void set_recving() noexcept(true) { v |= 8; }
        constexpr void unset_recving() noexcept(true) { v &= ~8; }

        constexpr void send_goaway() noexcept(true) { v |= 16; }
        constexpr bool goaway_sent() noexcept(true) { return v & 16; }

      private:
        char v = 1 | 2;
    } io_cntl;

    void parse_restart() noexcept(true) { __M_parse_state = {}; }

    void do_read() {
        if (can_read()) {
            io_cntl.set_recving();
            stream().lowest_layer().async_read_some(
                net::buffer(__M_inbuf),
                cntl().template next_with_tag<internal_read>());
        }
    }

    void do_send() {
        if (can_send()) {
            io_cntl.set_sending();
            net::async_write_sequence_exactly(
                stream().lowest_layer(), std::move(__M_pending_response),
                cntl().template next_with_tag<internal_write>());
        }
    }

    // weak exception guarantee
    // that is, if anything throws, cntl.complete() is guaranteed to be called
    void feed() {
        if (io_cntl.want_recv()) {
            if (__M_avail ||
                __M_parse_state.why == __M_parse_state.HeadersComplete) {
                llhttp_errno r;
                try {
                    r = llhttp_execute(&__M_parser, __M_next, __M_avail);
                } catch (...) {
                    std::rethrow_exception(std::current_exception());
                }
                if (r == HPE_PAUSED) {
                    llhttp_resume(&__M_parser);
                    __M_avail -= llhttp_get_error_pos(&__M_parser) - __M_next;
                    __M_next = llhttp_get_error_pos(&__M_parser);
                    try {
                        if (__M_parse_state.why ==
                            __M_parse_state.HeadersComplete) {
                            __M_parse_state.want_data = false;
                            on<header_complete>(session(), __M_request,
                                                *this);
                        } else {
                            if (__M_request.fields.exactly_contains(
                                    "connection", "close")) {
                                h11_shutdown_recv();
                            }
                            on<message_complete>(session(), __M_request,
                                                 *this);
                            parse_restart();
                        }
                    } catch (const std::exception& e) {
                        struct user_ise {
                            fields_type fields;

                            user_ise() {
                                fields.set_field("Server", "chxhttp.h11");
                                fields.set_field("Connection", "close");
                            }
                        } static const ise;
                        response(status_code::Internal_Server_Error,
                                 ise.fields);
                    }
                    feed();
                } else if (r == HPE_OK) {
                    __M_avail = 0;
                    __M_next = nullptr;
                } else {
                    struct badrequest {
                        fields_type fields;

                        badrequest() {
                            fields.set_field("Server", "chxhttp.h11");
                            fields.set_field("Connection", "close");
                        }
                    } static const ise;
                    response(status_code::Bad_Request, ise.fields);
                }
            }
        }
    }

    constexpr bool can_read() noexcept(true) {
        return io_cntl.want_recv() && !io_cntl.is_recving();
    }
    constexpr bool can_send() noexcept(true) {
        return io_cntl.want_send() && !io_cntl.is_sending() &&
               !__M_pending_response.empty();
    }
};
template <typename Stream, typename Session, typename StreamAccessor>
operation(Stream&&, Session&&, StreamAccessor&&) -> operation<
    std::conditional_t<std::is_rvalue_reference_v<Stream&&>, Stream, Stream&&>,
    std::conditional_t<std::is_rvalue_reference_v<Session&&>, Session,
                       Session&&>,
    std::decay_t<StreamAccessor>>;
template <typename Stream, typename Session>
operation(Stream&&, Session&&) -> operation<
    std::conditional_t<std::is_rvalue_reference_v<Stream&&>, Stream, Stream&&>,
    std::conditional_t<std::is_rvalue_reference_v<Session&&>, Session,
                       Session&&>>;
}  // namespace chx::http::detail

namespace chx::http {
template <typename Stream, typename Session, typename CompletionToken>
decltype(auto) async_http(Stream&& stream, Session&& session,
                          CompletionToken&& completion_token) {
    using operation_type = decltype(detail::operation(
        std::forward<Stream>(stream), std::forward<Session>(session)));
    return net::async_combine_reference_count<const std::error_code&>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream), std::forward<Session>(session));
}
}  // namespace chx::http
