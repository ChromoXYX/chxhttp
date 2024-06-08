#pragma once

#include "./request.hpp"
#include "./response.hpp"
#include "./events.hpp"
#include <iostream>

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

    friend struct response_type<operation>;

    template <typename Str, typename Ses, typename SA>
    operation(Str&& str, Ses&& ses, SA&& sa)
        : __M_nstream(std::forward<Str>(str)),
          __M_session(std::forward<Ses>(ses))
    /*, StreamAccessor(std::forward<SA>(sa))*/ {
        __M_inbuf.resize(4096);
        llhttp_init(&__M_parser, HTTP_REQUEST, &settings.s);
        __M_parser.data = this;
    }
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
        on<connection_start>(__M_session, *this);
        do_read();
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_read) {
        __M_reading = false;
        if (!e && !should_stop()) {
            __M_next = __M_inbuf.data();
            __M_avail = s;
            exec();
        } else {
            __M_should_stop = true;
            cancel_all();
            try {
                on<bad_network>(__M_session, *this, e);
            } catch (...) {
                cntl.complete(std::error_code{});
                std::rethrow_exception(std::current_exception());
            }
            cntl.complete(e ? e : net::detail::make_ec(net::errc::timed_out));
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s) {
        return operator()(cntl, e, s, response_write{});
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    response_write) {
        if (!e && !should_stop()) {
            resume();
        } else {
            __M_should_stop = true;
            cancel_all();
            try {
                on<bad_network>(__M_session, *this, e);
            } catch (...) {
                cntl.complete(std::error_code{});
                std::rethrow_exception(std::current_exception());
            }
            cntl.complete(e ? e : net::detail::make_ec(net::errc::timed_out));
        }
    }

    void resume() {
        if (!__M_reading) {
            exec();
        }
    }
    constexpr void should_stop(bool value) noexcept(true) {
        if (value) {
            __M_should_stop = true;
        }
    }
    constexpr bool should_stop() const noexcept(true) {
        return __M_should_stop;
    }

    constexpr bool reading() const noexcept(true) { return __M_reading; }

  protected:
    Stream __M_nstream;
    Session __M_session;

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
                on<message_begin>(self->__M_session, *self);
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
        bool should_close = false;
        std::size_t current_max = 4096;
        ssize_t current_size = 0;
    } __M_parse_state;
    llhttp_t __M_parser;
    bool __M_should_stop = false;
    bool __M_reading = false;
    void parse_restart() noexcept(true) { __M_parse_state = {}; }

    void do_read() {
        assert(__M_reading == false);
        __M_reading = true;
        stream().lowest_layer().async_read_some(
            net::buffer(__M_inbuf),
            cntl().template next_with_tag<internal_read>());
    }

    void fatal_close(const std::error_code& e = {}) {
        __M_should_stop = true;
        cancel_all();
        cntl().complete(e);
    }

    // weak exception guarantee
    // that is, if anything throws, cntl.complete() is guaranteed to be called
    void exec() {
        if (!__M_should_stop) {
            if (__M_avail ||
                __M_parse_state.why == __M_parse_state.HeadersComplete) {
                llhttp_errno r;
                try {
                    r = llhttp_execute(&__M_parser, __M_next, __M_avail);
                } catch (...) {
                    fatal_close();
                    std::rethrow_exception(std::current_exception());
                }
                if (r == HPE_PAUSED) {
                    llhttp_resume(&__M_parser);
                    __M_avail -= llhttp_get_error_pos(&__M_parser) - __M_next;
                    __M_next = llhttp_get_error_pos(&__M_parser);
                    if (__M_parse_state.why ==
                        __M_parse_state.HeadersComplete) {
                        __M_parse_state.want_data = false;
                        try {
                            on<header_complete>(__M_session, __M_request,
                                                response_type(*this));
                        } catch (...) {
                            fatal_close();
                            std::rethrow_exception(std::current_exception());
                        }
                        if (!__M_parse_state.should_close) {
                            return exec();
                        } else {
                            __M_should_stop = true;
                            return cntl().complete(std::error_code{});
                        }
                    } else {
                        try {
                            on<message_complete>(__M_session, __M_request,
                                                 response_type(*this));
                        } catch (...) {
                            fatal_close();
                            std::rethrow_exception(std::current_exception());
                        }
                        if (!__M_parse_state.should_close) {
                            parse_restart();
                        } else {
                            __M_should_stop = true;
                            return cntl().complete(std::error_code{});
                        }
                    }
                } else if (r == HPE_OK) {
                    __M_avail = 0;
                    __M_next = nullptr;
                    return do_read();
                } else {
                    __M_should_stop = true;
                    try {
                        on<bad_request>(__M_session, response_type(*this));
                    } catch (...) {
                        fatal_close();
                        std::rethrow_exception(std::current_exception());
                    }
                    return fatal_close();
                }
            } else {
                return do_read();
            }
        } else {
            return cntl().complete(std::error_code{});
        }
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
