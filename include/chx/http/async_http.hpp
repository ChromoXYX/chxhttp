#pragma once

#include "./request.hpp"
#include "./status_code.hpp"
#include "./events.hpp"
#include "./detail/payload.hpp"
#include "./session_closed.hpp"
#include "./response.hpp"

#include <chx/log.hpp>
#include <chx/net.hpp>

namespace chx::http::detail {
template <typename Event, typename T, typename... Args>
void on(T&& t, Args&&... args) {
    if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
        std::forward<T>(t)(Event(), std::forward<Args>(args)...);
    }
}

template <typename Stream, typename Session, typename FixedTimer,
          typename CntlType = int>
struct operation : CHXNET_NONCOPYABLE,
                   public net::detail::enable_weak_from_this<
                       operation<Stream, Session, FixedTimer, CntlType>> {
    using cntl_type = CntlType;
    template <typename T>
    using rebind = operation<Stream, Session, FixedTimer, T>;
    struct internal_read {};
    struct internal_write {};
    struct internal_write_final {};
    struct internal_timeout {};

    void unhandled_exception(cntl_type& cntl, std::exception_ptr) {
        terminate_now();
        cntl.complete(std::error_code{});
    }

    template <typename Str, typename Ses, typename Tmr>
    operation(Str&& str, Ses&& ses, Tmr& tmr)
        : __M_nstream(std::forward<Str>(str)),
          __M_session(std::make_unique<Session>(std::forward<Ses>(ses))),
          __M_tmr(tmr) {
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
    constexpr Session& session() noexcept(true) { return *__M_session; }
    constexpr const Session& session() const noexcept(true) {
        return *__M_session;
    }

    void cancel_all() { cntl()(nullptr); }

    template <typename Cntl> void operator()(Cntl& cntl) {
        on<connection_start>(session(), *this);
        do_read();

        __M_tmr.async_register(
            std::chrono::seconds(3),
            net::bind_cancellation_signal(
                __M_tmr_controller,
                cntl.template next_with_tag<internal_timeout>()));
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_read) {
        io_cntl.unset_recving();
        if (!e) {
            if (io_cntl.want_recv()) {
                feed2(__M_inbuf.data(), s);
                do_read();
            }
        } else if (e == net::errc::eof) {
            __M_tmr_controller.emit();
            __M_tmr_controller.clear();
            io_cntl.shutdown_recv();
        } else {
            // network failure, mostly eof
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
            if (__M_pending_response.empty()) {
                update_timeout(std::chrono::seconds(3));
            }
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

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, internal_timeout) {
        if (!e || e != net::errc::operation_canceled) {
            io_cntl.shutdown_recv();
            __M_tmr_controller.clear();
            cancel_all();
        }
        cntl.complete(e);
    }

  private:
    Stream __M_nstream;
    std::unique_ptr<Session> __M_session;
    FixedTimer& __M_tmr;
    net::cancellation_signal __M_tmr_controller;

    template <typename Rep, typename Period>
    void update_timeout(const std::chrono::duration<Rep, Period>& dur) {
        if (__M_tmr_controller.valid()) {
            auto* cntl =
                net::fixed_timer_controller(__M_tmr, __M_tmr_controller);
            assert(cntl && cntl->valid());

            if (dur.count() != 0) {
                std::chrono::time_point<std::chrono::system_clock> desired =
                    std::chrono::system_clock::now() + dur;
                if (desired > cntl->time_point()) {
                    cntl->update(desired);
                }
            } else if (cntl->time_point() != net::detail::__zero_time_point) {
                cntl->update(dur);
            }
        }
    }

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
            throw session_closed();
        }
    }
    constexpr bool get_guard() noexcept(true) {
        return !io_cntl.goaway_sent() && io_cntl.want_send();
    }

    template <typename... Ts>
    void response(status_code code, fields_type fields, Ts&&... ts) {
        if (get_guard()) {
            if (code == status_code::Bad_Request ||
                static_cast<unsigned short>(code) >= 500) {
                io_cntl.send_goaway();
                io_cntl.shutdown_recv();
            }

            // content length
            std::size_t content_length = 0;
            if constexpr (sizeof...(Ts)) {
                content_length = (... + net::buffer(ts).size());
            }
            fields.set_field("Content-Length",
                             log::format(CHXLOG_STR("%lu"), content_length));

            // connection
            if (!h11_would_close()) {
                fields.set_field("connection", "keep-alive");
                fields.set_field("keep-alive", "timeout=3");
            } else {
                fields.set_field("connection", "close");
            }

            __response(code, fields, std::forward<Ts>(ts)...);
            do_send();
        }
    }

    // h11_shutdown_recv and h11_shutdown_both shall not be invoked out of
    // async_combine::operator() scope!
    constexpr void h11_shutdown_recv() noexcept(true) {
        io_cntl.shutdown_recv();
    }

    constexpr bool h11_would_close() noexcept(true) {
        return !io_cntl.want_recv();
    }

    void terminate_now() {
        io_cntl.shutdown_both();
        __M_tmr_controller.clear();
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
                if (self->__M_parse_state.current_size + s <=
                    self->__M_parse_state.current_max) {
                    self->__M_parse_state.current_size += s;
                    try {
                        on<data_block>(self->session(), self->__M_request,
                                       response_impl(self), p, p + s);
                    } catch (const std::exception& ex) {
                        return HPE_USER;
                    }
                } else {
                    return -1;
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
                on<message_start>(self->session(), *self);
                return HPE_OK;
            };
            s.on_headers_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                try {
                    on<header_complete>(
                        self->session(),
                        const_cast<const request_type&>(self->__M_request),
                        response_impl(self));
                } catch (const std::exception& ex) {
                    return HPE_PAUSED;
                }
                return !self->io_cntl.goaway_sent() ? HPE_OK : HPE_PAUSED;
            };
            s.on_message_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_parse_state.current_size = 0;
                try {
                    if (!llhttp_should_keep_alive(c)) {
                        self->h11_shutdown_recv();
                    }
                    self->update_timeout(std::chrono::seconds(0));
                    on<message_complete>(self->session(), self->__M_request,
                                         response_impl(self));
                    self->__M_request = {};
                } catch (const std::exception& ex) {
                    return HPE_PAUSED;
                }
                return !self->io_cntl.goaway_sent() ? HPE_OK : HPE_PAUSED;
            };
        }
    } constexpr static inline settings = {};

    std::vector<char> __M_inbuf;
    std::string __M_pbuf;

    request_type __M_request;
    struct parse_state {
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
            update_timeout(std::chrono::seconds(0));
            net::async_write_sequence_exactly(
                stream().lowest_layer(), std::move(__M_pending_response),
                cntl().template next_with_tag<internal_write>());
        }
    }

    // 24.08.19 found it hard to understand feed(), so made feed2() :(
    // 24.08.23 i think it would be better for os to manage pipelining message,
    // not chxhttp :), so do_read() and do_send() should be called by response.
    // but pending_response is still useful.
    void feed2(const char* ptr, std::size_t len) {
        if (io_cntl.want_recv()) {
            llhttp_errno r;
            try {
                r = llhttp_execute(&__M_parser, ptr, len);
            } catch (...) {
                std::rethrow_exception(std::current_exception());
            }
            switch (r) {
            case HPE_OK: {
                // everything was ok
                break;
            }
            case HPE_USER:
            case HPE_PAUSED: {
                if (io_cntl.goaway_sent()) {
                    break;
                }
                // header_complete or message_complete throws, should
                // response with 500 and shutdown
                fields_type fields;
                fields.set_field("Server", "chxhttp.h11");
                response(status_code::Internal_Server_Error, std::move(fields));
                break;
            }
                // something else, and bad request
            default: {
                fields_type fields;
                fields.set_field("Server", "chxhttp.h11");
                response(status_code::Bad_Request, std::move(fields));
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

    class response_impl : public response {
        friend operation;

      public:
        response_impl(const response_impl&) = default;
        response_impl(response_impl&&) = default;

        std::unique_ptr<response> copy() const override {
            return std::unique_ptr<response>(new response_impl(__M_p));
        }
        void co_spawn(net::future<>&& future) const {
            if (get_guard()) {
                auto& cntl = __M_p.get()->cntl();
                net::co_spawn(
                    cntl.get_associated_io_context(),
                    [](net::future<> f) -> net::task {
                        co_return co_await f;
                    }(std::move(future)),
                    [&cntl](const std::error_code& e) { cntl.complete(e); });
            }
        }

        bool get_guard() const noexcept(true) override {
            return !__M_p.expired() && __M_p->get_guard();
        }

        void end(status_code code, fields_type&& fields) override {
            __response(code, std::move(fields));
        }
        void end(status_code code, fields_type&& fields,
                 std::string_view payload) {
            __response(code, std::move(fields), std::move(payload));
        }
        void end(status_code code, fields_type&& fields, std::string payload) {
            __response(code, std::move(fields), std::move(payload));
        }
        void end(status_code code, fields_type&& fields,
                 std::vector<unsigned char> payload) {
            __response(code, std::move(fields), std::move(payload));
        }
        void end(status_code code, fields_type&& fields,
                 net::mapped_file mapped, std::size_t len, std::size_t offset) {
            __response(code, std::move(fields),
                       net::carrier{std::move(mapped), offset, len});
        }

        const net::ip::tcp::socket& socket() const noexcept(true) override {
            return __M_p->stream();
        }

      private:
        constexpr response_impl(operation* self) noexcept(true)
            : __M_p(self->weak_from_this()) {}
        constexpr response_impl(const net::detail::weak_ptr<operation>& p)
            : __M_p(p) {}

        net::detail::weak_ptr<operation> __M_p;

        template <typename... Ts>
        void __response(status_code code, fields_type&& fields, Ts&&... ts) {
            if (get_guard()) {
                __M_p->response(code, std::move(fields),
                                std::forward<Ts>(ts)...);
            }
        }
    };
};
template <typename Stream, typename Session, typename FixedTimer>
operation(Stream&&, Session&&, FixedTimer&) -> operation<
    std::conditional_t<std::is_rvalue_reference_v<Stream&&>, Stream, Stream&&>,
    std::conditional_t<std::is_rvalue_reference_v<Session&&>, Session,
                       Session&&>,
    FixedTimer>;
}  // namespace chx::http::detail

namespace chx::http {
template <typename Stream, typename Session, typename FixedTimer,
          typename CompletionToken>
decltype(auto) async_http(Stream&& stream, Session&& session,
                          FixedTimer& fixed_timer,
                          CompletionToken&& completion_token) {
    using operation_type = decltype(detail::operation(
        std::forward<Stream>(stream), std::forward<Session>(session),
        fixed_timer));
    return net::async_combine_reference_count<const std::error_code&>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream), std::forward<Session>(session),
        fixed_timer);
}
}  // namespace chx::http
