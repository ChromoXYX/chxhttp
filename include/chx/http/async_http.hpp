#pragma once

#include "./request.hpp"
#include "./status_code.hpp"
#include "./events.hpp"
#include "./detail/payload.hpp"
#include "./session_closed.hpp"
#include "./response.hpp"

#include <chx/log.hpp>
#include <chx/net.hpp>
#include <map>

namespace chx::http::detail {
template <typename Event, typename T, typename... Args>
void on(T&& t, Args&&... args) {
    if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
        std::forward<T>(t)(Event(), std::forward<Args>(args)...);
    }
}

template <typename Stream, typename Session, typename CntlType = int>
struct operation
    : CHXNET_NONCOPYABLE,
      net::detail::enable_weak_from_this<operation<Stream, Session, CntlType>> {
    using cntl_type = CntlType;
    template <typename T> using rebind = operation<Stream, Session, T>;
    struct internal_read {};
    struct internal_write {};
    struct internal_write_final {};
    struct internal_timeout {};
    struct internal_backend_timeout {};

    template <typename Str, typename Ses, typename Tmr>
    operation(Str&& str, Ses&& ses, Tmr& tmr)
        : __M_nstream(std::forward<Str>(str)),
          __M_session(std::forward<Ses>(ses)), __M_tmr(tmr) {
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

    void cancel_all() {
        try {
            cntl()(nullptr);
        } catch (const std::exception&) {
            net::rethrow_with_fatal(std::current_exception());
        }
    }

    template <typename Cntl> void operator()(Cntl& cntl) {
        try {
            on<connection_start>(session(), *this);
            do_read();

            __M_tmr.async_register(
                std::chrono::seconds(3),
                net::bind_cancellation_signal(
                    __M_tmr_controller,
                    cntl.template next_with_tag<internal_timeout>()));
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_read) {
        try {
            io_cntl.unset_recving();
            if (!e) {
                __M_inbuf_begin = __M_inbuf.data();
                __M_inbuf_sz = s;
                feed2(__M_inbuf_begin, __M_inbuf_sz);
            } else if (e == net::errc::eof || e == net::errc::io_error) {
                shutdown_recv();
            } else {
                // network failure, mostly eof
                terminate_now();
            }
            cntl.complete(e);
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_write) {
        try {
            io_cntl.unset_sending();
            // internal_write would never get cancelled, except for
            // terminate_now()
            if (!e) {
                if (__M_strms.empty()) {
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
                            cntl.template next_with_tag<
                                internal_write_final>());
                    }
                }
            } else {
                terminate_now();
            }
            cntl.complete(e);
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, std::size_t s,
                    internal_write_final) {
        try {
            io_cntl.unset_sending();
            if (e) {
                terminate_now();
            }
            cntl.complete(e);
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, internal_timeout) {
        try {
            if (!e) {
                shutdown_recv();
            }
            cntl.complete(e);
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e,
                    internal_backend_timeout) {
        try {
            __M_backend_tmr_controller.clear();
            if (!e) {
                while (!__M_strms.empty() &&
                       __M_strms.begin()->second.ddl <
                           std::chrono::steady_clock::now()) {
                    auto ite = __M_strms.begin();
                    auto weak_ptr = ite->second.weak_from_this();
                    on<backend_timeout>(
                        session(), ite->second.request,
                        response_impl(this, ite->second.weak_from_this()));
                    if (weak_ptr) {
                        __M_strms.erase(ite);
                    }
                }
                if (!__M_strms.empty()) {
                    __M_tmr.async_register(
                        __M_strms.begin()->second.ddl,
                        bind_cancellation_signal(
                            __M_backend_tmr_controller,
                            cntl.template next_with_tag<
                                internal_backend_timeout>()));
                    assert(__M_backend_tmr_controller);
                }
            }
            cntl.complete(e);
        } catch (const std::exception&) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

  private:
    Stream __M_nstream;
    Session __M_session;
    net::fixed_timer& __M_tmr;
    net::cancellation_signal __M_tmr_controller;
    net::cancellation_signal __M_backend_tmr_controller;

    template <typename Rep, typename Period>
    void update_timeout(const std::chrono::duration<Rep, Period>& dur) {
        if (__M_tmr_controller.valid()) {
            auto* cntl = net::fixed_timer_controller(__M_tmr_controller);
            assert(cntl && cntl->valid());

            if (dur.count() != 0) {
                std::chrono::time_point<std::chrono::steady_clock> desired =
                    std::chrono::steady_clock::now() + dur;
                if (desired > cntl->time_point()) {
                    cntl->update(desired);
                }
            } else if (cntl->time_point() != net::detail::__zero_time_point<
                                                 std::chrono::steady_clock>) {
                cntl->update(dur);
            }
        }
    }

    using response_variant_t = std::variant<
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
        std::string_view>;
    std::vector<response_variant_t> __M_pending_response;
    std::queue<std::pair<std::size_t, response_variant_t>> __M_strms_queue;
    std::size_t __M_next_in_stream_id = 0;
    std::size_t __M_next_out_stream_id = 0;

    // handle pipelining like what we do in h2 :/
    struct h11_stream : net::detail::enable_weak_from_this<h11_stream> {
        using map_type = std::map<std::size_t, h11_stream>;
        using iterator = typename map_type::iterator;

        iterator self;
        request_type request;
        std::chrono::steady_clock::time_point ddl = {};
    };
    std::map<std::size_t, h11_stream> __M_strms;
    h11_stream& create_stream() {
        auto [ite, c] =
            __M_strms.emplace(__M_next_in_stream_id++, h11_stream{});
        assert(c);
        h11_stream& strm = ite->second;
        strm.self = ite;
        return strm;
    }
    void set_stream_backend_ddl(const net::detail::weak_ptr<h11_stream>& ptr) {
        h11_stream& strm = *ptr;
        strm.ddl = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        if (!__M_backend_tmr_controller) {
            __M_tmr.async_register(
                strm.ddl,
                bind_cancellation_signal(
                    __M_backend_tmr_controller,
                    cntl().template next_with_tag<internal_backend_timeout>()));
            assert(__M_backend_tmr_controller);
        }
    }

    template <std::size_t Idx, typename... Ts>
    void __response_emplace(std::size_t strm_id, status_code code,
                            const fields_type& fields, Ts&&... ts) {
        assert(strm_id >= __M_next_out_stream_id &&
               "stream id of response must >= __M_next_stream_id");
        assert(__M_strms.erase(strm_id) == 1);
        if (__M_strms.empty()) {
            __M_backend_tmr_controller.emit();
        }
        if (strm_id == __M_next_out_stream_id) {
            __M_pending_response.emplace_back(
                std::in_place_index_t<Idx>{}, std::string_view{"HTTP/1.1 "},
                chx::log::format(CHXLOG_STR("%u %s\r\n"),
                                 static_cast<unsigned short>(code),
                                 status_code_name(code)),
                fields.to_string(), std::string_view{"\r\n"},
                std::forward<Ts>(ts)...);
            ++__M_next_out_stream_id;
        } else {
            __M_strms_queue.emplace(
                strm_id,
                response_variant_t(
                    std::in_place_index_t<Idx>{}, std::string_view{"HTTP/1.1 "},
                    chx::log::format(CHXLOG_STR("%u %s\r\n"),
                                     static_cast<unsigned short>(code),
                                     status_code_name(code)),
                    fields.to_string(), std::string_view{"\r\n"},
                    std::forward<Ts>(ts)...));
        }
        while (!__M_strms_queue.empty() &&
               __M_strms_queue.front().first == __M_next_out_stream_id) {
            assert(__M_strms.count(__M_strms_queue.front().first) == 0);
            __M_pending_response.emplace_back(
                std::move(__M_strms_queue.front().second));
            __M_strms_queue.pop();
            ++__M_next_out_stream_id;
        }
        do_send();
        do_read();
    }

    template <typename... Ts>
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, Ts&&... ts) {
        if constexpr (sizeof...(Ts) > 1) {
            return __response_multi(strm_id, code, fields,
                                    std::forward<Ts>(ts)...);
        } else if constexpr (sizeof...(Ts) == 1) {
            return __response_single(strm_id, code, fields,
                                     std::forward<Ts>(ts)...);
        } else {
            return __response0(strm_id, code, fields);
        }
    }
    void __response0(std::size_t strm_id, status_code code,
                     const fields_type& fields) {
        __response_emplace<0>(strm_id, code, fields);
    }
    template <typename... Ts>
    void __response_multi(std::size_t strm_id, status_code code,
                          const fields_type& fields, Ts&&... ts) {
        std::unique_ptr store =
            detail::payload_store::create(std::forward<Ts>(ts)...);
        std::vector<net::iovec_buffer> iov =
            detail::create_iovec_vector(store->data);
        __response_emplace<1>(strm_id, code, fields, std::move(store),
                              std::move(iov));
    }
    template <typename T>
    void __response_single(std::size_t strm_id, status_code code,
                           const fields_type& fields, T&& t) {
        if constexpr (std::is_lvalue_reference_v<T> &&
                      !std::is_same_v<std::decay_t<T>, std::string_view>) {
            return __response_multi(strm_id, code, fields, std::forward<T>(t));
        } else {
            using __dct = std::decay_t<T>;
            if constexpr (std::is_same_v<__dct, std::vector<unsigned char>>) {
                __response_emplace<2>(strm_id, code, fields, std::move(t));
            } else if constexpr (std::is_same_v<__dct, std::string_view>) {
                __response_emplace<4>(strm_id, code, fields, t);
            } else if constexpr (std::is_same_v<
                                     __dct, std::vector<net::iovec_buffer>>) {
                __response_emplace<3>(strm_id, code, fields, std::move(t));
            } else {
                return __response_multi(strm_id, code, fields,
                                        std::forward<T>(t));
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
    void response(std::size_t strm_id, status_code code, fields_type fields,
                  Ts&&... ts) {
        if (get_guard()) {
            if (code == status_code::Bad_Request) {
                io_cntl.send_goaway();
                shutdown_recv();
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

            __response(strm_id, code, fields, std::forward<Ts>(ts)...);
        }
    }

    constexpr bool h11_would_close() noexcept(true) {
        return !io_cntl.want_recv();
    }

    void terminate_now() {
        shutdown_both();
        io_cntl.send_goaway();
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
                    if (self->__M_curr_strm) {
                        on<data_block>(self->session(),
                                       const_cast<const request_type&>(
                                           self->__M_curr_strm->request),
                                       response_impl(self, self->__M_curr_strm),
                                       (const unsigned char*)p,
                                       (const unsigned char*)p + s);
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
                if (self->__M_curr_strm) {
                    self->__M_curr_strm->request.method =
                        detail::method_from_h1(llhttp_get_method(c));
                }
                return HPE_OK;
            };
            s.on_url_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                if (self->__M_curr_strm) {
                    self->__M_curr_strm->request.request_target =
                        std::move(self->__M_pbuf);
                }
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_field_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                if (self->__M_curr_strm) {
                    self->__M_curr_strm->request.fields.emplace_back(
                        std::move(self->__M_pbuf));
                }
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_value_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                if (self->__M_curr_strm) {
                    self->__M_curr_strm->request.fields.back().second =
                        std::move(self->__M_pbuf);
                }
                self->__M_pbuf.clear();
                return HPE_OK;
            };

            s.on_message_begin = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_curr_strm = self->create_stream().weak_from_this();
                on<message_start>(self->session(), *self);
                return HPE_OK;
            };
            s.on_headers_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                if (self->__M_curr_strm) {
                    on<header_complete>(
                        self->session(),
                        const_cast<const request_type&>(
                            self->__M_curr_strm->request),
                        response_impl(self, self->__M_curr_strm));
                }
                return !self->io_cntl.goaway_sent() ? HPE_OK : HPE_PAUSED;
            };
            s.on_message_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_parse_state.current_size = 0;
                if (!llhttp_should_keep_alive(c)) {
                    self->shutdown_recv();
                }
                if (self->__M_curr_strm) {
                    self->update_timeout(std::chrono::seconds(0));
                    self->set_stream_backend_ddl(self->__M_curr_strm);
                    on<message_complete>(
                        self->session(), self->__M_curr_strm->request,
                        response_impl(self, self->__M_curr_strm));
                }
                return self->__M_strms.size() < -1 &&
                               !self->io_cntl.goaway_sent()
                           ? HPE_OK
                           : HPE_PAUSED;
            };
        }
    } constexpr static inline settings = {};

    std::vector<char> __M_inbuf;
    const char* __M_inbuf_begin = nullptr;
    std::size_t __M_inbuf_sz = 0;
    std::string __M_pbuf;

    net::detail::weak_ptr<h11_stream> __M_curr_strm;
    struct parse_state {
        std::size_t current_max = 4096;
        ssize_t current_size = 0;
    } __M_parse_state;
    llhttp_t __M_parser;

    struct {
        constexpr bool want_recv() const noexcept(true) { return v & 1; }
        constexpr bool want_send() const noexcept(true) { return v & 2; }
        constexpr bool is_sending() const noexcept(true) { return v & 4; }
        constexpr bool is_recving() const noexcept(true) { return v & 8; }

        constexpr void set_sending() noexcept(true) { v |= 4; }
        constexpr void unset_sending() noexcept(true) { v &= ~4; }

        constexpr void set_recving() noexcept(true) { v |= 8; }
        constexpr void unset_recving() noexcept(true) { v &= ~8; }

        constexpr void send_goaway() noexcept(true) { v |= 16; }
        constexpr bool goaway_sent() noexcept(true) { return v & 16; }

        constexpr void set_feeding() noexcept(true) { v |= 32; }
        constexpr void unset_feeding() noexcept(true) { v &= ~32; }
        constexpr bool is_feeding() noexcept(true) { return v & 32; }

        constexpr void shutdown_both() noexcept(true) {
            shutdown_recv();
            shutdown_send();
        }
        constexpr void shutdown_recv() noexcept(true) { v &= ~1; }
        constexpr void shutdown_send() noexcept(true) { v &= ~2; }

      private:
        char v = 1 | 2;
    } io_cntl;
    void shutdown_recv() noexcept(true) {
        std::error_code e;
        stream().shutdown(stream().shutdown_receive, e);
        __M_tmr_controller.emit();
        __M_tmr_controller.clear();
        io_cntl.shutdown_recv();
    }
    void shutdown_send() noexcept(true) {
        std::error_code e;
        stream().shutdown(stream().shutdown_write, e);
        io_cntl.shutdown_send();
    }
    void shutdown_both() noexcept(true) {
        std::error_code e;
        stream().shutdown(stream().shutdown_both, e);
        __M_tmr_controller.emit();
        __M_tmr_controller.clear();
        io_cntl.shutdown_both();
    }

    void do_read() {
        if (can_read()) {
            if (__M_inbuf_sz == 0) {
                io_cntl.set_recving();
                stream().lowest_layer().async_read_some(
                    net::buffer(__M_inbuf),
                    cntl().template next_with_tag<internal_read>());
            } else {
                feed2(__M_inbuf_begin, __M_inbuf_sz);
            }
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
        if (can_read() && !io_cntl.is_feeding()) {
            struct guard_t {
                constexpr guard_t(operation* o) : oper(o) {
                    oper->io_cntl.set_feeding();
                }
                constexpr ~guard_t() { oper->io_cntl.unset_feeding(); }

                operation* const oper;
            } guard(this);
            llhttp_errno r = llhttp_execute(&__M_parser, ptr, len);
            switch (r) {
            case HPE_OK:  // everything was ok
            {
                __M_inbuf_sz = 0;
                __M_inbuf_begin = nullptr;
                return do_read();
            }
            case HPE_PAUSED:  // user closed the connection
            {
                const char* stop_pos = llhttp_get_error_pos(&__M_parser);
                __M_inbuf_begin = stop_pos;
                __M_inbuf_sz = len - (stop_pos - ptr);
                llhttp_resume(&__M_parser);
                return;
            }
            case HPE_USER:
                // something else, and bad request
            default: {
                if (__M_curr_strm) {
                    fields_type fields;
                    fields.set_field("Server", "chxhttp.h11");
                    response(__M_curr_strm->self->first,
                             status_code::Bad_Request, std::move(fields));
                } else {
                    terminate_now();
                }
            }
            }
        }
    }

    constexpr bool can_read() noexcept(true) {
        return __M_strms.size() < -1 && io_cntl.want_recv() &&
               !io_cntl.is_recving();
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

        virtual ~response_impl() = default;

        virtual std::unique_ptr<response> make_unique() const override {
            return std::make_unique<response_impl>(*this);
        }
        virtual std::shared_ptr<response> make_shared() const override {
            return std::make_shared<response_impl>(*this);
        }

        virtual bool get_guard() const noexcept(true) override {
            return __M_p && __M_p->get_guard() && __M_strm;
        }

        virtual void do_end(status_code code, fields_type&& fields) override {
            __response(code, std::move(fields));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::string_view payload) override {
            __response(code, std::move(fields), std::move(payload));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::string payload) override {
            __response(code, std::move(fields), std::move(payload));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::vector<unsigned char> payload) override {
            __response(code, std::move(fields), std::move(payload));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::mapped_file mapped) override {
            __response(code, std::move(fields), std::move(mapped));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::carrier<net::mapped_file> mapped) override {
            __response(code, std::move(fields), std::move(mapped));
        }

        virtual const net::ip::tcp::socket* socket() const
            noexcept(true) override {
            return __M_p ? &__M_p->stream() : nullptr;
        }
        virtual void terminate() override {
            if (__M_p) {
                __M_p->terminate_now();
            }
        }
        virtual net::io_context* get_associated_io_context() const
            noexcept(true) override {
            return __M_p ? &__M_p->cntl().get_associated_io_context() : nullptr;
        }

      private:
        constexpr response_impl(
            operation* self,
            const net::detail::weak_ptr<h11_stream>& strm_ptr) noexcept(true)
            : __M_p(self->weak_from_this()), __M_strm(strm_ptr) {}

        net::detail::weak_ptr<operation> __M_p;
        net::detail::weak_ptr<h11_stream> __M_strm;

        template <typename... Ts>
        void __response(status_code code, fields_type&& fields, Ts&&... ts) {
            if (get_guard()) {
                __M_p->response(__M_strm->self->first, code, std::move(fields),
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
template <typename Stream, typename SessionFactory, typename CompletionToken>
decltype(auto) async_http(Stream&& stream, SessionFactory&& session_factory,
                          net::fixed_timer& fixed_timer,
                          CompletionToken&& completion_token) {
    using operation_type = decltype(detail::operation(
        std::forward<Stream>(stream),
        std::forward<SessionFactory>(session_factory)(), fixed_timer));
    return net::async_combine_reference_count<const std::error_code&>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream),
        std::forward<SessionFactory>(session_factory)(), fixed_timer);
}
}  // namespace chx::http
