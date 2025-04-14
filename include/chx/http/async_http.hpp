#pragma once

#include "./request.hpp"
#include "./status_code.hpp"
#include "./events.hpp"
#include "./session_closed.hpp"
#include "./response.hpp"
#include "./options.hpp"

#include <chx/log.hpp>
#include <chx/net.hpp>
#include <chx/net/detail/accumulate_size.hpp>

namespace chx::http::detail {
template <typename Event, typename T, typename... Args>
void on(T&& t, Args&&... args) {
    if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
        std::forward<T>(t)(Event(), std::forward<Args>(args)...);
    }
}

/*
About timeout:
now there are only 2 timeouts: read_timeout and write_timeout.
for read_timeout: updates timer after every read operation completes, pauses
when message_complete (wait for backend), and gets resumed after every pending
data sent.
*/

template <typename Stream, typename Session, typename CntlType = int>
struct operation
    : net::detail::enable_weak_from_this<operation<Stream, Session, CntlType>> {
    CHXNET_NONCOPYABLE

    operation(operation&&) = delete;

    using cntl_type = CntlType;
    template <typename T> using rebind = operation<Stream, Session, T>;
    struct internal_read {};
    struct internal_write {};
    struct internal_timeout {};
    // struct internal_backend_timeout {};

    template <typename Str, typename Ses, typename Tmr>
    operation(Str&& str, Ses&& ses, Tmr& tmr, const options_t* options)
        : __M_stream(std::forward<Str>(str)),
          __M_session(std::forward<Ses>(ses)), __M_tmr(tmr),
          __M_options(options) {
        __M_inbuf.resize(4096);
        llhttp_init(&__M_parser, HTTP_REQUEST, &settings.s);
        __M_parser.data = this;
    }

    auto& stream() { return __M_stream; }
    const auto& stream() const { return __M_stream; }
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
                __M_options->keepalive_timeout,
                net::bind_cancellation_signal(
                    __M_keepalive_controller,
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
                update_keepalive_timeout(__M_options->keepalive_timeout);
                __M_inbuf_begin = __M_inbuf.data();
                __M_inbuf_sz = s;
                do_feed();
            } else if (e == net::additional_errc::eof ||
                       e == net::errc::io_error) {
                shutdown_recv();
            } else {
                // network failure
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
                if (flying_stream_n() == 0 && io_cntl.want_recv()) {
                    // no pending response, and can still read
                    update_keepalive_timeout(__M_options->keepalive_timeout);
                }
                do_send();
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
    void operator()(Cntl& cntl, const std::error_code& e, internal_timeout) {
        try {
            __M_keepalive_controller.clear();
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

  private:
    Stream __M_stream;
    Session __M_session;
    net::fixed_timer& __M_tmr;
    net::cancellation_signal
        __M_keepalive_controller;  // keepalive_timeout equals to
                                   // lingering_timeout

    const options_t* const __M_options;

    template <typename Rep, typename Period>
    void
    update_keepalive_timeout(const std::chrono::duration<Rep, Period>& dur) {
        if (__M_keepalive_controller.valid()) {
            auto* cntl = net::fixed_timer_controller(__M_keepalive_controller);
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
        std::string, std::tuple<std::string, net::const_buffer>,
        std::tuple<std::string, std::string>,
        std::tuple<std::string, std::vector<unsigned char>>,
        std::tuple<std::string, net::mapped_file>,
        std::tuple<std::string, net::carrier<net::mapped_file>>,
        std::tuple<std::string, net::vcarrier>,
        std::tuple<std::string, std::vector<std::vector<unsigned char>>>,

        std::vector<unsigned char>, std::string_view>;
    enum __Resp_Var : std::size_t {
        __Resp_HeaderOnly = 0,
        __Resp_ConstBuffer = 1,
        __Resp_Str = 2,
        __Resp_Vector = 3,
        __Resp_MappedFile = 4,
        __Resp_MappedFileCarrier = 5,
        __Resp_VCarrier = 6,
        __Resp_MultiVector = 7,

        __Resp_StreamingString = 0,
        __Resp_StreamingVector = 8,
        __Resp_StreamingStringView = 9
    };
    std::vector<response_variant_t> __M_pending_response;

    struct cmp {
        constexpr bool
        operator()(const std::pair<std::size_t, response_variant_t>& a,
                   const std::pair<std::size_t, response_variant_t>& b) const
            noexcept(true) {
            return a.first > b.first;
        }
    };
    std::priority_queue<std::pair<std::size_t, response_variant_t>,
                        std::vector<std::pair<std::size_t, response_variant_t>>,
                        cmp>
        __M_strms_queue;
    // std::size_t __M_next_in_stream_id = 0;
    std::size_t __M_current_in_stream_id = 0;
    std::size_t __M_next_out_stream_id = 0;

    constexpr std::size_t flying_stream_n() noexcept(true) {
        return __M_current_in_stream_id - __M_next_out_stream_id + 1;
    }

    std::size_t streaming_flush_header(status_code code, fields_type&& fields) {
        fields.set_field("transfer-encoding", "chunked");
        std::string r =
            chx::log::format(CHXLOG_STR("HTTP/1.1 %u %s\r\n%s\r\n"),
                             static_cast<unsigned short>(code),
                             status_code_name(code), fields.to_string());
        std::size_t s = r.size();
        __M_pending_response.emplace_back(
            std::in_place_index<__Resp_StreamingString>, std::move(r));
        do_send();
        do_feed();
        return s;
    }
    std::size_t streaming_flush(std::vector<unsigned char>&& buffer) {
        std::size_t s = buffer.size();
        std::string prefix = chx::log::format(CHXLOG_STR("%:x:lu\r\n"), s);
        __M_pending_response.emplace_back(
            std::in_place_index<__Resp_StreamingString>, std::move(prefix));
        __M_pending_response.emplace_back(
            std::in_place_index<__Resp_StreamingVector>, std::move(buffer));
        __M_pending_response.emplace_back(
            std::in_place_index<__Resp_StreamingStringView>,
            std::string_view{"\r\n"});
        do_send();
        do_feed();
        return s;
    }
    void streaming_commit() {
        __M_pending_response.emplace_back(
            std::in_place_index<__Resp_StreamingStringView>,
            std::string_view{"0\r\n\r\n"});
        ++__M_next_out_stream_id;
        while (!__M_strms_queue.empty() &&
               __M_strms_queue.top().first == __M_next_out_stream_id) {
            __M_pending_response.emplace_back(std::move(
                const_cast<response_variant_t&>(__M_strms_queue.top().second)));
            __M_strms_queue.pop();
            ++__M_next_out_stream_id;
        }
        do_send();
        do_feed();
    }

    template <std::size_t Idx, typename... Ts>
    void __response_emplace(std::size_t strm_id, status_code code,
                            const fields_type& fields, Ts&&... ts) {
        if (strm_id < __M_next_out_stream_id) {
            return;
        }
        if (strm_id == __M_next_out_stream_id) {
            __M_pending_response.emplace_back(
                std::in_place_index_t<Idx>{},
                chx::log::format(CHXLOG_STR("HTTP/1.1 %u %s\r\n%s\r\n"),
                                 static_cast<unsigned short>(code),
                                 status_code_name(code), fields.to_string()),
                std::forward<Ts>(ts)...);
            ++__M_next_out_stream_id;
        } else {
            __M_strms_queue.emplace(
                strm_id, response_variant_t(
                             std::in_place_index_t<Idx>{},
                             chx::log::format(
                                 CHXLOG_STR("HTTP/1.1 %u %s\r\n%s\r\n"),
                                 static_cast<unsigned short>(code),
                                 status_code_name(code), fields.to_string()),
                             std::forward<Ts>(ts)...));
        }
        while (!__M_strms_queue.empty() &&
               __M_strms_queue.top().first == __M_next_out_stream_id) {
            __M_pending_response.emplace_back(std::move(
                const_cast<response_variant_t&>(__M_strms_queue.top().second)));
            __M_strms_queue.pop();
            ++__M_next_out_stream_id;
        }
        do_send();
        do_feed();
    }

    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields) {
        __response_emplace<__Resp_HeaderOnly>(strm_id, code, fields);
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, net::const_buffer view) {
        __response_emplace<__Resp_ConstBuffer>(strm_id, code, fields, view);
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, std::string&& str) {
        __response_emplace<__Resp_Str>(strm_id, code, fields, std::move(str));
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, std::vector<unsigned char>&& d) {
        __response_emplace<__Resp_Vector>(strm_id, code, fields, std::move(d));
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, net::mapped_file&& f) {
        __response_emplace<__Resp_MappedFile>(strm_id, code, fields,
                                              std::move(f));
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields,
                    net::carrier<net::mapped_file>&& f) {
        __response_emplace<__Resp_MappedFileCarrier>(strm_id, code, fields,
                                                     std::move(f));
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields, net::vcarrier&& v) {
        __response_emplace<__Resp_VCarrier>(strm_id, code, fields,
                                            std::move(v));
    }
    void __response(std::size_t strm_id, status_code code,
                    const fields_type& fields,
                    std::vector<std::vector<unsigned char>>&& v) {
        __response_emplace<__Resp_MultiVector>(strm_id, code, fields,
                                               std::move(v));
    }

  public:
    constexpr auto& guard() {
        if (get_guard()) {
            return *this;
        } else {
            throw session_closed();
        }
    }
    constexpr bool get_guard() noexcept(true) { return io_cntl.want_send(); }

    template <typename... Ts>
    void response(std::size_t strm_id, status_code code, fields_type fields,
                  Ts&&... ts) {
        if (get_guard()) {
            // content length
            std::size_t content_length = 0;
            if constexpr (sizeof...(Ts)) {
                content_length = net::detail::accumulate_size(ts...);
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
        cancel_all();
    }

  private:
    struct settings_t {
        llhttp_settings_t s = {};

        static int consume(llhttp_t* c, const char* p, std::size_t s) {
            operation* self = static_cast<operation*>(c->data);
            if (self->__M_parse_state.current_size + s <=
                self->__M_options->max_header_size) {
                self->__M_parse_state.current_size += s;
                self->__M_pbuf.append(p, s);
                return HPE_OK;
            } else {
                self->encountered_error(http::status_code::URI_Too_Long,
                                        self->__M_current_in_stream_id);
                return -1;
            }
        }

        constexpr settings_t() {
            s.on_body = [](llhttp_t* c, const char* p, std::size_t s) -> int {
                operation* self = static_cast<operation*>(c->data);
                on<data_block>(
                    self->session(), self->__M_current_request,
                    response_impl(self, self->__M_current_in_stream_id),
                    (const unsigned char*)p, (const unsigned char*)p + s);
                return self->io_cntl.want_recv() ? HPE_OK : HPE_PAUSED;
            };
            s.on_url = consume;
            s.on_header_field = consume;
            s.on_header_value = consume;

            s.on_method_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_current_request.method =
                    detail::method_from_h1(llhttp_get_method(c));
                return HPE_OK;
            };
            s.on_url_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_current_request.request_target =
                    std::move(self->__M_pbuf);
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_field_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_current_request.fields.emplace_back(
                    std::move(self->__M_pbuf));
                self->__M_pbuf.clear();
                return HPE_OK;
            };
            s.on_header_value_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_current_request.fields.back().second =
                    std::move(self->__M_pbuf);
                self->__M_pbuf.clear();
                return HPE_OK;
            };

            s.on_message_begin = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_parse_state = {};
                self->__M_current_request = {};
                on<message_start>(self->session(), *self);
                return HPE_OK;
            };
            s.on_headers_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_parse_state.current_size = 0;
                on<header_complete>(
                    self->session(), self->__M_current_request,
                    response_impl(self, self->__M_current_in_stream_id));
                return !self->should_pause() && self->io_cntl.want_recv()
                           ? HPE_OK
                           : HPE_PAUSED;
            };
            s.on_message_complete = [](llhttp_t* c) -> int {
                operation* self = static_cast<operation*>(c->data);
                self->__M_parse_state.current_size = 0;
                if (!llhttp_should_keep_alive(c)) {
                    self->shutdown_recv();
                } else if (self->__M_current_in_stream_id >=
                           self->__M_options->max_stream_id) {
                    self->shutdown_recv();
                }
                self->update_keepalive_timeout(std::chrono::seconds(0));
                on<message_complete>(
                    self->session(), self->__M_current_request,
                    response_impl(self, self->__M_current_in_stream_id++));
                return (self->flying_stream_n() <
                            self->__M_options->max_concurrent_stream &&
                        self->io_cntl.want_recv())
                           ? HPE_OK
                           : HPE_PAUSED;
            };
        }
    } constexpr static inline settings = {};

    std::vector<char> __M_inbuf;
    const char* __M_inbuf_begin = nullptr;
    std::size_t __M_inbuf_sz = 0;
    std::string __M_pbuf;

    // net::detail::weak_ptr<h11_stream> __M_curr_strm;
    // net::detail::main_anchor<h11_stream> __M_curr_strm_anchor;
    struct parse_state {
        union {
            ssize_t current_size = 0;
        };
        std::size_t pause_vote = 0;
    } __M_parse_state;
    constexpr bool should_pause() noexcept(true) {
        return __M_parse_state.pause_vote;
    }
    request_type __M_current_request = {};
    llhttp_t __M_parser;

    struct {
        /*
        http/1.1 io_cntl only has 2 flags: recv and send
        recv: can read message from socket/can process message from buffer
        send: can write message to socket/can store message in pending message
        queue

        goaway removed. we need goaway flag in h2 because we want to make sure
        GOAWAY frame must be the last frame in pending message queue. however in
        http/1.1, we do not have a GOAWAY frame, and we always want to recv or
        send whenever we can.
        */
        constexpr bool want_recv() const noexcept(true) { return v & 1; }
        constexpr bool want_send() const noexcept(true) { return v & 2; }
        constexpr bool is_sending() const noexcept(true) { return v & 4; }
        constexpr bool is_recving() const noexcept(true) { return v & 8; }

        constexpr void set_sending() noexcept(true) { v |= 4; }
        constexpr void unset_sending() noexcept(true) { v &= ~4; }

        constexpr void set_recving() noexcept(true) { v |= 8; }
        constexpr void unset_recving() noexcept(true) { v &= ~8; }

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
        __M_keepalive_controller.emit();
        __M_keepalive_controller.clear();
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
        __M_keepalive_controller.emit();
        __M_keepalive_controller.clear();
        io_cntl.shutdown_both();
    }

    void do_feed() {
        if (!should_pause() && io_cntl.want_recv() && !io_cntl.is_recving() &&
            flying_stream_n() <= __M_options->max_concurrent_stream) {
            __feed(__M_inbuf_begin, __M_inbuf_sz);
        }
    }

    void do_read() {
        if (!should_pause() && io_cntl.want_recv() && !io_cntl.is_recving() &&
            flying_stream_n() <= __M_options->max_concurrent_stream) {
            assert(__M_inbuf_sz == 0);
            io_cntl.set_recving();
            stream().lowest_layer().async_read_some(
                net::buffer(__M_inbuf),
                cntl().template next_with_tag<internal_read>());
        }
    }

    void do_send() {
        if (io_cntl.want_send() && !io_cntl.is_sending() &&
            !__M_pending_response.empty()) {
            io_cntl.set_sending();
            update_keepalive_timeout(std::chrono::seconds(0));
            net::async_write_sequence_exactly(
                stream().lowest_layer(), std::move(__M_pending_response),
                cntl().template next_with_tag<internal_write>());
        }
    }

    void encountered_error(status_code code, std::size_t strm_id) {
        shutdown_recv();
        on<ev::request_4xx>(session(), code, __M_current_request,
                            response_impl(this, strm_id));
    }

    // 24.08.19 found it hard to understand feed(), so made feed2() :(
    // 24.08.23 i think it would be better for os to manage pipelining message,
    // not chxhttp :), so do_read() and do_send() should be called by response.
    // but pending_response is still useful.
    void __feed(const char* ptr, std::size_t len) {
        if (!io_cntl.is_feeding()) {
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
            case HPE_PAUSED:  // session want to pause, or too many strm
            {
                const char* stop_pos = llhttp_get_error_pos(&__M_parser);
                assert(stop_pos >= ptr);
                __M_inbuf_begin = stop_pos;
                __M_inbuf_sz = len - (stop_pos - ptr);
                llhttp_resume(&__M_parser);
                return;
            }
            case HPE_USER:  // callbacks returns -1
                return;
            default: {
                encountered_error(status_code::Bad_Request,
                                  __M_current_in_stream_id);
            }
            }
        }
    }

    class response_impl : public response_type {
        friend operation;

      public:
        response_impl(const response_impl&) = default;
        response_impl(response_impl&&) = default;

        virtual ~response_impl() = default;

      private:
        virtual std::unique_ptr<response_type> make_unique() const override {
            return std::make_unique<response_impl>(*this);
        }
        virtual std::shared_ptr<response_type> make_shared() const override {
            return std::make_shared<response_impl>(*this);
        }

        virtual bool get_guard() const noexcept(true) override {
            return self && self->get_guard() &&
                   !(self->__M_current_in_stream_id == strm_id);
        }

        virtual void do_end(status_code code, fields_type&& fields) override {
            do_response(code, std::move(fields));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::const_buffer buffer) override {
            do_response(code, std::move(fields), std::move(buffer));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::string payload) override {
            do_response(code, std::move(fields), std::move(payload));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            std::vector<unsigned char> payload) override {
            do_response(code, std::move(fields), std::move(payload));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::mapped_file mapped) override {
            do_response(code, std::move(fields), std::move(mapped));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::carrier<net::mapped_file> mapped) override {
            do_response(code, std::move(fields), std::move(mapped));
        }
        virtual void do_end(status_code code, fields_type&& fields,
                            net::vcarrier&& vcarrier) override {
            do_response(code, std::move(fields), std::move(vcarrier));
        }
        virtual void
        do_end(status_code code, fields_type&& fields,
               std::vector<std::vector<unsigned char>> b) override {
            do_response(code, std::move(fields), std::move(b));
        }

        virtual const net::ip::tcp::socket* socket() const
            noexcept(true) override {
            return self ? &self->stream() : nullptr;
        }

        virtual void do_terminate() override {
            if (self) {
                self->terminate_now();
            }
        }
        virtual void do_pause() override {
            if (self) {
                self->update_keepalive_timeout(std::chrono::seconds(0));
                ++self->__M_parse_state.pause_vote;
            }
        }
        virtual void do_resume() override {
            if (self) {
                assert(self->__M_parse_state.pause_vote);
                --self->__M_parse_state.pause_vote;
                self->update_keepalive_timeout(
                    self->__M_options->keepalive_timeout);
                self->do_feed();
            }
        }

        virtual bool do_streaming_would_block() noexcept(true) override {
            return get_guard() && self->__M_next_out_stream_id != strm_id;
        }
        virtual std::size_t
        do_streaming_flush_header(status_code code,
                                  fields_type&& fields) override {
            assert(!do_streaming_would_block());
            return self->streaming_flush_header(code, std::move(fields));
        }
        virtual std::size_t
        do_streaming_flush(std::vector<unsigned char>&& buffer) override {
            assert(!do_streaming_would_block());
            return self->streaming_flush(std::move(buffer));
        }
        void do_streaming_commit() override {
            assert(!do_streaming_would_block());
            return self->streaming_commit();
        }

        virtual net::io_context& do_get_associated_io_context() const override {
            if (do_expired()) {
                throw session_closed{};
            }
            return self->cntl().get_associated_io_context();
        }

        virtual bool do_expired() const noexcept(true) override {
            return !self;
        }

        constexpr response_impl(operation* s, std::size_t id) noexcept(true)
            : self(s->weak_from_this()), strm_id(id) {}

        net::detail::weak_ptr<operation> self;
        const std::size_t strm_id;

        template <typename... Ts>
        void do_response(status_code code, fields_type&& fields, Ts&&... ts) {
            if (get_guard()) {
                self->response(strm_id, code, std::move(fields),
                               std::forward<Ts>(ts)...);
            }
        }
    };
};
template <typename Stream, typename Session, typename FixedTimer>
operation(Stream&&, Session&&, FixedTimer&, const options_t*) -> operation<
    std::conditional_t<std::is_rvalue_reference_v<Stream&&>, Stream, Stream&&>,
    std::conditional_t<std::is_rvalue_reference_v<Session&&>, Session,
                       Session&&>,
    FixedTimer>;
}  // namespace chx::http::detail

namespace chx::http {
template <typename Stream, typename SessionFactory, typename CompletionToken>
decltype(auto) async_http(Stream&& stream, SessionFactory&& session_factory,
                          net::fixed_timer& fixed_timer,
                          const options_t* options,
                          CompletionToken&& completion_token) {
    using operation_type = decltype(detail::operation(
        std::forward<Stream>(stream),
        std::forward<SessionFactory>(session_factory)(), fixed_timer, options));
    return net::async_combine_reference_count<const std::error_code&>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream),
        std::forward<SessionFactory>(session_factory)(), fixed_timer, options);
}

template <typename Stream, typename SessionFactory, typename CompletionToken>
decltype(auto) async_http(Stream&& stream, SessionFactory&& session_factory,
                          net::fixed_timer& fixed_timer,
                          CompletionToken&& completion_token) {
    return async_http(std::forward<Stream>(stream),
                      std::forward<SessionFactory>(session_factory),
                      fixed_timer, &default_options,
                      std::forward<CompletionToken>(completion_token));
}
}  // namespace chx::http
