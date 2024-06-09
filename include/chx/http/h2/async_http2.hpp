#pragma once

#include <algorithm>
#include <chrono>
#include <chx/net/io_context.hpp>
#include <chx/net/async_write_sequence_exactly.hpp>
#include <chx/net/utility.hpp>
#include <chx/net/iovec_buffer.hpp>
#include <map>
#include <array>
#include <numeric>
#include <set>

#include "../detail/payload.hpp"
#include "./exception.hpp"
#include "./types.hpp"
#include "./frame_type.hpp"
#include "./error_codes.hpp"
#include "./settings.hpp"
#include "./detail/copy_integer.hpp"

namespace chx::http::h2::detail::tags {
struct http2_impl {};
}  // namespace chx::http::h2::detail::tags

namespace chx::http::h2::detail {
template <typename Stream, typename Session, typename HPackImpl,
          typename FixedTimerRef, typename CntlType = int>
class h2_impl : HPackImpl {
  public:
    template <typename T>
    using rebind = h2_impl<Stream, Session, HPackImpl, FixedTimerRef, T>;
    using cntl_type = CntlType;
    using stream_type = Stream;
    using session_type = Session;
    using session_stream_userdata_type = typename Session::stream_userdata_type;
    using Flags = http::h2::frame_type::Flags;

    struct ev_send {};
    struct ev_recv {};
    struct ev_preface {};
    struct ev_ack_timeout {};
    struct ev_watchdog {};

    template <typename Strm, typename HPack>
    h2_impl(Strm&& strm, std::unique_ptr<Session> p, HPack&& h,
            FixedTimerRef& ftr)
        : HPackImpl(std::forward<HPack>(h)),
          __M_stream(std::forward<Strm>(strm)), __M_session(std::move(p)),
          __M_fixed_timer(ftr) {}

    constexpr cntl_type& cntl() noexcept(true) {
        return static_cast<cntl_type&>(*this);
    }
    constexpr stream_type& stream() noexcept(true) { return __M_stream; }
    constexpr session_type& session() noexcept(true) { return *__M_session; }

    void operator()(cntl_type& cntl) {
        do_watchdog();
        __M_inbuf.resize(4096);
        // #1 client connection preface
        io_cntl.set_recving();
        stream().lowest_layer().async_read_some(
            net::buffer(__M_inbuf), cntl.template next_with_tag<ev_preface>());
        // #2 server connection preface
        struct static_preface_vec {
            std::vector<views::settings_type::setting_type> v;

            static_preface_vec() : v(4) {
                v[0].identifier(Settings::SETTINGS_NO_RFC7540_PRIORITIES);
                v[0].value(1);
                v[1].identifier(Settings::SETTINGS_INITIAL_WINDOW_SIZE);
                v[1].value(65535);
                v[2].identifier(Settings::SETTINGS_MAX_FRAME_SIZE);
                v[2].value(16384);
                v[3].identifier(Settings::SETTINGS_MAX_CONCURRENT_STREAMS);
                v[3].value(100);
            }
        } static preface_vec = {};
        try {
            create_SETTINGS_frame(preface_vec.v);
            do_send();
        } catch (const runtime_exception& ex) {
            std::terminate();
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_preface) {
        io_cntl.unset_recving();
        if (!e && can_read()) {
            // client_largest_id -> offset of preface,
            // 24 - client_largest_id -> remain sz
            if (s >= 24 - client_largest_id) {
                if (std::equal(__M_inbuf.begin(),
                               __M_inbuf.begin() + 24 - client_largest_id,
                               &impl_detail::client_connection_preface_cstr
                                   [client_largest_id])) {
                    int offset = client_largest_id;
                    client_largest_id = 0;
                    try {
                        feed2(__M_inbuf.data() + 24 - offset,
                              __M_inbuf.data() + s);
                    } catch (const runtime_exception& ex) {
                        terminate_now(ex.get_error_code());
                    } catch (const std::exception& ex) {
                        terminate_now();
                        cntl.complete(std::error_code{});
                        std::rethrow_exception(std::current_exception());
                    }
                }
                return cntl.complete(e);
            } else {
                if (std::equal(__M_inbuf.begin(), __M_inbuf.begin() + s,
                               &impl_detail::client_connection_preface_cstr
                                   [client_largest_id])) {
                    client_largest_id += s;
                    io_cntl.set_recving();
                    stream().lowest_layer().async_read_some(
                        net::buffer(__M_inbuf),
                        cntl.template next_with_tag<ev_preface>());
                } else {
                    return cntl.complete(e);
                }
            }
        } else {
            terminate_now(ErrorCodes::INTERNAL_ERROR);
            cntl.complete(e);
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_send) {
        io_cntl.unset_sending();
        if (io_cntl.goaway_sent()) {
            cancel_all();
        }
        if (!e || e == net::errc::operation_canceled) {
            do_send();
            if (io_cntl.goaway_sent()) {
                io_cntl.shutdown_send();
            }
        } else {
            // network failure
            terminate_now();
        }
        cntl.complete(e);
    }
    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_recv) {
        io_cntl.unset_recving();
        if (!e || e == net::errc::operation_canceled) {
            try {
                feed2(__M_inbuf.data(), __M_inbuf.data() + s);
            } catch (const runtime_exception& ex) {
                terminate_now(ex.get_error_code());
            } catch (const std::exception& ex) {
                terminate_now();
                cntl.complete(std::error_code{});
                std::rethrow_exception(std::current_exception());
            }
        } else {
            // network failure
            terminate_now();
        }
        cntl.complete(e);
    }

    void operator()(cntl_type& cntl, const std::error_code& e, ev_watchdog) {
        if (!e) {
            if (!(watchdog_settings_ack_deadline.time_since_epoch().count() !=
                      0 &&
                  std::chrono::system_clock::now() >
                      watchdog_settings_ack_deadline)) {
                do_watchdog();
            } else {
                terminate_now(ErrorCodes::SETTINGS_TIMEOUT);
            }
        } else if (e != net::errc::operation_canceled) {
            // chxnet failure
            terminate_now();
        }
        cntl.complete(e);
    }

  protected:
    Stream __M_stream;
    FixedTimerRef& __M_fixed_timer;
    std::unique_ptr<Session> __M_session;

    void cancel_all() { cntl()(nullptr); }

    template <typename... Args> constexpr void on(Args&&... args) {
        if constexpr (std::is_invocable_v<Session, Args&&...>) {
            session()(std::forward<Args>(args)...);
        }
    }

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
    void do_send() {
        if (can_send()) {
            io_cntl.set_sending();
            net::async_write_sequence_exactly(
                stream().lowest_layer(), std::move(pending_frames),
                cntl().template next_with_tag<ev_send>());
        }
    }
    void do_read() {
        if (can_read()) {
            io_cntl.set_recving();
            stream().lowest_layer().async_read_some(
                net::buffer(__M_inbuf),
                cntl().template next_with_tag<ev_recv>());
        }
    }

    constexpr HPackImpl& hpack() noexcept(true) { return *this; }

    std::vector<unsigned char> __M_inbuf;

    http::h2::frame_type frame_parse;
    enum class StreamStates : int {
        Idle,
        ReservedLocal,
        ReservedRemote,
        Open,
        HalfClosedRemote,
        HalfClosedLocal,
        // Closed
    };

    using payload_rep = http::detail::payload_rep;
    using payload_store = http::detail::payload_store;
    using payload_monostate = http::detail::payload_monostate;
    using payload_variant =
        std::variant<std::tuple<payload_rep, std::vector<net::iovec_buffer>>,
                     std::vector<unsigned char>, payload_monostate>;
    using pending_frame_type =
        std::tuple<std::array<unsigned char, 9>, payload_variant>;
    template <typename T>
    static auto&
    __pending_frame_type_emplace_back(std::vector<pending_frame_type>& v,
                                      std::array<unsigned char, 9>&& header,
                                      std::unique_ptr<T> store) {
        std::tuple<payload_rep, std::vector<net::iovec_buffer>> tp(
            payload_rep{}, http::detail::create_iovec_vector(store->data));
        std::get<0>(tp).payload.reset(store.release());
        return v.emplace_back(
            std::move(header),
            payload_variant(std::in_place_index_t<0>{}, std::move(tp)));
    }

    static auto&
    __pending_frame_type_emplace_back(std::vector<pending_frame_type>& v,
                                      std::array<unsigned char, 9>&& header,
                                      payload_rep rep,
                                      std::vector<net::iovec_buffer>&& iov) {
        return v.emplace_back(std::move(header),
                              payload_variant(std::in_place_index_t<0>{},
                                              std::move(rep), std::move(iov)));
    }
    static auto&
    __pending_frame_type_emplace_back(std::vector<pending_frame_type>& v,
                                      std::array<unsigned char, 9>&& header,
                                      std::vector<unsigned char>&& iov) {
        return v.emplace_back(
            std::move(header),
            payload_variant(std::in_place_index_t<1>{}, std::move(iov)));
    }
    static auto&
    __pending_frame_type_emplace_back(std::vector<pending_frame_type>& v,
                                      std::array<unsigned char, 9>&& header) {
        return v.emplace_back(std::move(header),
                              payload_variant(std::in_place_index_t<2>{}));
    }

    struct h2_stream : session_stream_userdata_type {
        StreamStates state = StreamStates::Idle;
        int client_window = 65535;
        int server_window = 65535;

        std::vector<frame_type> field_blocks;
        std::vector<frame_type> after;

        std::vector<pending_frame_type> pending_DATA_frames;
        template <typename... Ts>
        constexpr auto&
        pending_DATA_frames_emplace_back(std::array<unsigned char, 9>&& header,
                                         Ts&&... ts) {
            return __pending_frame_type_emplace_back(pending_DATA_frames,
                                                     std::move(header),
                                                     std::forward<Ts>(ts)...);
        }

        template <StreamStates... St>
        constexpr bool state_any_of() const noexcept(true) {
            return ((state == St) || ...);
        }
        constexpr session_stream_userdata_type& userdata() noexcept(true) {
            return *this;
        }
    };
    std::map<stream_id_type, h2_stream> __M_strms;
    std::set<stream_id_type> __M_strms_seek_for_window;
    using strms_iterator = std::map<stream_id_type, h2_stream>::iterator;
    // bytes client can send
    int client_conn_window = 65535;
    // bytes server can send
    int server_conn_window = 65535;
    stream_id_type client_largest_id = 0;

    struct {
        int header_table_size = 4096;
        // no pp!
        int enable_push = 1;
        // useless since chxhttp cannot init stream, for now
        int max_concurrent_streams = 100;
        // SENDER's initial window size
        int initial_window_size = 65535;
        int max_frame_size = 16384;
        int max_header_list_size = 8192;
    } conn_settings;
    void apply_settings(const views::settings_type::setting_type& setting) {
        switch (setting.identifier()) {
        case Settings::SETTINGS_HEADER_TABLE_SIZE: {
            return hpack().encoder_set_header_table_size(setting.value());
        }
        case Settings::SETTINGS_ENABLE_PUSH: {
            return;
        }
        case Settings::SETTINGS_MAX_CONCURRENT_STREAMS: {
            return;
        }
        case Settings::SETTINGS_INITIAL_WINDOW_SIZE: {
            if (std::uint32_t v = setting.value(); v <= 0x7fffffff) {
                conn_settings.initial_window_size = v;
                return;
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FLOW_CONTROL_ERROR));
            }
        }
        case Settings::SETTINGS_MAX_FRAME_SIZE: {
            if (std::uint32_t v = setting.value();
                v >= 16384 && v <= 16777215) {
                conn_settings.max_frame_size = v;
                return;
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case Settings::SETTINGS_MAX_HEADER_LIST_SIZE: {
            conn_settings.max_header_list_size = setting.value();
        }
        default: {
            return;
        }
        }
    }
    struct {
        std::chrono::milliseconds ack_timeout = {};
    } settings_frame_detail = {};
    struct {
        // now chxhttp doesn't have a deadline for PING sent
        std::set<std::vector<unsigned char>> opaque_data;
    } ping_frame_detail;

    // net::cancellation_signal watchdog_cncl;
    std::chrono::milliseconds watchdog_interval =
        std::chrono::milliseconds(1000);
    std::chrono::time_point<std::chrono::system_clock>
        watchdog_settings_ack_deadline = {};
    void do_watchdog() {
        assert(watchdog_interval.count() != 0);
        __M_fixed_timer.async_register(
            watchdog_interval, cntl().template next_with_tag<ev_watchdog>());
    }

    constexpr bool
    client_new_strm_id_must_be_valid(stream_id_type id) noexcept(true) {
        if (id % 2 == 0) {
            return false;
        }
        if (client_largest_id >= id) {
            return false;
        } else {
            client_largest_id = id;
            return true;
        }
    }

    enum Status { __Start, __FrameHeader } __pstatus = __Start;

    unsigned char frame_header_buf[9] = {};
    int frame_header_buf_sz = 0;
    void frame_header_parse() {
        frame_parse.length = detail::from_network4(frame_header_buf, 3);
        frame_parse.type = frame_header_buf[3];
        frame_parse.flags = frame_header_buf[4];
        frame_parse.stream_id = detail::from_network4(frame_header_buf + 5);
    }

    void feed2(const unsigned char* ptr, const unsigned char* end) {
        // std::size_t s = __M_inbuf.size();
        // const unsigned char *ptr = __M_inbuf.data() + begin, *end = ptr +
        // s;
        while (ptr < end && io_cntl.want_recv()) {
            switch (__pstatus) {
            case __Start: {
                if (end - ptr >= 9 - frame_header_buf_sz) {
                    std::copy_n(ptr, 9 - frame_header_buf_sz,
                                frame_header_buf + frame_header_buf_sz);
                    ptr += 9 - frame_header_buf_sz;
                    frame_header_buf_sz = 0;
                    frame_header_parse();
                    __pstatus = __FrameHeader;
                    // check header...
                    frame_check_before_payload(frame_parse);
                    // reserve
                    if (frame_parse.length != 0) {
                        if (frame_parse.type == FrameType::DATA) {
                            auto ite = __M_strms.find(frame_parse.stream_id);
                            if (ite != __M_strms.end() &&
                                !session().ignore_DATA_frame(ite->second)) {
                                frame_parse.payload.reserve(frame_parse.length);
                            }
                        } else {
                            frame_parse.payload.reserve(frame_parse.length);
                        }
                    } else {
                        // process frame...
                        process_frame();
                        frame_parse.clear();
                        __pstatus = __Start;
                    }
                    break;
                } else {
                    frame_header_buf_sz += end - ptr;
                    std::copy(ptr, end, frame_header_buf + frame_header_buf_sz);
                    break;
                }
            }
            case __FrameHeader: {
                if (end - ptr >=
                    frame_parse.length - frame_parse.payload_length) {
                    std::size_t old = frame_parse.payload_length;
                    frame_parse.payload_length = frame_parse.length;
                    if (frame_parse.type == FrameType::DATA) {
                        if (auto ite = __M_strms.find(frame_parse.stream_id);
                            ite != __M_strms.end() &&
                            !session().ignore_DATA_frame(ite->second)) {
                            assert(old == frame_parse.payload.size());
                            frame_parse.payload.resize(frame_parse.length);
                            std::copy_n(ptr, frame_parse.length - old,
                                        frame_parse.payload.begin() + old);
                        }
                    } else {
                        assert(old == frame_parse.payload.size());
                        frame_parse.payload.resize(frame_parse.length);
                        std::copy_n(ptr, frame_parse.length - old,
                                    frame_parse.payload.begin() + old);
                    }
                    ptr += frame_parse.length - old;
                    // process frame...
                    process_frame();
                    frame_parse.clear();
                    __pstatus = __Start;
                    break;
                } else {
                    std::size_t old = frame_parse.payload_length;
                    frame_parse.payload_length += (end - ptr);
                    if (frame_parse.type == FrameType::DATA) {
                        if (auto ite = __M_strms.find(frame_parse.stream_id);
                            ite != __M_strms.end() &&
                            !session().ignore_DATA_frame(ite->second)) {
                            assert(old == frame_parse.payload.size());
                            frame_parse.payload.resize(
                                frame_parse.payload.size() + (end - ptr));
                            std::copy(ptr, end,
                                      frame_parse.payload.begin() + old);
                        }
                    } else {
                        assert(old == frame_parse.payload.size());
                        frame_parse.payload.resize(frame_parse.payload.size() +
                                                   (end - ptr));
                        std::copy(ptr, end, frame_parse.payload.begin() + old);
                    }
                    ptr = end;
                    break;
                }
            }
            }
        }
        do_read();
        do_send();
    }

    void terminate_now(const std::error_code& ec) {
        terminate_now(static_cast<ErrorCodes>(ec.value()));
    }
    void terminate_now(ErrorCodes ec) {
        // shutdown recv, so that no more frames will be consumed
        io_cntl.shutdown_recv();
        create_GOAWAY_frame(ec);
        do_send();
    }
    void terminate_now() {
        // just terminate right now
        io_cntl.shutdown_both();
        cancel_all();
    }

    void process_frame() {
        if (frame_parse.type == FrameType::DATA) {
            if (auto ite = __M_strms.find(frame_parse.stream_id);
                ite != __M_strms.end() &&
                !session().ignore_DATA_frame(ite->second)) {
                assert(frame_parse.payload_length ==
                       frame_parse.payload.size());
            }
        } else {
            assert(frame_parse.payload_length == frame_parse.payload.size());
        }
        if (!can_read()) [[unlikely]] {
            return;
        }
        if (frame_parse.length != frame_parse.payload.size()) {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        switch (frame_parse.type) {
        case FrameType::CONTINUATION: {
            return process_CONTINUATION();
        }
        case FrameType::DATA: {
            return process_DATA();
        }
        case FrameType::HEADERS: {
            return process_HEADER();
        }
        case FrameType::PRIORITY: {
            return process_PRIORITY();
        }
        case FrameType::RST_STREAM: {
            return process_RST_STREAM();
        }
        case FrameType::SETTINGS: {
            return process_SETTINGS();
        }
        case FrameType::PING: {
            return process_PING();
        }
        case FrameType::GOAWAY: {
            return process_GOAWAY();
        }
        case FrameType::WINDOW_UPDATE: {
            return process_WINDOW_UPDATE();
        }
        default: {
            return;
        }
        }
    }

    void process_CONTINUATION() {
        if (headers_frame_header_check(frame_parse) != ErrorCodes::NO_ERROR) {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        auto ite = __M_strms.find(frame_parse.stream_id);
        if (ite == __M_strms.end()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        h2_stream& strm = ite->second;
        if (strm.field_blocks.empty()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        if (frame_parse.flags & Flags::END_HEADERS) {
            fields_type fields;
            for (std::size_t i = 0; i < strm.field_blocks.size(); ++i) {
                auto [pos, len] =
                    headers_frame_get_payload(strm.field_blocks[i]);
                hpack().decode_block(strm.field_blocks[i].payload.data() + pos,
                                     len, false, fields);
            }
            auto [pos, len] = headers_frame_get_payload(frame_parse);
            hpack().decode_block(frame_parse.payload.data() + pos, len, true,
                                 fields);
            // on(*this,
            //    views::headers_type(std::move(frame_parse),
            //    std::move(fields)));
        } else {
            strm.field_blocks.emplace_back(std::move(frame_parse));
            return;
        }
        // lifecycle, but continuation only has END_HEADERS flag
    }
    void process_DATA() {
        // padding check
        if ((frame_parse.flags & Flags::PADDED) &&
            (frame_parse.payload[0] + 1 > frame_parse.payload.size()))
            [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        auto ite = __M_strms.find(frame_parse.stream_id);
        if (ite == __M_strms.end()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        h2_stream& strm = ite->second;
        // lifecycle
        if (frame_parse.flags & Flags::END_STREAM) {
            switch (strm.state) {
            case StreamStates::Open: {
                strm.state = StreamStates::HalfClosedRemote;
                break;
            }
            case StreamStates::HalfClosedRemote: {
                // strm.state = StreamStates::Closed;
                __M_strms.erase(ite);
                break;
            }
            default: {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
            }
            }
        }
        // invoke
        on(*this, ite->first, strm.userdata(),
           views::data_type(std::move(frame_parse)));
        return;
    }
    void process_HEADER() {
        if (headers_frame_header_check(frame_parse) != ErrorCodes::NO_ERROR)
            [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        if ((frame_parse.flags & Flags::END_STREAM) &&
            !(frame_parse.flags & Flags::END_HEADERS)) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        auto ite = __M_strms.find(frame_parse.stream_id);
        // idle -> open
        if (ite == __M_strms.end()) {
            h2_stream& strm =
                __M_strms.emplace(frame_parse.stream_id, h2_stream{})
                    .first->second;
            strm.client_window = conn_settings.initial_window_size;
            strm.server_window = conn_settings.initial_window_size;
            if (!(frame_parse.flags & Flags::END_STREAM)) {
                strm.state = StreamStates::Open;
            } else {
                strm.state = StreamStates::HalfClosedRemote;
            }
            if (frame_parse.flags & Flags::END_HEADERS) {
                // decode and invoke header
                fields_type fields;
                auto [pos, len] = headers_frame_get_payload(frame_parse);
                hpack().decode(frame_parse.payload.data() + pos, len, fields);
                on(*this, frame_parse.stream_id, strm.userdata(),
                   views::headers_type(std::move(frame_parse),
                                       std::move(fields)));
            } else {
                strm.field_blocks.emplace_back(std::move(frame_parse));
            }
        } else {
            h2_stream& strm = ite->second;
            // es only
            if (frame_parse.flags & Flags::END_STREAM) {
                if (!(frame_parse.flags & Flags::END_HEADERS)) {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
                switch (strm.state) {
                case StreamStates::Open: {
                    strm.state = StreamStates::HalfClosedRemote;
                    break;
                }
                case StreamStates::HalfClosedRemote: {
                    assert(frame_parse.flags & Flags::END_HEADERS);
                    __M_strms.erase(ite);
                    break;
                }
                default: {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
                }
                }
            }
            if (frame_parse.flags & Flags::END_HEADERS) {
                // invoke header
                fields_type fields;
                auto [pos, len] = headers_frame_get_payload(frame_parse);
                hpack().decode(frame_parse.payload.data() + pos, len, fields);
                on(*this, ite->first, strm.userdata(),
                   views::headers_type(std::move(frame_parse),
                                       std::move(fields)));
            } else {
                strm.field_blocks.emplace_back(std::move(frame_parse));
            }
        }
        return;
    }
    void process_PRIORITY() { return; }
    void process_RST_STREAM() {
        if (auto ite = __M_strms.find(frame_parse.stream_id);
            ite != __M_strms.end()) {
            // invoke
            on(*this, ite->first,
               views::rst_stream_type(std::move(frame_parse)));
            __M_strms.erase(ite);
        }
        return;
    }
    void process_SETTINGS() {
        if (frame_parse.flags & frame_parse.ACK) {
            if (watchdog_settings_ack_deadline.time_since_epoch().count() !=
                0) {
                watchdog_settings_ack_deadline = {};
                return;
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }

        create_SETTINGS_ACK_frame();
        // invoke
        views::settings_type sv(std::move(frame_parse));
        for (const auto& st : sv) {
            apply_settings(st);
        }
        on(*this, std::move(sv));
        return;
    }
    void process_PING() {
        // ack
        create_PING_ACK_frame(std::move(frame_parse.payload));
        on(*this, views::ping_type(std::move(frame_parse)));
    }
    void process_GOAWAY() {
        /* rfc9113: Once the GOAWAY is sent, the sender will ignore frames
        sent on streams INITIATED by the RECEIVER if the stream has an
        identifier higher than the included last stream identifier.
        ie, client stops sending frames -> shutdown_recv
        */
        io_cntl.shutdown_recv();
        create_GOAWAY_frame(ErrorCodes::NO_ERROR);
        // invoke
        on(*this, views::goaway_type(std::move(frame_parse)));
        return;
    }
    void process_WINDOW_UPDATE() {
        views::window_update_type view(std::move(frame_parse));
        int inc = view.window_size_increment();
        if (inc <= 0) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        if (view.stream_id == 0) {
            safe_window_inc(server_conn_window, inc);
            for (auto ite = __M_strms_seek_for_window.begin();
                 server_conn_window &&
                 ite != __M_strms_seek_for_window.end();) {
                if (auto strm_ite = __M_strms.find(*(ite++));
                    strm_ite != __M_strms.end()) {
                    create_DATA_flush(strm_ite);
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
                }
            }
        } else {
            auto ite = __M_strms.find(view.stream_id);
            if (ite != __M_strms.end()) {
                safe_window_inc(ite->second.server_window, inc);
                create_DATA_flush(ite);
            }
        }
        // invoke
        on(*this, std::move(view));
        return;
    }

    constexpr bool
    frame_check_before_payload_must_be_CONTINUATION(const h2_stream& strm) {
        return !strm.field_blocks.empty();
    }
    constexpr bool frame_check_before_payload_no_prev(const h2_stream& strm) {
        return strm.field_blocks.empty();
    }
    void frame_check_before_payload(const http::h2::frame_type& frame) {
        if (frame.length > conn_settings.max_frame_size) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FRAME_SIZE_ERROR));
        }
        /*
        #1 check previous frame type (END_HEADERS) and check stream state
        #2 check length of frame, flow-control, and some fixed value
        */
        switch (frame.type) {
        case FrameType::CONTINUATION: {
            if (auto ite = __M_strms.find(frame.stream_id);
                ite != __M_strms.end()) {
                h2_stream& strm = ite->second;
                // check strm state
                if (!strm.template state_any_of<
                        StreamStates::ReservedLocal, StreamStates::Open,
                        StreamStates::HalfClosedRemote>()) [[unlikely]] {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
                // check prev frame
                if (frame_check_before_payload_must_be_CONTINUATION(strm)) {
                    return;
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case FrameType::DATA: {
            if ((frame.flags & Flags::PADDED) && frame.length < 1)
                [[unlikely]] {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
            // DATA frames can only be sent when a stream is in the "open"
            // or "half-closed (remote)" state.
            if (auto ite = __M_strms.find(frame.stream_id);
                ite != __M_strms.end()) {
                h2_stream& strm = ite->second;
                // check window, and calculate
                if (frame.length > client_conn_window ||
                    frame.length > strm.client_window) [[unlikely]] {
                    __CHXHTTP_H2RT_THROW(
                        make_ec(ErrorCodes::FLOW_CONTROL_ERROR));
                } else {
                    client_conn_window -= frame.length;
                    strm.client_window -= frame.length;
                }
                // check prev frame
                if (!frame_check_before_payload_no_prev(strm)) [[unlikely]] {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
                // check strm state
                if (strm.template state_any_of<
                        StreamStates::Open, StreamStates::HalfClosedRemote>()) {
                    return;
                } else [[unlikely]] {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case FrameType::HEADERS: {
            if (frame.length < headers_frame_field_block_offset(frame)) {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
            // HEADERS frames can be sent on a stream in the "idle",
            // "reserved (local)", "open", or "half-closed (remote)" state.
            if (auto ite = __M_strms.find(frame.stream_id);
                ite != __M_strms.end()) {
                // non-idle
                h2_stream& strm = ite->second;
                // check prev frame
                if (!frame_check_before_payload_no_prev(strm)) [[unlikely]] {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
                // check strm state
                if (strm.template state_any_of<
                        StreamStates::ReservedLocal, StreamStates::Open,
                        StreamStates::HalfClosedRemote>()) {
                    return;
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
            } else {
                // idle
                if (client_new_strm_id_must_be_valid(frame.stream_id)) {
                    return;
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
            }
        }
        case FrameType::PRIORITY: {
            return;
        }
        case FrameType::RST_STREAM: {
            if (frame.stream_id == 0 || frame.stream_id > client_largest_id)
                [[unlikely]] {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
            if (frame.length != 0x04) [[unlikely]] {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FRAME_SIZE_ERROR));
            }
            if (auto ite = __M_strms.find(frame.stream_id);
                ite != __M_strms.end()) {
                if (frame_check_before_payload_no_prev(ite->second)) {
                    return;
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
                }
            } else {
                return;
            }
        }
        case FrameType::SETTINGS: {
            if (frame.stream_id == 0) {
                if (frame.flags & Flags::ACK) {
                    if (frame.length == 0) {
                        return;
                    } else {
                        __CHXHTTP_H2RT_THROW(
                            make_ec(ErrorCodes::PROTOCOL_ERROR));
                    }
                } else {
                    return;
                }
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case FrameType::PUSH_PROMISE: {
            // actually chxhttp should never recv PP
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        case FrameType::PING: {
            if (frame.stream_id == 0) {
                if (frame.length == 0x08) {
                    return;
                } else {
                    __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FRAME_SIZE_ERROR));
                }
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case FrameType::GOAWAY: {
            if (frame.stream_id == 0 && frame.length >= 8) {
                return;
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
            }
        }
        case FrameType::WINDOW_UPDATE: {
            if (frame.length == 0x04) {
                if (frame.stream_id == 0) {
                    return;
                }
                if (auto ite = __M_strms.find(frame.stream_id);
                    ite != __M_strms.end()) {
                    if (frame_check_before_payload_no_prev(ite->second)) {
                        return;
                    } else {
                        __CHXHTTP_H2RT_THROW(
                            make_ec(ErrorCodes::PROTOCOL_ERROR));
                    }
                } else {
                    /**
                      rfc9113: This means that a receiver could receive a
                      WINDOW_UPDATE frame on a stream in a "half-closed
                      (remote)" or "closed" state.
                     */
                    if (frame.stream_id <= client_largest_id) {
                        return;
                    } else {
                        __CHXHTTP_H2RT_THROW(
                            make_ec(ErrorCodes::PROTOCOL_ERROR));
                    }
                }
            } else {
                __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FRAME_SIZE_ERROR));
            }
        }
        default: {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
        }
        }
    }

    std::vector<pending_frame_type> pending_frames;
    template <typename... Ts>
    constexpr void
    pending_frames_emplace_back(std::array<unsigned char, 9>&& header,
                                Ts&&... ts) {
        assert(!io_cntl.goaway_sent());
        __pending_frame_type_emplace_back(pending_frames, std::move(header),
                                          std::forward<Ts>(ts)...);
    }

    [[nodiscard]] std::vector<net::iovec_buffer>
    iovec_generator(std::vector<net::iovec_buffer>& iov, std::size_t s,
                    std::size_t* n = nullptr) {
        std::vector<net::iovec_buffer> _r;
        std::size_t cur = 0;
        while (cur < s && !iov.empty()) {
            // assert(!iov.empty());
            const std::size_t remain = s - cur;
            if (iov.front().iov_len <= remain) {
                cur += iov.front().iov_len;
                _r.push_back(std::move(iov.front()));
                iov.erase(iov.begin());
            } else {
                cur += remain;
                // if iov_len > remain, it must be the last (?)
                assert(cur == s);
                net::iovec_buffer a = iov.front(), &b = iov.front();
                a.iov_len = remain;
                b.iov_base = (unsigned char*)b.iov_base + remain;
                b.iov_len -= remain;
                _r.push_back(std::move(a));
            }
        }
        if (n) {
            *n = cur;
        }
        return std::move(_r);
    }

    constexpr std::array<unsigned char, 9>
    create_frame_header_helper(FrameType ft, std::size_t len, flags_type flags,
                               stream_id_type strm_id) noexcept(true) {
        std::array<unsigned char, 9> _r;
        _r[0] = len >> 16;
        _r[1] = len >> 8;
        _r[2] = len;

        _r[3] = static_cast<unsigned char>(ft);
        _r[4] = flags;

        _r[5] = strm_id >> 24;
        _r[6] = strm_id >> 16;
        _r[7] = strm_id >> 8;
        _r[8] = strm_id;
        return _r;
    }

    static constexpr flags_type get_flags_from_array(
        const std::array<unsigned char, 9>& header) noexcept(true) {
        return header[4];
    }
    static constexpr void
    set_flags_to_array(std::array<unsigned char, 9>& header,
                       flags_type f) noexcept(true) {
        header[4] = f;
    }

    void send_ES_lifecycle(decltype(__M_strms)::iterator pos) {
        h2_stream& strm = pos->second;
        switch (strm.state) {
        case StreamStates::Open: {
            strm.state = StreamStates::HalfClosedLocal;
            break;
        }
        case StreamStates::HalfClosedRemote: {
            __M_strms.erase(pos);
            break;
        }
        default: {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::PROTOCOL_ERROR));
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

    template <typename... Ts> void h2_shutdown_recv(ErrorCodes ec, Ts&&... ts) {
        create_GOAWAY_frame(ec, std::forward<Ts>(ts)...);
        do_send();
    }

    void create_HEADER_frame(flags_type flags, stream_id_type strm_id,
                             const fields_type& fields) {
        std::vector<unsigned char> payload;
        hpack().encode(fields, payload);

        // send frame
        auto ite = __M_strms.find(strm_id);
        if (ite == __M_strms.end()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        h2_stream& strm = ite->second;
        if (!strm.template state_any_of<StreamStates::Open,
                                        StreamStates::HalfClosedRemote>())
            [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        if (payload.size() <= conn_settings.max_frame_size) {
            pending_frames_emplace_back(
                create_frame_header_helper(FrameType::HEADERS, payload.size(),
                                           flags | frame_type::END_HEADERS,
                                           strm_id),
                std::move(payload));
        } else {
            auto store = payload_store::create(std::move(payload));
            std::vector<net::iovec_buffer> iovec =
                http::detail::create_iovec_vector(store->data);
            std::vector<net::iovec_buffer> section =
                iovec_generator(iovec, conn_settings.max_frame_size);
            pending_frames_emplace_back(
                create_frame_header_helper(
                    FrameType::HEADERS, conn_settings.max_frame_size,
                    flags & (~frame_type::END_HEADERS), strm_id),
                payload_rep{}, std::move(section));
            assert(!iovec.empty());
            while (!iovec.empty()) {
                std::size_t n = 0;
                section =
                    iovec_generator(iovec, conn_settings.max_frame_size, &n);
                pending_frames_emplace_back(
                    create_frame_header_helper(
                        FrameType::CONTINUATION, n,
                        flags & (~frame_type::END_HEADERS), strm_id),
                    payload_rep{}, std::move(section));
            }
            set_flags_to_array(std::get<0>(pending_frames.back()),
                               flags | frame_type::END_HEADERS);
            std::get<0>(std::get<0>(std::get<1>(pending_frames.back())))
                .payload.reset(store.release());
        }
        if (flags & frame_type::END_STREAM) {
            send_ES_lifecycle(ite);
        }
        do_send();
    }

    template <typename... Ts>
    void create_DATA_frame(flags_type flags, stream_id_type strm_id,
                           Ts&&... ts) {
        auto ite = __M_strms.find(strm_id);
        if (ite == __M_strms.end()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        h2_stream& strm = ite->second;
        if (strm.state != StreamStates::Open &&
            strm.state != StreamStates::HalfClosedRemote) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        std::size_t total_size = 0;
        if constexpr (sizeof...(Ts)) {
            total_size = (... + buffer(ts).size());
        }
        if (total_size != 0) {
            int min_window = std::min(server_conn_window, strm.server_window);
            if (total_size <= min_window) {
                server_conn_window -= total_size;
                strm.server_window -= total_size;
                if (total_size <= conn_settings.max_frame_size) {
                    auto store = payload_store::create(std::forward<Ts>(ts)...);
                    auto iovec = http::detail::create_iovec_vector(store->data);
                    auto header_arr = create_frame_header_helper(
                        FrameType::DATA, total_size, flags, strm_id);
                    pending_frames_emplace_back(std::move(header_arr),
                                                payload_rep{std::move(store)},
                                                std::move(iovec));
                } else {
                    auto store = payload_store::create(std::forward<Ts>(ts)...);
                    std::vector<net::iovec_buffer> iovec =
                        http::detail::create_iovec_vector(store->data);
                    while (!iovec.empty()) {
                        std::size_t n = 0;
                        std::vector<net::iovec_buffer> section =
                            iovec_generator(iovec, conn_settings.max_frame_size,
                                            &n);

                        auto header = create_frame_header_helper(
                            FrameType::DATA, n,
                            flags & (~frame_type::END_STREAM), strm_id);
                        pending_frames_emplace_back(std::move(header),
                                                    payload_rep{},
                                                    std::move(section));
                    }
                    assert(!pending_frames.empty());
                    std::get<0>(std::get<0>(std::get<1>(pending_frames.back())))
                        .payload.reset(store.release());
                    set_flags_to_array(std::get<0>(pending_frames.back()),
                                       flags);
                }
                if (flags & frame_type::END_STREAM) {
                    send_ES_lifecycle(ite);
                }
            } else {
                // total_size > min_window
                assert(min_window >= 0);
                auto store = payload_store::create(std::forward<Ts>(ts)...);
                auto iovec = http::detail::create_iovec_vector(store->data);
                __M_strms_seek_for_window.insert(strm_id);
                if (min_window <= conn_settings.max_frame_size) {
                    server_conn_window -= min_window;
                    strm.server_window -= min_window;
                    std::vector<net::iovec_buffer> inwnd =
                        iovec_generator(iovec, min_window);
                    pending_frames_emplace_back(
                        create_frame_header_helper(
                            FrameType::DATA, min_window,
                            flags & (~frame_type::END_STREAM), strm_id),
                        payload_rep{}, std::move(inwnd));
                    strm.pending_DATA_frames_emplace_back(
                        create_frame_header_helper(FrameType::DATA,
                                                   total_size - min_window,
                                                   flags, strm_id),
                        std::move(store), std::move(iovec));
                } else {
                    // window > max frame size
                    server_conn_window -= min_window;
                    strm.server_window -= min_window;
                    std::vector<net::iovec_buffer> inwnd =
                        iovec_generator(iovec, min_window);
                    while (!inwnd.empty()) {
                        std::size_t n = 0;
                        std::vector<net::iovec_buffer> section =
                            iovec_generator(inwnd, conn_settings.max_frame_size,
                                            &n);
                        pending_frames_emplace_back(
                            create_frame_header_helper(
                                FrameType::DATA, n,
                                flags & (~frame_type::END_STREAM), strm_id),
                            payload_rep{}, std::move(section));
                    }
                    assert(!iovec.empty());
                    strm.pending_DATA_frames_emplace_back(
                        create_frame_header_helper(FrameType::DATA,
                                                   total_size - min_window,
                                                   flags, strm_id),
                        std::move(store), std::move(iovec));
                }
            }
        } else {
            pending_frames_emplace_back(
                create_frame_header_helper(FrameType::DATA, 0, flags, strm_id));
        }
        do_send();
    }

    void create_RST_STREAM_frame(stream_id_type strm_id, ErrorCodes ec) {
        if (auto ite = __M_strms.find(strm_id); ite != __M_strms.end()) {
            std::vector<unsigned char> payload(4);
            detail::to_network4(static_cast<std::uint32_t>(ec), payload.data());
            pending_frames_emplace_back(
                create_frame_header_helper(FrameType::RST_STREAM, 4, 0,
                                           strm_id),
                std::move(payload));
            __M_strms.erase(ite);
        }
        do_send();
    }

    void create_SETTINGS_frame(
        const std::vector<views::settings_type::setting_type>& settings) {
        if (watchdog_settings_ack_deadline.time_since_epoch().count() != 0)
            [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(INTERNAL_ERROR));
        }
        static_assert(sizeof(views::settings_type::setting_type) == 6);
        std::vector<unsigned char> payload(
            (const unsigned char*)settings.data(),
            (const unsigned char*)settings.data() + settings.size() * 6);
        for (const auto& setting : settings) {
            apply_settings(setting);
        }
        pending_frames_emplace_back(
            create_frame_header_helper(FrameType::SETTINGS, settings.size() * 6,
                                       0, 0),
            std::move(payload));
        watchdog_settings_ack_deadline = std::chrono::system_clock::now() +
                                         settings_frame_detail.ack_timeout;
        do_send();
    }
    void create_SETTINGS_ACK_frame() {
        pending_frames_emplace_back(create_frame_header_helper(
            FrameType::SETTINGS, 0, frame_type::ACK, 0));
        do_send();
    }

    void create_PING_frame(std::vector<unsigned char> data) {
        auto [ite, b] = ping_frame_detail.opaque_data.emplace(data);
        if (!b) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        pending_frames_emplace_back(
            create_frame_header_helper(FrameType::PING, 8, 0, 0),
            std::move(data));
        do_send();
    }
    void create_PING_ACK_frame(std::vector<unsigned char>&& data) {
        pending_frames_emplace_back(
            create_frame_header_helper(FrameType::PING, 8, frame_type::ACK, 0),
            std::move(data));
        do_send();
    }

    // chxhttp always tries to make sure window size is fixed
    void create_WINDOW_UPDATE_frame(stream_id_type strm_id, int inc) {
        if (inc <= 0) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        auto ite = __M_strms.find(strm_id);
        if (ite == __M_strms.end()) [[unlikely]] {
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::INTERNAL_ERROR));
        }
        h2_stream& strm = ite->second;
        if (strm.client_window + inc < std::max(strm.client_window, inc) ||
            client_conn_window + inc < std::max(client_conn_window, inc)) {
            inc = 0x7fffffff - std::max(client_conn_window, strm.client_window);
        }
        std::vector<unsigned char> payload(4);
        detail::to_network4(inc, payload.data());
        pending_frames_emplace_back(
            create_frame_header_helper(FrameType::WINDOW_UPDATE, 4, 0, strm_id),
            std::move(payload));
        client_conn_window += inc;
        strm.client_window += inc;
        do_send();
    }

  private:
    // GOAWAY means shutdown_both for chxhttp, and for now
    template <typename... Ts>
    void create_GOAWAY_frame(ErrorCodes e,
                             Ts&&... additional_data) noexcept(true) {
        io_cntl.shutdown_recv();
        if constexpr (sizeof...(Ts) != 0) {
            struct goaway_impl {
                using value_type = unsigned char;
                // last stream id eq 0: chxhttp won't send any data if client is
                // misbehaving.
                std::uint32_t stream_id = 0, error_code = 0;

                const unsigned char* data() const noexcept(true) {
                    return (const unsigned char*)this;
                }
                constexpr std::size_t size() const noexcept(true) { return 8; }
            } st;
            static_assert(sizeof(goaway_impl) == 8);
            st.error_code = htonl(e);

            std::size_t frame_length =
                8 + (... + net::buffer(additional_data).size());
            assert(frame_length <= conn_settings.max_frame_size);

            pending_frames_emplace_back(
                create_frame_header_helper(FrameType::GOAWAY, frame_length, 0,
                                           0),
                payload_store::create(st,
                                      std::forward<Ts>(additional_data)...));
        } else {
            std::vector<unsigned char> payload(8);
            detail::to_network4(static_cast<std::uint32_t>(e),
                                payload.data() + 4);
            pending_frames_emplace_back(
                create_frame_header_helper(FrameType::GOAWAY, 8, 0, 0),
                std::move(payload));
        }
        io_cntl.send_goaway();
        do_send();
    }

    void create_DATA_flush(decltype(__M_strms)::iterator strm_ite) {
        stream_id_type strm_id = strm_ite->first;
        h2_stream& strm = strm_ite->second;
        auto ite = strm.pending_DATA_frames.begin();
        for (int wnd = std::min(strm.server_window, server_conn_window);
             ite != strm.pending_DATA_frames.end() && wnd;
             ++ite, wnd = std::min(strm.server_window, server_conn_window)) {
            auto& [header, va] = *ite;
            static_assert(std::is_same_v<std::decay_t<decltype(header)>,
                                         std::array<unsigned char, 9>>);
            flags_type flags = get_flags_from_array(header);
            assert(va.index() == 0);
            auto& [rep, iov] = std::get<0>(va);
            std::size_t len = std::accumulate(
                iov.begin(), iov.end(), std::size_t{},
                [](std::size_t s, const net::iovec_buffer& buf) {
                    return s + buf.size();
                });
            if (len <= wnd) {
                strm.server_window -= len;
                server_conn_window -= len;
                if (len <= conn_settings.max_frame_size) {
                    pending_frames_emplace_back(std::move(header),
                                                std::move(rep), std::move(iov));
                } else {
                    while (!iov.empty()) {
                        std::size_t n = 0;
                        std::vector<net::iovec_buffer> ciov = iovec_generator(
                            iov, conn_settings.max_frame_size, &n);
                        pending_frames_emplace_back(
                            create_frame_header_helper(
                                FrameType::DATA, n,
                                flags & (~frame_type::END_STREAM), strm_id),
                            payload_rep{}, std::move(ciov));
                    }
                    std::get<0>(std::get<0>(
                        std::get<1>(pending_frames.back()))) = std::move(rep);
                    set_flags_to_array(std::get<0>(pending_frames.back()),
                                       flags);
                }
                if (flags & frame_type::END_STREAM) {
                    strm.pending_DATA_frames.clear();
                    send_ES_lifecycle(strm_ite);
                    do_send();
                    return;
                }
            } else {
                strm.server_window -= wnd;
                server_conn_window -= wnd;
                if (wnd <= conn_settings.max_frame_size) {
                    std::size_t n = 0;
                    std::vector<net::iovec_buffer> ciov =
                        iovec_generator(iov, wnd, &n);
                    assert(n == wnd);
                    pending_frames_emplace_back(
                        create_frame_header_helper(
                            FrameType::DATA, wnd,
                            flags & (~frame_type::END_STREAM), strm_id),
                        payload_rep{}, std::move(ciov));
                } else {
                    std::size_t bytes_sent = 0;
                    while (bytes_sent < wnd) {
                        std::size_t n = 0;
                        std::vector<net::iovec_buffer> ciov = iovec_generator(
                            iov,
                            std::min(static_cast<std::size_t>(
                                         conn_settings.max_frame_size),
                                     wnd - bytes_sent),
                            &n);
                        bytes_sent += n;
                        pending_frames_emplace_back(
                            create_frame_header_helper(
                                FrameType::DATA, n,
                                flags & (~frame_type::END_STREAM), strm_id),
                            payload_rep{}, std::move(ciov));
                    }
                    assert(bytes_sent == wnd);
                }
                detail::to_network4(len - wnd, header.data(), 3);
            }
        }
        if (ite != strm.pending_DATA_frames.end()) {
            strm.pending_DATA_frames.erase(strm.pending_DATA_frames.begin(),
                                           ite);
        } else {
            __M_strms_seek_for_window.erase(strm_ite->first);
        }
        do_send();
    }

    constexpr static std::size_t
    headers_frame_field_block_offset(const frame_type& frame) noexcept(true) {
        return (frame.flags & frame.PADDED) +
               ((frame.flags & frame.PRIORITY) ? 5 : 0);
    }
    constexpr static ErrorCodes
    headers_frame_header_check(const frame_type& frame) noexcept(true) {
        if (frame.flags & frame.PADDED) {
            const std::size_t padded_length = frame.payload[0];
            return (frame.length >
                    ((frame.flags & frame.PRIORITY) ? 6 : 1) + padded_length)
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        } else {
            return (frame.length > ((frame.flags & frame.PRIORITY) ? 5 : 0))
                       ? ErrorCodes::NO_ERROR
                       : ErrorCodes::PROTOCOL_ERROR;
        }
    }
    constexpr static std::pair<std::size_t, std::size_t>
    headers_frame_get_payload(const frame_type& frame) noexcept(true) {
        if (frame.flags & frame.PADDED) {
            const std::size_t padded_length = frame.payload[0];
            return {(frame.flags & frame.PRIORITY) ? 6 : 1,
                    frame.length - padded_length -
                        ((frame.flags & frame.PRIORITY) ? 6 : 1)};
        } else {
            return {(frame.flags & frame.PRIORITY) ? 5 : 0,
                    frame.length - ((frame.flags & frame.PRIORITY) ? 5 : 0)};
        }
    }

    constexpr static void safe_window_inc(int& v, int i) {
        if (v + i >= std::max(v, i)) {
            v += i;
            return;
        } else {
            // ah, no rst. shutdown even for stream
            __CHXHTTP_H2RT_THROW(make_ec(ErrorCodes::FLOW_CONTROL_ERROR));
        }
    }

    struct impl_detail {
        static constexpr char client_connection_preface_cstr[] = {
            'P', 'R', 'I',  ' ',  '*',  ' ',  'H', 'T', 'T',  'P',  '/',  '2',
            '.', '0', '\r', '\n', '\r', '\n', 'S', 'M', '\r', '\n', '\r', '\n'};
    };

    // can server listen and recv right now
    constexpr bool can_read() noexcept(true) {
        return io_cntl.want_recv() && !io_cntl.is_recving();
    }
    // can server send any frame immediately
    bool can_send() noexcept(true) {
        return io_cntl.want_send() && !pending_frames.empty() &&
               !io_cntl.is_sending();
    }
};
template <typename Stream, typename Session, typename H, typename FixedTimerRef>
h2_impl(Stream&&, std::unique_ptr<Session>, H&&, FixedTimerRef&)
    -> h2_impl<Stream, Session, std::decay_t<H>, FixedTimerRef>;
template <typename Stream, typename Session, typename H, typename FixedTimerRef>
h2_impl(Stream&, std::unique_ptr<Session>, H&&, FixedTimerRef&)
    -> h2_impl<Stream&, Session, std::decay_t<H>, FixedTimerRef>;
}  // namespace chx::http::h2::detail

namespace chx::http::h2 {
template <typename Stream, typename Session, typename HPack,
          typename FixedTimer, typename CompletionToken>
decltype(auto) async_http2(Stream&& stream, std::unique_ptr<Session> session,
                           HPack&& hpack, FixedTimer&& fixed_timer,
                           CompletionToken&& completion_token) {
    using operation_type = decltype(detail::h2_impl(
        std::forward<Stream>(stream), std::move(session),
        std::forward<HPack>(hpack), std::forward<FixedTimer>(fixed_timer)));
    return net::async_combine_reference_count<const std::error_code&>(
        stream.get_associated_io_context(),
        std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream), std::move(session),
        std::forward<HPack>(hpack), std::forward<FixedTimer>(fixed_timer));
}
}  // namespace chx::http::h2

/*
TODO:
  0. exception instead of ErrorCodes!
  -1. specify types for strm_id and flags.
  -2. use htons for endian.
  3. code review.
*/
