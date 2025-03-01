#pragma once

// a brand new http/2 impl. support http server side semantics ONLY

// any error issued by chxhttp.h2 should be connection error.

#include "./detail/parser.hpp"
#include "./detail/types.hpp"
#include "./error_codes.hpp"
#include "./events.hpp"
#include "../header.hpp"
#include "../detail/payload.hpp"
#include "./detail/stream_states.hpp"
#include "./detail/h2_stream.hpp"
#include "./detail/frame.hpp"
#include "../status_code.hpp"

#include <array>
#include <chrono>
#include <chx/net/detail/tracker.hpp>
#include <chx/net/async_write_sequence_exactly.hpp>
#include <chx/net/detail/remove_rvalue_reference.hpp>
#include <chx/net/basic_fixed_timer.hpp>
#include <variant>
#include <map>

namespace chx::http::h2 {
template <typename SessionFactory> struct connection;
}

namespace chx::http::h2::detail {
template <typename T> struct visitor;

template <typename Stream, typename Connection, typename HPackImpl,
          typename CntlType = int>
struct operation : net::detail::enable_weak_from_this<
                       operation<Stream, Connection, HPackImpl, CntlType>> {
    template <typename T> friend struct visitor;
    template <typename T> friend struct h2::connection;

  private:
    template <typename Event, typename T, typename... Args>
    ErrorCodes on(T&& t, Args&&... args) {
        if constexpr (std::is_invocable_v<T&&, Event, Args&&...>) {
            return std::forward<T>(t)(Event(), std::forward<Args>(args)...);
        } else {
            return ErrorCodes::NO_ERROR;
        }
    }

    using cntl_type = CntlType;
    using session_type = typename Connection::session_type;
    using h2_strm = h2_stream<session_type>;

    struct ev_send {};
    struct ev_send_final {};

    struct ev_read {};

    struct ev_settings_timeout {};
    struct ev_keepalive_timeout {};

    enum Stage {
        LengthStage = 0,
        TypeStage = 1,
        FlagsStage = 2,
        StreamIdStage = 3,
        DataPaddingStage = 4,
        DataBodyStage = 5,
        DataTail = 6,
        HeaderPaddingStage = 7,
        HeaderPriorityStage = 8,
        HeaderBodyStage = 9,
        HeaderTail = 10,
        PriorityStage = 11,
        RstStage = 12,
        SettingsKeyStage = 13,
        SettingsValStage = 14,
        PingStage = 15,
        GoAwayStrmIdStage = 16,
        GoAwayErrorCodeStage = 17,
        GoAwayDebugStage = 18,
        WndUpdateStage = 19,
        ContinuationStage = 20,

        PrefacePRIStage = 21,
        PrefaceLengthStage = 22,
        PrefaceTypeStage = 23,
        PrefaceFlagsStage = 24,
        PrefaceStreamIdStage = 25
    };

  public:
    template <typename T>
    using rebind = operation<Stream, Connection, HPackImpl, T>;

    template <typename Strm, typename Conn, typename H, typename FixedTmr>
    operation(Strm&& strm, Conn&& conn, H&& h, FixedTmr& tmr)
        : __M_stream(std::forward<Strm>(strm)),
          __M_session(std::forward<Conn>(conn)), __M_hpack(std::forward<H>(h)),
          __M_tmr(tmr) {}

    void operator()(cntl_type& cntl) {
        try {
            __M_buf.resize(4096);
            __M_state.template emplace<PrefacePRIStage>();
            __M_stream.lowest_layer().async_read_some(
                net::buffer(__M_buf), cntl.template next_with_tag<ev_read>());
            __M_tmr.async_register(
                std::chrono::seconds(30),
                net::bind_cancellation_signal(
                    keepalive_timeout,
                    cntl.template next_with_tag<ev_keepalive_timeout>()));
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(std::error_code{});
            std::rethrow_exception(std::current_exception());
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_read) {
        try {
            if (!e) {
                if (ErrorCodes r = feed(__M_buf.data(), __M_buf.data() + s);
                    r == ErrorCodes::NO_ERROR && io_cntl.want_recv()) {
                    update_keepalive(std::chrono::seconds(30));
                    __M_stream.lowest_layer().async_read_some(
                        net::buffer(__M_buf),
                        cntl.template next_with_tag<ev_read>());
                    return cntl.complete(e);
                }
            }
            shutdown_recv();
            return complete_with_goaway(e);
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(e);
            std::rethrow_exception(std::current_exception());
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_send) {
        try {
            io_cntl.unset_sending();
            update_keepalive(std::chrono::seconds(30));
            if (!e) {
                if (!io_cntl.goaway_sent()) {
                    do_send();
                } else if (can_send()) {
                    assert(!keepalive_timeout && !io_cntl.want_recv());
                    io_cntl.set_sending();
                    return net::async_write_sequence_exactly(
                        __M_stream.lowest_layer(), std::move(pending_frames),
                        cntl.template next_with_tag<ev_send_final>());
                }
                return complete_with_goaway(e);
            } else {
                terminate_now();
                return cntl.complete(e);
            }
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(e);
            std::rethrow_exception(std::current_exception());
        }
    }
    void operator()(cntl_type& cntl, const std::error_code& e, std::size_t s,
                    ev_send_final) {
        try {
            io_cntl.unset_sending();
            if (!e) {
                complete_with_goaway(e);
            } else {
                terminate_now();
                return cntl.complete(e);
            }
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(e);
            std::rethrow_exception(std::current_exception());
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e,
                    ev_keepalive_timeout) {
        try {
            keepalive_timeout.clear();
            if (!e) {
                shutdown_recv();
            }
            return complete_with_goaway(e);
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(e);
            std::rethrow_exception(std::current_exception());
        }
    }

    void operator()(cntl_type& cntl, const std::error_code& e,
                    ev_settings_timeout) {
        try {
            settings_ack_timeout.clear();
            if (!e) {
                create_GOAWAY_frame(ErrorCodes::SETTINGS_TIMEOUT);
            }
            return complete_with_goaway(e);
        } catch (const std::exception& ex) {
            terminate_now();
            cntl.complete(e);
            std::rethrow_exception(std::current_exception());
        }
    }

  private:
    constexpr cntl_type& cntl() noexcept(true) {
        return static_cast<cntl_type&>(*this);
    }
    void cancel_all() {
        try {
            cntl()(nullptr);
        } catch (const std::exception&) {
            net::rethrow_with_fatal(std::current_exception());
        }
    }
    void complete_with_goaway(const std::error_code& e,
                              ErrorCodes h2_ec = ErrorCodes::NO_ERROR) {
        settings_ack_timeout.emit();
        if (cntl().tracked_task_empty()) {
            create_GOAWAY_frame(h2_ec);
        }
        cntl().complete(e);
    }

    bool can_send() noexcept(true) {
        return io_cntl.want_send() && !pending_frames.empty() &&
               !io_cntl.is_sending();
    }

    void do_send() {
        if (can_send()) {
            io_cntl.set_sending();
            update_keepalive(std::chrono::seconds(0));
            net::async_write_sequence_exactly(
                __M_stream.lowest_layer(), std::move(pending_frames),
                cntl().template next_with_tag<ev_send>());
        }
    }

    Stream __M_stream;
    Connection __M_session;
    HPackImpl __M_hpack;
    net::fixed_timer& __M_tmr;

    net::cancellation_signal settings_ack_timeout;
    net::cancellation_signal keepalive_timeout;

    template <typename Rep, typename Period>
    void update_keepalive(const std::chrono::duration<Rep, Period>& dur) {
        if (keepalive_timeout) {
            auto* cntl = net::safe_fixed_timer_controller(keepalive_timeout);
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

    std::vector<unsigned char> __M_buf;

    using payload_rep = http::detail::payload_storage_wrapper;
    using payload_store = http::detail::payload_storage;
    using payload_monostate = http::detail::payload_monostate;

    using payload_variant =
        std::variant<payload_monostate, std::vector<unsigned char>,
                     std::array<unsigned char, 8>, net::const_buffer,
                     std::array<unsigned char, 4>,
                     //
                     net::offset_carrier<net::const_buffer>,
                     net::offset_carrier<std::string>,
                     net::offset_carrier<std::vector<unsigned char>>,
                     net::carrier<net::mapped_file>,
                     net::offset_carrier<net::vcarrier>>;
    enum __Payload {
        __Payload_Empty = 0,
        __Payload_Vector = 1,
        __Payload_Array8 = 2,
        __Payload_ConstBuffer = 3,
        __Payload_OffsetCarrierVector = 7
    };
    using pending_frame_type =
        std::tuple<std::array<unsigned char, 9>, payload_variant>;
    std::vector<pending_frame_type> pending_frames;

    std::array<unsigned char, 9>
    create_frame_header_helper(FrameType ft, std::size_t len, flags_t flags,
                               stream_id_t strm_id) noexcept(true) {
        std::array<unsigned char, 9> _r;
        std::uint32_t len_network = htonl(len);
        ::memcpy(_r.data(), (unsigned char*)&len_network + 1, 3);

        _r[3] = static_cast<unsigned char>(ft);
        _r[4] = flags;

        std::uint32_t strm_id_network = htonl(strm_id);
        ::memcpy(_r.data() + 5, &strm_id_network, 4);
        return _r;
    }

    struct {
        constexpr bool want_recv() const noexcept(true) { return v & 1; }
        constexpr bool want_send() const noexcept(true) { return v & 2; }
        constexpr bool is_sending() const noexcept(true) { return v & 4; }

        constexpr void set_sending() noexcept(true) { v |= 4; }
        constexpr void unset_sending() noexcept(true) { v &= ~4; }

        constexpr void send_goaway() noexcept(true) { v |= 16; }
        constexpr bool goaway_sent() noexcept(true) { return v & 16; }

        constexpr void shutdown_both() noexcept(true) {
            shutdown_recv();
            shutdown_send();
        }
        constexpr void shutdown_recv() noexcept(true) { v &= ~1; }
        constexpr void shutdown_send() noexcept(true) { v &= ~2; }

      private:
        char v = 1 | 2;
    } io_cntl;

    void shutdown_recv() {
        std::error_code e;
        __M_stream.shutdown(__M_stream.shutdown_receive, e);
        io_cntl.shutdown_recv();
        keepalive_timeout.emit();
        keepalive_timeout.clear();
    }
    void shutdown_send() {
        std::error_code e;
        __M_stream.shutdown(__M_stream.shutdown_write, e);
        io_cntl.shutdown_send();
    }
    void shutdown_both() {
        std::error_code e;
        __M_stream.shutdown(__M_stream.shutdown_both, e);
        io_cntl.shutdown_both();
        keepalive_timeout.emit();
        keepalive_timeout.clear();
    }

    std::variant<length_parser, type_parser, flags_parser, stream_id_parser,
                 // data
                 std::monostate, variable_length_parser, variable_length_parser,
                 // headers
                 std::monostate, fixed_length_parser<5>, variable_length_parser,
                 variable_length_parser,
                 // priority
                 fixed_length_parser<5>,
                 // rst
                 fixed_length_parser<4>,
                 // settings
                 uint16_integer_parser, uint32_integer_parser,
                 // no pp
                 // ping
                 fixed_length_parser<8>,
                 // goaway
                 fixed_length_parser<4>, fixed_length_parser<4>,
                 variable_length_parser,
                 // window update
                 uint32_integer_parser,
                 // continuation
                 variable_length_parser,
                 // preface below
                 fixed_length_parser<24>, length_parser, type_parser,
                 flags_parser, stream_id_parser>
        __M_state;
    std::map<stream_id_t, h2_strm> __M_strms;
    using h2_strm_iterator = typename std::map<stream_id_t, h2_strm>::iterator;

    enum Settings : std::uint16_t {
        SETTINGS_HEADER_TABLE_SIZE = 0x01,
        SETTINGS_ENABLE_PUSH = 0x02,
        SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
        SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
        SETTINGS_MAX_FRAME_SIZE = 0x05,
        SETTINGS_MAX_HEADER_LIST_SIZE = 0x06,

        SETTINGS_NO_RFC7540_PRIORITIES = 0x09
    };
    struct {
        int header_table_size = 4096;
        int enable_push = 1;
        int max_concurrent_streams = 100;
        int initial_window_size = 65535;
        int max_frame_size = 16384;
        int max_header_list_size = 8192;
    } conn_settings{};
    ErrorCodes apply_settings(std::uint16_t key, std::uint32_t val) {
        switch (key) {
        case Settings::SETTINGS_HEADER_TABLE_SIZE: {
            return __M_hpack.encoder_set_header_table_size(val);
        }
        case Settings::SETTINGS_ENABLE_PUSH: {
            return ErrorCodes::NO_ERROR;
        }
        case Settings::SETTINGS_MAX_CONCURRENT_STREAMS: {
            return ErrorCodes::NO_ERROR;
        }
        case Settings::SETTINGS_INITIAL_WINDOW_SIZE: {
            if (std::uint32_t v = val; v <= 0x7fffffff) {
                conn_settings.initial_window_size = v;
                return ErrorCodes::NO_ERROR;
            } else {
                return ErrorCodes::FLOW_CONTROL_ERROR;
            }
        }
        case Settings::SETTINGS_MAX_FRAME_SIZE: {
            if (std::uint32_t v = val; v >= 16384 && v <= 16777215) {
                conn_settings.max_frame_size = v;
                return ErrorCodes::NO_ERROR;
            } else {
                return ErrorCodes::PROTOCOL_ERROR;
            }
        }
        case Settings::SETTINGS_MAX_HEADER_LIST_SIZE: {
            conn_settings.max_header_list_size = val;
            return ErrorCodes::NO_ERROR;
        }
        default: {
            return ErrorCodes::NO_ERROR;
        }
        }
    }

    frame<session_type> current_frame = {};
    ErrorCodes reset_fsm() {
        ErrorCodes r = on<ev::frame_complete>(__M_session, *this,
                                              current_frame.const_self());
        current_frame = {};
        __M_state.template emplace<LengthStage>();
        return r;
    }

    stream_id_t next_header = 0;
    stream_id_t client_max_id = 0;

    std::int32_t client_wnd = 65535;
    std::int32_t server_wnd = 65535;

    ErrorCodes frame_dispatch() {
        if (current_frame.stream_id &&
            current_frame.stream_id >
                std::numeric_limits<std::int32_t>::max()) {
            return ErrorCodes::PROTOCOL_ERROR;
        }
        if (next_header) {
            if (current_frame.type != CONTINUATION) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            auto ite = __M_strms.find(current_frame.stream_id);
            if (ite == __M_strms.end()) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
        }
        switch (current_frame.type) {
        case DATA: {
            /*
            DATA frame requirements:
            0. state==Open✅
            1. if PADDED, then length must ge 1.✅
            2. when PADDED length read, length must ge 1 + PADDED
            3. length le client wnd and stream client wnd✅
            */
            if ((current_frame.flags & Flags::PADDED) &&
                current_frame.length < 1) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            auto ite = __M_strms.find(current_frame.stream_id);
            if (ite == __M_strms.end()) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            h2_strm& strm = ite->second;
            if (strm.state != StreamStates::Open) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.length > client_wnd ||
                current_frame.length > strm.client_wnd) {
                return ErrorCodes::FLOW_CONTROL_ERROR;
            }
            client_wnd -= current_frame.length;
            strm.client_wnd -= current_frame.length;
            if (!(current_frame.flags & Flags::PADDED)) {
                __M_state.template emplace<DataBodyStage>(current_frame.length);
            } else {
                __M_state.template emplace<DataPaddingStage>();
            }

            if (current_frame.flags & Flags::END_STREAM) {
                strm.state = StreamStates::HalfClosedRemote;
            }
            current_frame.strm = strm.weak_from_this();
            break;
        }
        case HEADERS: {
            /*
            HEADERS requirements:
            0. length must ge offset.✅
            1. state==Open.✅
            */
            const std::size_t offset =
                ((current_frame.flags & Flags::PADDED) ? 1 : 0) +
                ((current_frame.flags & Flags::PRIORITY) ? 5 : 0);
            if (current_frame.length < offset) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            auto ite = __M_strms.find(current_frame.stream_id);
            if (ite == __M_strms.end()) {
                if (current_frame.stream_id % 2 == 0 ||
                    (client_max_id &&
                     current_frame.stream_id <= client_max_id)) {
                    return ErrorCodes::PROTOCOL_ERROR;
                }
                client_max_id = current_frame.stream_id;
                ite = __M_strms.emplace(current_frame.stream_id, __M_session)
                          .first;
                ite->second.self_pos = ite;
                ite->second.client_wnd = conn_settings.initial_window_size;
                ite->second.server_wnd = conn_settings.initial_window_size;
            }
            h2_strm& strm = ite->second;
            if (strm.state != StreamStates::Open) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.flags & Flags::PADDED) {
                __M_state.template emplace<HeaderPaddingStage>();
            } else if (current_frame.flags & Flags::PRIORITY) {
                __M_state.template emplace<HeaderPriorityStage>();
            } else {
                __M_state.template emplace<HeaderBodyStage>(
                    current_frame.length);
            }
            if (!(current_frame.flags & Flags::END_HEADERS)) {
                next_header = current_frame.stream_id;
            } else {
                next_header = 0;
            }

            if (current_frame.flags & Flags::END_STREAM) {
                strm.state = StreamStates::HalfClosedRemote;
            }
            current_frame.strm = strm.weak_from_this();
            break;
        }
        case PRIORITY: {
            /*
            PRIORITY requirements:
            0. length eq 5
            */
            if (current_frame.length != 5) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            __M_state.template emplace<PriorityStage>();
            break;
        }
        case RST_STREAM: {
            /*
            RST requirements:
            0. strm_id eq 0.✅
            1. strm_id le client_max_id.✅
            2. length eq 4.✅
            */
            if (current_frame.stream_id == 0) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (client_max_id && current_frame.stream_id > client_max_id) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.length != 4) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            __M_state.template emplace<RstStage>();
            break;
        }
        case SETTINGS: {
            /*
            SETTINGS requirements:
            0. strm_id eq 0.✅
            1.0 if ACK, then length eq 0.✅
            1.1 if not ACK, then length % 6 eq 0.✅
            */
            if (current_frame.stream_id != 0) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.flags & Flags::ACK) {
                settings_ack_timeout.emit();
                if (current_frame.length != 0) {
                    return ErrorCodes::PROTOCOL_ERROR;
                }
                __M_state.template emplace<LengthStage>();
            } else {
                if (current_frame.length % 6) {
                    return ErrorCodes::PROTOCOL_ERROR;
                }
                __M_state.template emplace<SettingsKeyStage>();
            }
            break;
        }
        case PUSH_PROMISE: {
            /*
            no PP!
            */
            return ErrorCodes::PROTOCOL_ERROR;
        }
        case PING: {
            /*
            PING requirements:
            0. length eq 8.✅
            1. stream_id eq 0.✅
            2. if ACK, then it must be ACK.
            */
            if (current_frame.length != 8) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.stream_id != 0) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            __M_state.template emplace<PingStage>();
            break;
        }
        case GOAWAY: {
            /*
            GOAWAY requirements:
            0. length ge 8.✅
            1. stream_id eq 0.✅
            */
            if (current_frame.length < 8) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.stream_id != 0) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            __M_state.template emplace<GoAwayStrmIdStage>();
            break;
        }
        case WINDOW_UPDATE: {
            /*
            WND_UPD requirements:
            0. length eq 4.✅
            1. strm_id exists (not ge client_max_id).✅
            */
            if (current_frame.length != 4) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.stream_id && client_max_id &&
                current_frame.stream_id > client_max_id) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (current_frame.stream_id) {
                if (auto ite = __M_strms.find(current_frame.stream_id);
                    ite != __M_strms.end()) {
                    current_frame.strm = ite->second.weak_from_this();
                }
            }
            __M_state.template emplace<WndUpdateStage>();
            break;
        }
        case CONTINUATION: {
            /*
            CONTINUATION requirements:
            0. it must be CONTINUATION :P
            */
            if (current_frame.stream_id == 0 ||
                next_header != current_frame.stream_id) {
                return ErrorCodes::PROTOCOL_ERROR;
            }
            if (auto ite = __M_strms.find(next_header);
                ite != __M_strms.end()) {
                current_frame.strm = ite->second.weak_from_this();
            } else {
                return ErrorCodes::INTERNAL_ERROR;
            }
            if (current_frame.flags & Flags::END_HEADERS) {
                next_header = 0;
            }
            __M_state.template emplace<ContinuationStage>(current_frame.length);
            break;
        }
        default: {
            return ErrorCodes::PROTOCOL_ERROR;
        }
        }
        return on<ev::frame_start>(__M_session, *this,
                                   current_frame.const_self());
    }

    ErrorCodes feed(const unsigned char* begin, const unsigned char* end) {
        while (begin <= end && io_cntl.want_recv()) {
            switch (__M_state.index()) {
            case LengthStage: {
                length_parser& parser = *std::get_if<LengthStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.length = parser.result();
                    __M_state.template emplace<TypeStage>();
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case TypeStage: {
                type_parser& parser = *std::get_if<TypeStage>(&__M_state);
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.type = *(begin++);
                __M_state.template emplace<FlagsStage>();
            }
            case FlagsStage: {
                flags_parser& parser = *std::get_if<FlagsStage>(&__M_state);
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.flags = *(begin++);
                __M_state.template emplace<StreamIdStage>();
            }
            case StreamIdStage: {
                stream_id_parser& parser =
                    *std::get_if<StreamIdStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.stream_id = parser.result();

                    // dispatch
                    if (ErrorCodes r = frame_dispatch();
                        r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case DataPaddingStage: {
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.padding = *(begin++);
                if (current_frame.length < current_frame.padding + 1) {
                    return ErrorCodes::PROTOCOL_ERROR;
                }
                __M_state.template emplace<DataBodyStage>(
                    current_frame.length - 1 - current_frame.padding);
            }
            case DataBodyStage: {
                variable_length_parser& parser =
                    *std::get_if<DataBodyStage>(&__M_state);
                ParseResult r = parser(begin, end);
                if (r == ParseSuccess) {
                    // data
                    if (ErrorCodes r = on<ev::data_block>(
                            __M_session, *this, current_frame.const_self(),
                            parser.begin, parser.end);
                        r == ErrorCodes::NO_ERROR) {
                        __M_state.template emplace<DataTail>(
                            current_frame.padding);
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return on<ev::data_block>(__M_session, *this,
                                              current_frame.const_self(),
                                              parser.begin, parser.end);
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case DataTail: {
                variable_length_parser& parser =
                    *std::get_if<DataTail>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    // tail, data frame complete
                    const length_t len = current_frame.length;
                    if (ErrorCodes r = reset_fsm();
                        r == ErrorCodes::NO_ERROR && !len ||
                        (r = create_WINDOW_UPDATE_frame_conn(len)) ==
                            ErrorCodes::NO_ERROR) {
                        do_send();
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case HeaderPaddingStage: {
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.padding = *(begin++);
                if (current_frame.flags & Flags::PRIORITY) {
                    __M_state.template emplace<HeaderPriorityStage>();
                } else {
                    __M_state.template emplace<HeaderBodyStage>(
                        current_frame.length - current_frame.padding - 1);
                    break;
                }
            }
            case HeaderPriorityStage: {
                fixed_length_parser<5>& parser =
                    *std::get_if<HeaderPriorityStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    const std::size_t offset =
                        ((current_frame.flags & Flags::PADDED) ? 1 : 0) +
                        ((current_frame.flags & Flags::PRIORITY) ? 5 : 0);
                    __M_state.template emplace<HeaderBodyStage>(
                        current_frame.length - offset - current_frame.padding);
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case HeaderBodyStage: {
                variable_length_parser& parser =
                    *std::get_if<HeaderBodyStage>(&__M_state);
                ParseResult r = parser(begin, end);
                if (r == ParseSuccess) {
                    // header
                    if (ErrorCodes r = __M_hpack.decode(
                            parser.begin, parser.end,
                            current_frame.flags & Flags::END_HEADERS);
                        r == ErrorCodes::NO_ERROR) {
                        if (ErrorCodes r = on_headers_complete();
                            r != ErrorCodes::NO_ERROR) {
                            return r;
                        }
                        __M_state.template emplace<HeaderTail>(
                            current_frame.padding);
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return __M_hpack.decode(parser.begin, parser.end, 0);
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case HeaderTail: {
                variable_length_parser& parser =
                    *std::get_if<HeaderTail>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case PriorityStage: {
                fixed_length_parser<5>& parser =
                    *std::get_if<PriorityStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case RstStage: {
                // ok
                fixed_length_parser<4>& parser =
                    *std::get_if<RstStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    __M_strms.erase(current_frame.stream_id);
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case SettingsKeyStage: {
                // ok
                if (current_frame.settings_consumed == current_frame.length) {
                    if (ErrorCodes r = create_SETTINGS_ACK_frame();
                        r != ErrorCodes::NO_ERROR) {
                        return r;
                    }
                    do_send();
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                }
                uint16_integer_parser& parser =
                    *std::get_if<SettingsKeyStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.settings_consumed += 2;
                    current_frame.settings_key = parser.result();
                    __M_state.template emplace<SettingsValStage>();
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case SettingsValStage: {
                // ok
                uint32_integer_parser& parser =
                    *std::get_if<SettingsValStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.settings_consumed += 4;
                    if (ErrorCodes r = apply_settings(
                            current_frame.settings_key, parser.result());
                        r == ErrorCodes::NO_ERROR) {
                        __M_state.template emplace<SettingsKeyStage>();
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case PingStage: {
                // ok
                fixed_length_parser<8>& parser =
                    *std::get_if<PingStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    std::array<unsigned char, 8> d;
                    std::copy_n(parser.result, 8, d.data());
                    if (ErrorCodes r = create_PING_ACK_frame(std::move(d));
                        r != ErrorCodes::NO_ERROR) {
                        return r;
                    }
                    do_send();
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case GoAwayStrmIdStage: {
                fixed_length_parser<4>& parser =
                    *std::get_if<GoAwayStrmIdStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    __M_state.template emplace<GoAwayErrorCodeStage>();
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case GoAwayErrorCodeStage: {
                fixed_length_parser<4>& parser =
                    *std::get_if<GoAwayErrorCodeStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    __M_state.template emplace<GoAwayDebugStage>(
                        current_frame.length - 8);
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case GoAwayDebugStage: {
                variable_length_parser& parser =
                    *std::get_if<GoAwayDebugStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    client_max_id = -1;
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case WndUpdateStage: {
                uint32_integer_parser& parser =
                    *std::get_if<WndUpdateStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    const std::uint32_t upd = parser.result();
                    if (upd == 0 ||
                        upd > std::numeric_limits<std::int32_t>::max()) {
                        return ErrorCodes::PROTOCOL_ERROR;
                    }
                    if (current_frame.stream_id == 0) {
                        const std::int64_t cur = server_wnd;
                        if (cur + upd >
                            std::numeric_limits<std::int32_t>::max()) {
                            return ErrorCodes::PROTOCOL_ERROR;
                        }
                        server_wnd += upd;
                        for (auto ite = __M_strms.begin();
                             ite != __M_strms.end() && server_wnd > 0;) {
                            h2_strm& strm = ite->second;
                            auto cur = ite++;
                            if (!strm.pending_DATA_tasks.empty()) {
                                create_DATA_flush3(cur);
                            }
                        }
                    } else if (current_frame.strm) {
                        h2_strm& strm = *current_frame.strm;
                        const std::int64_t cur = strm.server_wnd;
                        if (cur + upd >
                            std::numeric_limits<std::int32_t>::max()) {
                            return ErrorCodes::PROTOCOL_ERROR;
                        }
                        strm.server_wnd += upd;
                        create_DATA_flush3(strm.self_pos);
                    }
                    if (ErrorCodes r = reset_fsm(); r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case ContinuationStage: {
                variable_length_parser& parser =
                    *std::get_if<ContinuationStage>(&__M_state);
                ParseResult r = parser(begin, end);
                if (r == ParseSuccess) {
                    if (ErrorCodes r = __M_hpack.decode(
                            parser.begin, parser.end,
                            current_frame.flags & Flags::END_HEADERS);
                        r == ErrorCodes::NO_ERROR) {
                        if (ErrorCodes r = on_headers_complete();
                            r != ErrorCodes::NO_ERROR) {
                            return r;
                        }
                        if (ErrorCodes r = reset_fsm();
                            r == ErrorCodes::NO_ERROR) {
                            break;
                        } else {
                            return r;
                        }
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return __M_hpack.decode(parser.begin, parser.end, 0);
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case PrefacePRIStage: {
                fixed_length_parser<24>& parser =
                    *std::get_if<PrefacePRIStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    constexpr static char preface[] =
                        "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                    if (std::equal(preface, preface + 24, parser.result,
                                   parser.result + 24)) {
                        if (ErrorCodes r = create_SETTINGS_frame({});
                            r == ErrorCodes::NO_ERROR) {
                            do_send();
                            __M_state.template emplace<PrefaceLengthStage>();
                        } else {
                            return r;
                        }
                    } else {
                        terminate_now();
                        return ErrorCodes::NOT_H2;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case PrefaceLengthStage: {
                length_parser& parser =
                    *std::get_if<PrefaceLengthStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.length = parser.result();
                    __M_state.template emplace<PrefaceTypeStage>();
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            case PrefaceTypeStage: {
                type_parser& parser =
                    *std::get_if<PrefaceTypeStage>(&__M_state);
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.type = *(begin++);
                if (current_frame.type == FrameType::SETTINGS) {
                    __M_state.template emplace<PrefaceFlagsStage>();
                } else {
                    return ErrorCodes::PROTOCOL_ERROR;
                }
            }
            case PrefaceFlagsStage: {
                flags_parser& parser =
                    *std::get_if<PrefaceFlagsStage>(&__M_state);
                if (begin == end) {
                    return ErrorCodes::NO_ERROR;
                }
                current_frame.flags = *(begin++);
                __M_state.template emplace<PrefaceStreamIdStage>();
            }
            case PrefaceStreamIdStage: {
                stream_id_parser& parser =
                    *std::get_if<PrefaceStreamIdStage>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    current_frame.stream_id = parser.result();

                    // dispatch
                    if (ErrorCodes r = frame_dispatch();
                        r == ErrorCodes::NO_ERROR) {
                        break;
                    } else {
                        return r;
                    }
                } else if (r == ParseNeedMore) {
                    return ErrorCodes::NO_ERROR;
                } else {
                    return ErrorCodes::INTERNAL_ERROR;
                }
            }
            default:
                assert(false);
            }
        }
        return ErrorCodes::NO_ERROR;
    }

    ErrorCodes on_headers_complete() {
        if (current_frame.flags & Flags::END_HEADERS) {
            fields_type fields;
            ErrorCodes r = __M_hpack.release(fields);
            if (r != ErrorCodes::NO_ERROR) {
                return r;
            }
            r = on<ev::header_complete>(__M_session, *this,
                                        current_frame.const_self(),
                                        std::move(fields));
            if (r != ErrorCodes::NO_ERROR) {
                return r;
            }
        }
        return ErrorCodes::NO_ERROR;
    }

    template <typename CharT>
    static CharT* to_network4(std::uint32_t v, CharT* dest,
                              std::size_t len = 4) {
        std::uint32_t c = htonl(v);
        std::memcpy(dest, (std::uint8_t*)&c + 4 - len, len);
        return dest + len;
    }
    template <typename CharT>
    static CharT* to_network2(std::uint16_t v, CharT* dest,
                              std::size_t len = 2) {
        std::uint16_t c = htons(v);
        std::memcpy(dest, (std::uint8_t*)&c + 2 - len, len);
        return dest + len;
    }

    ErrorCodes create_PING_ACK_frame(std::array<unsigned char, 8>&& data) {
        pending_frames.emplace_back(
            create_frame_header_helper(FrameType::PING, 8, Flags::ACK, 0),
            payload_variant(std::move(data)));
        // do_send();
        return ErrorCodes::NO_ERROR;
    }

    ErrorCodes create_RST_STREAM_frame(stream_id_t strm_id, ErrorCodes ec) {
        if (!io_cntl.goaway_sent()) {
            if (auto ite = __M_strms.find(strm_id); ite != __M_strms.end()) {
                std::vector<unsigned char> payload(4);
                to_network4(static_cast<std::uint32_t>(ec), payload.data());
                pending_frames.emplace_back(
                    create_frame_header_helper(FrameType::RST_STREAM, 4, 0,
                                               strm_id),
                    std::move(payload));
                __M_strms.erase(ite);
            }
        }
        return ErrorCodes::NO_ERROR;
    }

    void create_GOAWAY_frame(ErrorCodes e) {
        if (!io_cntl.goaway_sent()) {
            shutdown_recv();
            io_cntl.send_goaway();
            client_max_id = -1;
            __M_strms.clear();
            std::array<unsigned char, 8> payload;
            to_network4(largest_strm_id_processed, payload.data());
            to_network4(static_cast<std::uint32_t>(e), payload.data() + 4);
            pending_frames.emplace_back(
                create_frame_header_helper(FrameType::GOAWAY, 8, 0, 0),
                payload_variant(std::move(payload)));
            do_send();
        }
    }

    ErrorCodes create_SETTINGS_ACK_frame() {
        if (!io_cntl.goaway_sent()) {
            pending_frames.emplace_back(
                create_frame_header_helper(FrameType::SETTINGS, 0, Flags::ACK,
                                           0),
                payload_variant{});
        }
        // do_send();
        return ErrorCodes::NO_ERROR;
    }
    ErrorCodes create_SETTINGS_frame(
        const std::initializer_list<std::pair<std::uint16_t, std::uint32_t>>&
            list) {
        if (settings_ack_timeout) {
            return ErrorCodes::INTERNAL_ERROR;
        }
        if (!io_cntl.goaway_sent()) {
            std::vector<unsigned char> payload(list.size() * 6);
            unsigned char* ptr = payload.data();
            for (const auto& [k, v] : list) {
                if (ErrorCodes r = apply_settings(k, v);
                    r != ErrorCodes::NO_ERROR) {
                    return ErrorCodes::INTERNAL_ERROR;
                }
                ptr = to_network2(k, ptr);
                ptr = to_network4(v, ptr);
            }
            pending_frames.emplace_back(
                create_frame_header_helper(FrameType::SETTINGS, payload.size(),
                                           0, 0),
                std::move(payload));
            __M_tmr.async_register(
                std::chrono::seconds(3),
                net::bind_cancellation_signal(
                    settings_ack_timeout,
                    cntl().template next_with_tag<ev_settings_timeout>()));
        }
        return ErrorCodes::NO_ERROR;
    }

    void create_DATA_flush3(h2_strm_iterator ite) {
        if (!io_cntl.goaway_sent()) {
            stream_id_t strm_id = ite->first;
            h2_strm& strm = ite->second;
            auto& q = strm.pending_DATA_tasks;
            for (int wnd = std::min(server_wnd, strm.server_wnd);
                 !q.empty() && wnd > 0;) {
                data_task_t& task = q.front();
                const std::size_t consumed =
                    std::min(static_cast<std::size_t>(wnd), task.size());
                server_wnd -= consumed;
                wnd -= consumed;
                if (consumed == task.size()) {
                    // send whole data task
                    std::visit(
                        [&](auto& a) {
                            pending_frames.emplace_back(
                                create_frame_header_helper(FrameType::DATA,
                                                           consumed, task.flags,
                                                           strm_id),
                                payload_variant(std::move(a)));
                        },
                        task.carrier);
                    const flags_t flags = task.flags;
                    q.pop();
                    if (flags & Flags::END_STREAM) {
                        assert(strm.state == StreamStates::HalfClosedRemote);
                        __M_strms.erase(ite);
                        break;
                    }
                } else {
                    // send prefix of data
                    pending_frames.emplace_back(
                        create_frame_header_helper(FrameType::DATA, consumed, 0,
                                                   strm_id),
                        payload_variant(task.remove_prefix(consumed)));
                }
            }
            do_send();
        }
    }

  public:
    ErrorCodes create_HEADER_frame(flags_t flags, h2_strm& strm,
                                   status_code code,
                                   const fields_type& fields) {
        if (!io_cntl.goaway_sent()) {
            const stream_id_t strm_id = strm.self_pos->first;
            std::vector<unsigned char> payload;
            if (ErrorCodes r = __M_hpack.encode(code, fields, payload);
                r != ErrorCodes::NO_ERROR) {
                return r;
            }

            // send frame
            if (payload.size() <= conn_settings.max_frame_size) {
                const std::size_t n = payload.size();
                pending_frames.emplace_back(
                    create_frame_header_helper(FrameType::HEADERS, n,
                                               flags | Flags::END_HEADERS,
                                               strm.self_pos->first),
                    payload_variant(std::move(payload)));
            } else {
                const std::size_t total_n =
                    (payload.size() + conn_settings.max_frame_size - 1) /
                    conn_settings.max_frame_size;

                const std::size_t head = pending_frames.size();
                pending_frames.resize(pending_frames.size() + total_n);

                std::get<0>(pending_frames.back())[4] =
                    flags | Flags::END_HEADERS;
                auto& last =
                    std::get<1>(pending_frames.back())
                        .template emplace<__Payload_OffsetCarrierVector>(
                            net::offset_carrier(std::move(payload), 0));
                for (std::size_t i = 0; i + 1 < total_n; ++i) {
                    net::const_buffer b(last.data(),
                                        conn_settings.max_frame_size);
                    last.remove_prefix(conn_settings.max_frame_size);
                    std::get<1>(pending_frames[i + head])
                        .template emplace<__Payload_ConstBuffer>(b);
                }
            }
            if (flags & Flags::END_STREAM) {
                send_ES_lifecycle(strm.self_pos);
            }
        }
        return ErrorCodes::NO_ERROR;
    }

    template <typename T>
    void create_DATA_frame(flags_t flags, h2_strm& strm, T&& t) {
        if (!io_cntl.goaway_sent()) {
            assert(strm.state == StreamStates::Open ||
                   strm.state == StreamStates::HalfClosedRemote);
            const std::size_t sz = net::buffer(t).size();
            if (sz) {
                strm.pending_DATA_tasks.push(
                    data_task_t::create(flags, std::forward<T>(t)));
                create_DATA_flush3(strm.self_pos);
            } else {
                pending_frames.emplace_back(
                    create_frame_header_helper(FrameType::DATA, 0, flags,
                                               strm.self_pos->first),
                    payload_variant{});
                if (flags & Flags::END_STREAM) {
                    send_ES_lifecycle(strm.self_pos);
                }
            }
        }
    }

    ErrorCodes create_WINDOW_UPDATE_frame_stream(h2_strm& strm,
                                                 std::int32_t inc) {
        if (!io_cntl.goaway_sent()) {
            if (inc <= 0) {
                return ErrorCodes::INTERNAL_ERROR;
            }
            std::array<unsigned char, 4> payload;
            to_network4(inc, payload.data());
            pending_frames.emplace_back(
                create_frame_header_helper(FrameType::WINDOW_UPDATE, 4, 0,
                                           strm.self_pos->first),
                payload_variant(payload));
            strm.client_wnd += inc;
        }
        return ErrorCodes::NO_ERROR;
    }
    ErrorCodes create_WINDOW_UPDATE_frame_conn(std::int32_t inc) {
        if (!io_cntl.goaway_sent()) {
            if (inc <= 0) {
                return ErrorCodes::INTERNAL_ERROR;
            }
            std::array<unsigned char, 4> payload;
            to_network4(inc, payload.data());
            pending_frames.emplace_back(
                create_frame_header_helper(FrameType::WINDOW_UPDATE, 4, 0, 0),
                payload_variant(payload));
            client_wnd += inc;
        }
        return ErrorCodes::NO_ERROR;
    }

    void terminate_now() {
        shutdown_both();
        io_cntl.send_goaway();
        __M_strms.clear();
        cancel_all();
    }

    stream_id_t largest_strm_id_processed = 0;

  private:
    void send_ES_lifecycle(decltype(__M_strms)::iterator pos) {
        h2_strm& strm = pos->second;
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
            assert(false);
        }
        }
    }
};
template <typename Stream, typename Connection, typename HPackImpl,
          typename FixedTimer>
operation(Stream&&, Connection&&, HPackImpl&&, FixedTimer&) -> operation<
    typename net::detail::remove_rvalue_reference<Stream&&>::type,
    typename net::detail::remove_rvalue_reference<Connection&&>::type,
    typename net::detail::remove_rvalue_reference<HPackImpl&&>::type,
    FixedTimer>;
}  // namespace chx::http::h2::detail

namespace chx::http::h2 {
template <typename Stream, typename Connection, typename HPack,
          typename CompletionToken>
decltype(auto) async_http2(net::io_context& ctx, Stream&& stream,
                           Connection&& connection, HPack&& hpack,
                           net::fixed_timer& timer,
                           CompletionToken&& completion_token) {
    using operation_type = decltype(detail::operation(
        std::forward<Stream>(stream), std::forward<Connection>(connection),
        std::forward<HPack>(hpack), timer));
    return net::async_combine_reference_count<const std::error_code&>(
        ctx, std::forward<CompletionToken>(completion_token),
        net::detail::type_identity<operation_type>{},
        std::forward<Stream>(stream), std::forward<Connection>(connection),
        std::forward<HPack>(hpack), timer);
}
}  // namespace chx::http::h2
