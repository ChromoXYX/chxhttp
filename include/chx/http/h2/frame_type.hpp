#pragma once

#include "./types.hpp"
#include "./detail/copy_integer.hpp"

#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include <vector>

#include <chx/net/io_context.hpp>

namespace chx::http::h2 {
enum FrameType : std::uint8_t {
    DATA = 0x00,
    HEADERS = 0x01,
    PRIORITY = 0x02,
    RST_STREAM = 0x03,
    SETTINGS = 0x04,
    PUSH_PROMISE = 0x05,
    PING = 0x06,
    GOAWAY = 0x07,
    WINDOW_UPDATE = 0x08,
    CONTINUATION = 0x09
};

struct frame_type {
    enum Flags : flags_type {
        ACK = 0x01,
        END_STREAM = 0x01,
        END_HEADERS = 0x04,
        PADDED = 0x08,
        PRIORITY = 0x20,
        NO_FLAG = 0
    };

    length_type length = 0;
    std::uint8_t type = 0;
    flags_type flags = 0;
    stream_id_type stream_id = 0;

    std::vector<unsigned char> payload;
    length_type payload_length = 0;

    void clear() noexcept(true) {
        length = 0;
        type = 0;
        flags = 0;
        stream_id = 0;
        payload_length = 0;
        payload.clear();
    }
};

struct views {
    struct data_type : frame_type {
        data_type(const data_type&) = default;
        data_type(data_type&&) = default;
        data_type(frame_type&& fr) noexcept(true) : frame_type(std::move(fr)) {}

        constexpr bool get_PADDED() const noexcept(true) {
            return flags & PADDED;
        }
        constexpr bool get_END_STREAM() const noexcept(true) {
            return flags & END_STREAM;
        }
    };
    struct headers_type : frame_type {
        headers_type(const headers_type&) = default;
        headers_type(headers_type&&) = default;
        headers_type(frame_type&& fr, fields_type&& fi) noexcept(true)
            : frame_type(std::move(fr)), fields(std::move(fi)) {}

        constexpr bool get_PRIORITY() const noexcept(true) {
            return flags & PRIORITY;
        }
        constexpr bool get_PADDED() const noexcept(true) {
            return flags & PADDED;
        }
        constexpr bool get_END_STREAM() const noexcept(true) {
            return flags & END_STREAM;
        }

        fields_type fields;
    };
    struct rst_stream_type : frame_type {
        rst_stream_type(const rst_stream_type&) = default;
        rst_stream_type(rst_stream_type&&) = default;
        rst_stream_type(frame_type&& fr) noexcept(true)
            : frame_type(std::move(fr)) {}

        std::uint32_t get_error_code() const noexcept(true) {
            return detail::from_network4(payload.data());
        }
    };
    struct settings_type : frame_type {
        settings_type(const settings_type&) = default;
        settings_type(settings_type&&) = default;
        settings_type(frame_type&& fr) noexcept(true)
            : frame_type(std::move(fr)) {}

        struct setting_type {
            constexpr std::add_lvalue_reference_t<unsigned char[6]>
            underlying() noexcept(true) {
                return __buf;
            }

            using value_type = unsigned char;
            constexpr value_type* data() noexcept(true) { return __buf; }
            constexpr const value_type* data() const noexcept(true) {
                return __buf;
            }
            constexpr std::size_t size() const noexcept(true) { return 6; }

            std::uint16_t identifier() const noexcept(true) {
                return detail::from_network2(__buf);
            }
            std::uint32_t value() const noexcept(true) {
                return detail::from_network4(__buf + 2);
            }

            void identifier(std::uint16_t id) noexcept(true) {
                detail::to_network2(id, __buf);
            }
            void value(std::uint32_t v) noexcept(true) {
                detail::to_network4(v, __buf + 2);
            }

          private:
            unsigned char __buf[6] = {};
        };
        static_assert(sizeof(setting_type) == 6);

        constexpr bool get_ACK() const noexcept(true) { return flags & ACK; }

        constexpr std::size_t setting_size() const noexcept(true) {
            return length / 6;
        }

        setting_type* begin() noexcept(true) {
            return reinterpret_cast<setting_type*>(payload.data());
        }
        setting_type* end() noexcept(true) { return begin() + setting_size(); }

        const setting_type* begin() const noexcept(true) {
            return reinterpret_cast<const setting_type*>(payload.data());
        }
        const setting_type* end() const noexcept(true) {
            return begin() + setting_size();
        }
    };
    struct ping_type : frame_type {
        ping_type(const ping_type&) = default;
        ping_type(ping_type&&) = default;
        ping_type(frame_type&& fr) noexcept(true) : frame_type(std::move(fr)) {}

        constexpr bool get_ACK() const noexcept(true) { return flags & ACK; }
    };
    struct goaway_type : frame_type {
        goaway_type(const goaway_type&) = default;
        goaway_type(goaway_type&&) = default;
        goaway_type(frame_type&& fr) noexcept(true)
            : frame_type(std::move(fr)) {}

        stream_id_type last_stream_id() const noexcept(true) {
            return detail::from_network4(payload.data());
        }
        std::uint32_t error_code() const noexcept(true) {
            return detail::from_network4(payload.data() + 4);
        }
    };
    struct window_update_type : frame_type {
        window_update_type(const window_update_type&) = default;
        window_update_type(window_update_type&&) = default;
        window_update_type(frame_type&& fr) noexcept(true)
            : frame_type(std::move(fr)) {}

        std::uint32_t window_size_increment() const noexcept(true) {
            return detail::from_network4(payload.data());
        }
    };
};

struct data_frame_block {};
}  // namespace chx::http::h2