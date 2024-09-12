#pragma once

#include <system_error>

namespace chx::http::h2 {
enum [[nodiscard]] ErrorCodes : unsigned int {
    NO_ERROR = 0x00,
    PROTOCOL_ERROR = 0x01,
    INTERNAL_ERROR = 0x02,
    FLOW_CONTROL_ERROR = 0x03,
    SETTINGS_TIMEOUT = 0x04,
    STREAM_CLOSED = 0x05,
    FRAME_SIZE_ERROR = 0x06,
    REFUSED_STREAM = 0x07,
    CANCEL = 0x08,
    COMPRESSION_ERROR = 0x09,
    CONNECT_ERROR = 0x0a,
    ENHANCE_YOUR_CALM = 0x0b,
    INADEQUATE_SECURITY = 0x0c,
    HTTP_1_1_REQUIRED = 0x0d,

    NOT_H2 = 0xffffffff
};

inline std::error_code make_ec(ErrorCodes code) noexcept(true) {
    class __category : public std::error_category {
      public:
        virtual const char* name() const noexcept(true) override {
            return "chxhttp.h2 error_category";
        }

        virtual std::error_condition default_error_condition(int ev) const
            noexcept(true) override {
            return std::error_condition(ev, *this);
        }

        virtual bool equivalent(const std::error_code& ec, int ev) const
            noexcept(true) override {
            return *this == ec.category() && static_cast<int>(ec.value()) == ev;
        }

        virtual std::string message(int ev) const override {
            switch (ev) {
            case NO_ERROR: {
                return "Success";
            }
            case PROTOCOL_ERROR: {
                return "PROTOCOL_ERROR";
            }
            case INTERNAL_ERROR: {
                return "INTERNAL_ERROR";
            }
            case FLOW_CONTROL_ERROR: {
                return "FLOW_CONTROL_ERROR";
            }
            case SETTINGS_TIMEOUT: {
                return "SETTINGS_TIMEOUT";
            }
            case STREAM_CLOSED: {
                return "STREAM_CLOSED";
            }
            case FRAME_SIZE_ERROR: {
                return "FRAME_SIZE_ERROR";
            }
            case REFUSED_STREAM: {
                return "REFUSED_STREAM";
            }
            case CANCEL: {
                return "CANCEL";
            }
            case COMPRESSION_ERROR: {
                return "COMPRESSION_ERROR";
            }
            case CONNECT_ERROR: {
                return "CONNECT_ERROR";
            }
            case ENHANCE_YOUR_CALM: {
                return "ENHANCE_YOUR_CALM";
            }
            case INADEQUATE_SECURITY: {
                return "INADEQUATE_SECURITY";
            }
            case HTTP_1_1_REQUIRED: {
                return "HTTP_1_1_REQUIRED";
            }
            default: {
                return "UNKNOWN";
            }
            }
        }
    } static __c;
    return std::error_code(code, __c);
}
}  // namespace chx::http::h2