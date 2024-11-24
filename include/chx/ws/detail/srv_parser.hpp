#pragma once

#include "../frame.hpp"
#include "../status_codes.hpp"
#include "../../detail/parser.hpp"
#include <variant>
#include <cassert>

namespace chx::ws::detail::parser {
using namespace chx::detail::parser;

struct variable_length_parser {
    constexpr variable_length_parser(std::size_t len) noexcept(true)
        : length(len) {}

    constexpr ParseResult operator()(unsigned char*& b,
                                     const unsigned char* e) noexcept(true) {
        const std::size_t n =
            std::min(static_cast<std::size_t>(length - consumed),
                     static_cast<std::size_t>(e - b));
        begin = b;
        b += n;
        consumed += n;
        end = b;
        return consumed == length ? ParseSuccess : ParseNeedMore;
    }

    const std::size_t length;
    std::size_t consumed = 0;
    unsigned char* begin = nullptr;
    const unsigned char* end = nullptr;

    constexpr std::pair<unsigned char*, const unsigned char*>
    result() noexcept(true) {
        return {begin, end};
    }
};

struct srv_parser {
    template <typename Callbacks>
    StatusCodes execute(unsigned char* begin, unsigned char* end,
                        Callbacks&& callbacks) {
        while (begin <= end) {
            switch (__M_state.index()) {
            case Opcode: {
                if (begin == end) {
                    return NoError;
                }
                const std::uint8_t op = *(begin++);
                if (op & frame::FrameExtensionMask) {
                    return ProtocolError;
                }
                if (!frame_utils.check_valid_frame_type<
                        frame::Continuation, frame::Text, frame::Binary,
                        frame::ConnectionClose, frame::Ping, frame::Pong>(
                        op & frame::FrameTypeMask)) {
                    return ProtocolError;
                }
                __M_curr_frame.opcode = op;
                callbacks.on_opcode_complete();
                __M_state.template emplace<Payload8>();
                break;
            }
            case Payload8: {
                if (begin == end) {
                    return NoError;
                }
                std::uint8_t p8 = *(begin++);
                if (!(p8 & 0x80)) {
                    return ProtocolError;
                }
                p8 &= 0x7f;
                if (p8 < 126) {
                    __M_curr_frame.payload_length = p8;
                    callbacks.on_length_complete();
                    __M_state.template emplace<MaskingKey>();
                } else if (p8 == 126) {
                    __M_state.template emplace<Payload16>();
                } else if (p8 == 127) {
                    __M_state.template emplace<Payload16>();
                } else {
                    assert(false);
                }
                break;
            }
            case Payload16: {
                uint16_integer_parser& parser =
                    *std::get_if<Payload16>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    __M_curr_frame.payload_length = parser.result();
                    callbacks.on_length_complete();
                    __M_state.template emplace<MaskingKey>();
                } else {
                    return NoError;
                }
                break;
            }
            case Payload64: {
                uint64_integer_parser& parser =
                    *std::get_if<Payload64>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    __M_curr_frame.payload_length = parser.result();
                    callbacks.on_length_complete();
                    __M_state.template emplace<MaskingKey>();
                } else {
                    return NoError;
                }
                break;
            }
            case MaskingKey: {
                fixed_length_parser<4>& parser =
                    *std::get_if<MaskingKey>(&__M_state);
                if (ParseResult r = parser(begin, end); r == ParseSuccess) {
                    std::copy(parser.result, parser.result + 4,
                              __M_curr_frame.masking_key);
                    callbacks.on_masking_key_complete();
                    __M_state.template emplace<5>(
                        __M_curr_frame.payload_length);
                } else {
                    return NoError;
                }
                break;
            }
            case PayloadData: {
                variable_length_parser& parser =
                    *std::get_if<PayloadData>(&__M_state);
                ParseResult r = parser(begin, end);
                frame_utils.transform_by_mask(__M_curr_frame.masking_key,
                                              parser.begin, parser.end);
                callbacks.on_payload(parser.begin, parser.end);
                if (r == ParseSuccess) {
                    reset_frame_state();
                } else {
                    return NoError;
                }
                break;
            }
            }
        }
        assert(false);
    }

  protected:
    std::variant<uint8_integer_parser, uint8_integer_parser,
                 uint16_integer_parser, uint64_integer_parser,
                 uint32_integer_parser, variable_length_parser>
        __M_state;
    enum __State {
        Opcode = 0,
        Payload8 = 1,
        Payload16 = 2,
        Payload64 = 3,
        MaskingKey = 4,
        PayloadData = 5
    };

    frame __M_curr_frame = {};
    struct frame_utils {
        template <frame::FrameType... FrameTypes>
        constexpr bool check_valid_frame_type(std::uint8_t target) const
            noexcept(true) {
            return ((target == FrameTypes) || ...);
        }

        std::size_t payload_index = 0;
        constexpr void
        transform_by_mask(const std::uint8_t (&mask)[4], unsigned char* begin,
                          const unsigned char* end) noexcept(true) {
            while (begin < end) {
                *(begin++) ^= mask[payload_index++ % 4];
            }
        }
    } frame_utils;
    void reset_frame_state() noexcept(true) {
        __M_curr_frame = {};
        frame_utils = {};
        __M_state.template emplace<Opcode>();
    }
};
}  // namespace chx::ws::detail::parser
