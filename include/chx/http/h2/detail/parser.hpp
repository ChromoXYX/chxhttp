#pragma once

#include "../../../detail/parser.hpp"
#include "./types.hpp"

namespace chx::http::h2::detail {
using namespace chx::detail::parser;

struct length_parser : fixed_length_parser<3> {
    length_t result() noexcept(true) {
        std::uint32_t val = 0;
        ::memcpy((unsigned char*)&val + 1, fixed_length_parser<3>::result, 3);
        return ntohl(val);
    }
};

struct type_parser {};
struct flags_parser {};

struct stream_id_parser : fixed_length_parser<4> {
    stream_id_t result() noexcept(true) {
        std::uint32_t val = 0;
        ::memcpy((unsigned char*)&val, fixed_length_parser<4>::result, 4);
        return ntohl(val);
    }
};

struct variable_length_parser {
    constexpr variable_length_parser(length_t len) : length(len) {}

    constexpr ParseResult operator()(const unsigned char*& b,
                                     const unsigned char* e) noexcept(true) {
        const std::size_t n =
            std::min(static_cast<std::size_t>(length - consumed),
                     static_cast<std::size_t>(std::distance(b, e)));
        begin = b;
        b += n;
        consumed += n;
        end = b;
        return consumed == length ? ParseSuccess : ParseNeedMore;
    }

    const length_t length;
    std::uint32_t consumed = 0;
    const unsigned char *begin = nullptr, *end = nullptr;
};
}  // namespace chx::http::h2::detail
