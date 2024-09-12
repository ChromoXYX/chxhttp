#pragma once

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <netinet/in.h>
#include <limits>
#include "./types.hpp"

namespace chx::http::h2::detail {
enum [[nodiscard]] ParseResult {
    ParseSuccess,
    ParseNeedMore,
    ParseMalformed,
    ParseInternalError
};

template <std::size_t N> struct fixed_length_parser {
    static_assert(N <= std::numeric_limits<std::uint8_t>::max());
    constexpr ParseResult operator()(const unsigned char*& begin,
                                     const unsigned char* end) noexcept(true) {
        const std::size_t n =
            std::min(static_cast<std::size_t>(N - consumed),
                     static_cast<std::size_t>(std::distance(begin, end)));
        for (std::size_t i = 0; i < n; ++i) {
            result[consumed++] = *(begin++);
        }
        return consumed == N ? ParseSuccess : ParseNeedMore;
    }

    std::uint8_t consumed = 0;
    unsigned char result[N] = {};
};

struct uint16_integer_parser : fixed_length_parser<2> {
    std::uint16_t result() noexcept(true) {
        std::uint16_t r = 0;
        ::memcpy((unsigned char*)&r, fixed_length_parser<2>::result, 2);
        return ntohs(r);
    }
};

struct uint32_integer_parser : fixed_length_parser<4> {
    std::uint32_t result() noexcept(true) {
        std::uint32_t r = 0;
        ::memcpy((unsigned char*)&r, fixed_length_parser<4>::result, 4);
        return ntohl(r);
    }
};

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