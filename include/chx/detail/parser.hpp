#pragma once

#include <cstdint>
#include <algorithm>
#include <cstring>
#include <netinet/in.h>
#include <limits>

namespace chx::detail::parser {
enum [[nodiscard]] ParseResult {
    ParseSuccess,
    ParseNeedMore,
    ParseMalformed,
    ParseInternalError
};

template <std::size_t N> struct fixed_length_parser {
    static_assert(N <= std::numeric_limits<std::uint8_t>::max());
    template <typename CharT>
    constexpr ParseResult
    operator()(CharT*& begin, std::add_const_t<CharT>* end) noexcept(true) {
        const std::size_t n = std::min(static_cast<std::size_t>(N - consumed),
                                       static_cast<std::size_t>(end - begin));
        for (std::size_t i = 0; i < n; ++i) {
            result[consumed++] = *(begin++);
        }
        return consumed == N ? ParseSuccess : ParseNeedMore;
    }

    std::uint8_t consumed = 0;
    unsigned char result[N] = {};
};

struct uint8_integer_parser {};

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

struct uint64_integer_parser : fixed_length_parser<8> {
    std::uint64_t result() noexcept(true) {
        std::uint64_t r = 0;
        ::memcpy((unsigned char*)&r, fixed_length_parser<8>::result, 8);
        return be64toh(r);
    }
};
}  // namespace chx::detail::parser