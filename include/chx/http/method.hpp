#pragma once

#include <llhttp.h>

namespace chx::http {
enum method_type {
    BAD_METHOD = 0,
    GET = 1,
    HEAD = 2,
    POST = 3,
    PUT = 4,
    DELETE = 5,
    CONNECT = 6,
    OPTIONS = 7,
    TRACE = 8
};

constexpr const char* method_name(method_type m) noexcept(true) {
    switch (m) {
    case method_type::GET: {
        return "GET";
    }
    case method_type::HEAD: {
        return "HEAD";
    }
    case method_type::POST: {
        return "POST";
    }
    case method_type::PUT: {
        return "PUT";
    }
    case method_type::DELETE: {
        return "DELETE";
    }
    case method_type::CONNECT: {
        return "CONNECT";
    }
    case method_type::OPTIONS: {
        return "OPTIONS";
    }
    case method_type::TRACE: {
        return "TRACE";
    }
    default: {
        return "BAD METHOD";
    }
    }
}

namespace detail {
inline method_type method_from_h1(uint8_t m) noexcept(true) {
    switch (m) {
    case HTTP_GET: {
        return method_type::GET;
    }
    case HTTP_HEAD: {
        return method_type::HEAD;
    }
    case HTTP_POST: {
        return method_type::POST;
    }
    case HTTP_PUT: {
        return method_type::PUT;
    }
    case HTTP_DELETE: {
        return method_type::DELETE;
    }
    case HTTP_CONNECT: {
        return method_type::CONNECT;
    }
    case HTTP_OPTIONS: {
        return method_type::OPTIONS;
    }
    case HTTP_TRACE: {
        return method_type::TRACE;
    }
    default: {
        return method_type::BAD_METHOD;
    }
    }
}
}  // namespace detail
}  // namespace chx::http