#pragma once

#include <cstddef>

#include <chx/http/method.hpp>
#include <chx/http/h2/types.hpp>
#include <string_view>
#include <vector>

struct request_type {
    chx::http::method_type method;
    std::string_view scheme;
    std::string_view authority;
    std::string_view path;

    chx::http::h2::fields_type fields;

    std::vector<std::vector<unsigned char>> payload;
};

std::size_t boot_h2();