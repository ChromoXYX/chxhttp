#pragma once

#include "./method.hpp"
#include "./header.hpp"

namespace chx::http {
struct request_type {
    method_type method;
    std::string request_target;
    fields_type fields;
    fields_type trailing_headers;
};
}  // namespace chx::http
