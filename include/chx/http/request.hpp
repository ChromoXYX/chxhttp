#pragma once

#include "./method.hpp"
#include "./header.hpp"

namespace chx::http {
struct request_type {
    method_type method;
    std::string request_target;
    fields_type fields;

    // std::vector<unsigned char> body;
};
}  // namespace chx::http
