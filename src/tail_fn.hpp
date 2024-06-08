#pragma once

#include <system_error>

struct tail_fn_t {
    inline static std::size_t cnt = 0;

    void operator()(const std::error_code& e) const;
} inline tail_fn = {};
