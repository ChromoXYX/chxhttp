#pragma once

#include "../request.hpp"
#include "../response.hpp"

namespace chx::http::web {
class error_handler_base {
  public:
    virtual ~error_handler_base() = default;

    virtual void operator()(status_code why, const request_type& request,
                            response& response) {
        response.end(why, fields_type{});
    }
};
}  // namespace chx::http::web
