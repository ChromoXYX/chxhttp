#pragma once

#include "../request.hpp"
#include "../response.hpp"

namespace chx::http::web {
class uncaught_exception_handler_base {
  public:
    virtual ~uncaught_exception_handler_base() = default;

    virtual void operator()(std::exception_ptr ex, const request_type& request,
                            response_type& response) {
        response.end(status_code::Internal_Server_Error, fields_type{});
    }
};
}  // namespace chx::http::web
