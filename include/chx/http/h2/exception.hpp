#pragma once

#include <chx/net/exception.hpp>
#include <system_error>

namespace chx::http::h2 {
class runtime_exception : public net::exception {
    std::error_code __M_ec;

  public:
    runtime_exception(const std::error_code& ec, const char* cmsg)
        : exception(cmsg), __M_ec(ec) {}
    runtime_exception(const std::error_code& ec, const std::string& msg)
        : exception(msg), __M_ec(ec) {}

    const std::error_code& get_error_code() const noexcept(true) {
        return __M_ec;
    }
};

class connection_closed : public net::exception {
  public:
    using exception::exception;
};
}  // namespace chx::http::h2

#define __CHXHTTP_H2RT_THROW(ec)                                               \
    throw ::chx::http::h2::runtime_exception(                                  \
        ec, ec.message() + " at file: " __FILE__                               \
                           " line: " __CHXNET_MAKE_QUOTE(__LINE__))
