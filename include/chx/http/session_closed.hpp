#pragma once

#include <chx/net/exception.hpp>

namespace chx::http {
class session_closed : public net::exception {
  public:
    using exception::exception;
};
}  // namespace chx::http