#pragma once

#include "./status_code.hpp"
#include "./header.hpp"
#include "./session_closed.hpp"

#include <chx/net/coroutine2.hpp>
#include <chx/net/utility.hpp>

namespace chx::http {
class response {
  public:
    virtual ~response() = default;

    virtual std::unique_ptr<response> copy() const = 0;
    virtual bool get_guard() const noexcept(true) = 0;
    virtual void guard() const {
        if (!get_guard()) {
            throw session_closed{};
        }
    }

    virtual void end(status_code code, fields_type&& fields) = 0;
    virtual void end(status_code code, fields_type&& fields,
                     std::string_view payload) = 0;
    virtual void end(status_code code, fields_type&& fields,
                     std::vector<unsigned char> payload) = 0;
    virtual void end(status_code code, fields_type&& fields,
                     net::mapped_file mapped, std::size_t len,
                     std::size_t offset = 0) = 0;

    virtual void co_spawn(net::future<>&& future) const = 0;
};
}  // namespace chx::http
