#pragma once

#include "./status_code.hpp"
#include "./header.hpp"
#include "./session_closed.hpp"
#include <chx/net/tcp.hpp>
#include <chx/net/utility.hpp>

namespace chx::http {
class response {
  public:
    virtual ~response() = default;

    virtual std::shared_ptr<response> make_shared() const = 0;
    virtual std::unique_ptr<response> make_unique() const = 0;

    virtual bool get_guard() const noexcept(true) = 0;
    virtual void guard() const {
        if (!get_guard()) {
            throw session_closed{};
        }
    }

    virtual net::io_context* get_associated_io_context() const
        noexcept(true) = 0;
    virtual const net::ip::tcp::socket* socket() const noexcept(true) = 0;
    virtual void terminate() = 0;

    template <typename... Ts>
    void end(status_code code, fields_type&& fields, Ts&&... ts) {
        try {
            do_end(code, std::move(fields), std::forward<Ts>(ts)...);
        } catch (const std::exception&) {
            net::rethrow_with_fatal(std::current_exception());
        }
    }

  private:
    virtual void do_end(status_code code, fields_type&& fields) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::string_view payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::string payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::vector<unsigned char> payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::mapped_file mapped) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::carrier<net::mapped_file> mapped) = 0;
};
}  // namespace chx::http
