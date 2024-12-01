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

    virtual const net::ip::tcp::socket* socket() const noexcept(true) = 0;

    void pause() { do_pause(); }
    void resume() { do_resume(); }
    void terminate() { do_terminate(); }

    virtual net::io_context& get_associated_io_context() const {
        return do_get_associated_io_context();
    }

    template <typename... Ts>
    void end(status_code code, fields_type&& fields, Ts&&... ts);

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
    virtual void do_end(status_code code, fields_type&& fields,
                        net::vcarrier&& vc) = 0;

    virtual void do_terminate() = 0;
    virtual void do_pause() = 0;
    virtual void do_resume() = 0;

    virtual net::io_context& do_get_associated_io_context() const = 0;

    struct can_do_end_directly;
};

struct response::can_do_end_directly {
    template <typename... Ts,
              typename = decltype(std::declval<response>().do_end(
                  std::declval<status_code>(), std::declval<fields_type>(),
                  std::declval<Ts&&>()...))>
    can_do_end_directly(Ts&&...);
};

template <typename... Ts>
void response::end(status_code code, fields_type&& fields, Ts&&... ts) {
    try {
        if constexpr (std::is_constructible_v<can_do_end_directly, Ts&&...>) {
            do_end(code, std::move(fields), std::forward<Ts>(ts)...);
        } else {
            do_end(code, std::move(fields),
                   net::vcarrier::create(std::forward<Ts>(ts)...));
        }
    } catch (const std::exception&) {
        net::rethrow_with_fatal(std::current_exception());
    }
}
}  // namespace chx::http
