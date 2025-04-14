#pragma once

#include "./status_code.hpp"
#include "./header.hpp"
#include "./session_closed.hpp"
#include <chx/net/detail/monostate_container.hpp>
#include <chx/net/tcp.hpp>
#include <chx/net/utility.hpp>
#include <variant>

namespace chx::http {
struct action_result {
    friend class response_type;

    using payload_type =
        std::variant<net::detail::monostate_container, net::const_buffer,
                     std::string, std::vector<unsigned char>,
                     std::vector<std::vector<unsigned char>>, net::mapped_file,
                     net::carrier<net::mapped_file>, net::vcarrier>;

    status_code code = status_code::OK;
    fields_type fields;
    payload_type payload;

    action_result() = default;

    action_result(status_code code) : action_result(code, fields_type{}) {}
    action_result(status_code code, fields_type fields)
        : code(code), fields(std::move(fields)) {}

    template <typename T>
    action_result(status_code code, T t)
        : action_result(code, fields_type{}, std::move(t)) {}
    template <typename T>
    action_result(status_code code, fields_type fields, T t)
        : code(code), fields(std::move(fields)), payload(std::move(t)) {}

    template <typename CharT, typename Traits>
    action_result(status_code code, fields_type fields,
                  std::basic_string_view<CharT, Traits> t)
        : code(code), fields(std::move(fields)), payload(net::buffer(t)) {}

    template <typename CharT, std::size_t N,
              typename = std::void_t<std::enable_if_t<sizeof(CharT) == 1>>>
    action_result(status_code code, fields_type fields, CharT p[N])
        : action_result(code, std::move(fields), std::basic_string_view{p}) {}
};

class response_type {
  public:
    virtual ~response_type() = default;

    virtual std::shared_ptr<response_type> make_shared() const = 0;
    virtual std::unique_ptr<response_type> make_unique() const = 0;

    virtual bool get_guard() const noexcept(true) = 0;
    virtual void guard() const {
        if (!get_guard()) {
            throw session_closed{};
        }
    }

    bool expired() const noexcept(true) { return do_expired(); }

    virtual const net::ip::tcp::socket* socket() const noexcept(true) = 0;

    void pause() { do_pause(); }
    void resume() { do_resume(); }
    void terminate() { do_terminate(); }

    virtual net::io_context& get_associated_io_context() const {
        return do_get_associated_io_context();
    }

    // bool would_block() const noexcept(true) { return do_would_block(); }

    class stream_type {
        friend response_type;
        response_type& __M_self;

        status_code __M_status_code;
        fields_type __M_fields;
        std::queue<std::vector<unsigned char>> __M_buf;

        bool __M_started = false;

        stream_type(response_type& self) noexcept(true) : __M_self(self) {}

        void flush() {
            if (!__M_started && !__M_self.do_streaming_would_block()) {
                __M_started = true;
                __M_self.do_streaming_flush_header(__M_status_code,
                                                   std::move(__M_fields));
                while (!__M_buf.empty()) {
                    __M_self.do_streaming_flush(std::move(__M_buf.front()));
                    __M_buf.pop();
                }
            }
        }

      public:
        stream_type& set_status_code(status_code c) {
            __M_status_code = c;
            return *this;
        }

        stream_type& set_fields(fields_type&& fields) {
            __M_fields = std::move(fields);
            if (!__M_self.do_streaming_would_block()) {
                __M_self.do_streaming_flush_header(__M_status_code,
                                                   std::move(__M_fields));
                __M_started = true;
            }
            return *this;
        }

        stream_type& write(std::vector<unsigned char> buffer) {
            if (__M_started) {
                __M_self.do_streaming_flush(std::move(buffer));
            } else {
                __M_buf.push(std::move(buffer));
                flush();
            }
            return *this;
        }
        stream_type& write(std::string str) {
            return write(std::vector<unsigned char>(str.begin(), str.end()));
        }

        void commit() {
            flush();
            if (!__M_started) {
                std::vector<std::vector<unsigned char>> b;
                b.reserve(__M_buf.size());
                while (!__M_buf.empty()) {
                    b.push_back(std::move(__M_buf.front()));
                    __M_buf.pop();
                }
                __M_self.do_end(__M_status_code, std::move(__M_fields),
                                std::move(b));
            } else {
                __M_self.do_streaming_commit();
            }
        }
    };

    stream_type stream() noexcept(true) { return {*this}; }

    void end(status_code code, fields_type&& fields) {
        try {
            do_end(code, std::move(fields));
        } catch (const std::exception&) {
            net::rethrow_with_fatal(std::current_exception());
        }
    }

    template <typename T> void end(status_code code, fields_type fields, T t) {
        try {
            do_end(code, std::move(fields), std::move(t));
        } catch (const std::exception&) {
            net::rethrow_with_fatal(std::current_exception());
        }
    }

    void end(action_result result) {
        std::visit(
            [&](auto& a) {
                if constexpr (std::is_same_v<
                                  std::decay_t<decltype(a)>,
                                  net::detail::monostate_container>) {
                    end(result.code, std::move(result.fields));
                } else {
                    end(result.code, std::move(result.fields), std::move(a));
                }
            },
            result.payload);
    }

  private:
    virtual bool do_expired() const noexcept(true) = 0;

    virtual void do_end(status_code code, fields_type&& fields) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::const_buffer view) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::string payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::vector<unsigned char> payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        std::vector<std::vector<unsigned char>> payload) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::mapped_file mapped) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::carrier<net::mapped_file> mapped) = 0;
    virtual void do_end(status_code code, fields_type&& fields,
                        net::vcarrier&& vc) = 0;

    virtual void do_terminate() = 0;
    virtual void do_pause() = 0;
    virtual void do_resume() = 0;

    virtual bool do_streaming_would_block() noexcept(true) = 0;
    // return 0 or positive for bytes pushed
    virtual std::size_t do_streaming_flush_header(status_code code,
                                                  fields_type&& fields) = 0;
    virtual std::size_t
    do_streaming_flush(std::vector<unsigned char>&& buffer) = 0;
    virtual void do_streaming_commit() = 0;

    virtual net::io_context& do_get_associated_io_context() const = 0;
};
}  // namespace chx::http
