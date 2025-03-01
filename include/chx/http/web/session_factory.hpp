#pragma once

#include "./controller_base.hpp"
#include "../events.hpp"
#include <variant>
#include <chx/net/detail/tracker.hpp>

namespace chx::http::web {
namespace detail {
template <typename Dispatcher> struct dispatcher_session {
    constexpr dispatcher_session(Dispatcher* s) noexcept(true) : self(s) {}
    constexpr dispatcher_session(dispatcher_session&& other) noexcept(true) =
        default;

    ~dispatcher_session() noexcept(true) {
        if (auto* p = std::get_if<1>(&uv); p) {
            p->first->on_destruct(p->second);
        }
    }

    template <typename Response>
    void operator()(header_complete, request_type& req, Response&& resp) {
        assert(uv.index() == 0);
        auto [preferred_, controller_] = self->get(req);
        if (controller_) {
            resp.pause();
            controller_->on_header_complete(
                req, resp,
                [this, controller_](header_complete_args args) mutable {
                    auto [resp, ses] = std::move(args);
                    if (!resp.expired()) {
                        uv.template emplace<1>(controller_, std::move(ses));
                        resp.resume();
                    } else {
                        controller_->on_destruct(ses);
                    }
                });
        } else {
            uv.template emplace<2>(preferred_);
        }
    }

    template <typename Response>
    void operator()(data_block, request_type& request, Response&& resp,
                    const unsigned char* begin, const unsigned char* end) {
        if (auto* p = std::get_if<1>(&uv); p) {
            resp.pause();
            p->first->on_data_block(p->second, request, resp, begin, end,
                                    [this](data_block_args args) mutable {
                                        auto [resp] = args;
                                        if (!resp.expired()) {
                                            resp.resume();
                                        }
                                    });
        }
    }

    void operator()(message_complete, request_type& request,
                    response_type&& resp) {
        switch (uv.index()) {
        case 1: {
            auto [controller, ctx] = std::move(*std::get_if<1>(&uv));
            uv.template emplace<0>();
            controller->on_message_complete(ctx, request, std::move(resp));
            return;
        }
        case 2: {
            status_code c = *std::get_if<2>(&uv);
            uv.template emplace<0>();
            safe_invoke(self->get_error_handler(), c, request, resp);
            return;
        }
        default: {
            assert(false);
        }
        }
    }

    void operator()(backend_timeout, request_type& req, response_type&& resp) {
        safe_invoke(self->get_error_handler(),
                    http::status_code::Gateway_Timeout, req, resp);
    }

    void operator()(ev::request_4xx, status_code code, request_type& req,
                    response_type&& resp) {
        safe_invoke(self->get_error_handler(), code, req, resp);
    }

  protected:
    Dispatcher* const self;

    std::variant<std::monostate,
                 std::pair<controller_base*, controller_context>, status_code,
                 std::monostate>
        uv;

    template <typename T, typename... Args>
    static void safe_invoke(T* ptr, Args&&... args) {
        if (ptr) {
            (*ptr)(std::forward<Args>(args)...);
        }
    }
};
}  // namespace detail
template <typename Dispatcher>
decltype(auto) session_factory(Dispatcher& dispatcher) {
    return [&dispatcher]() { return detail::dispatcher_session(&dispatcher); };
}
}  // namespace chx::http::web