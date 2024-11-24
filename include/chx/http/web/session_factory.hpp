#pragma once

#include "./controller_base.hpp"
#include "../events.hpp"
#include <variant>

namespace chx::http::web {
namespace detail {
template <typename Dispatcher> struct dispatcher_session {
    constexpr dispatcher_session(Dispatcher* s) noexcept(true) : self(s) {}
    constexpr dispatcher_session(dispatcher_session&& other) noexcept(true) =
        default;

    void operator()(header_complete, request_type& request, response&& resp) {
        assert(uv.index() == 0);
        auto [preferred_, controller] = self->get(request);
        if (controller) {
            try {
                std::shared_ptr session_storage =
                    controller->on_header_complete(request);
                uv.template emplace<1>(controller, session_storage);
            } catch (const std::exception&) {
                uv.template emplace<3>(std::current_exception());
            }
        } else {
            // u.deferred_error = preferred_;
            uv.template emplace<2>(preferred_);
        }
    }

    void operator()(data_block, request_type& request, response&& resp,
                    const unsigned char* begin, const unsigned char* end) {
        if (auto* p = std::get_if<1>(&uv); p) {
            try {
                p->first->on_data_block(p->second, request, begin, end);
            } catch (const std::exception&) {
                uv.template emplace<3>(std::current_exception());
            }
        }
    }

    void operator()(message_complete, request_type& request, response&& resp) {
        switch (uv.index()) {
        case 1: {
            auto& p = *std::get_if<1>(&uv);
            try {
                p.first->on_message_complete(p.second, request,
                                             std::move(resp));
            } catch (const std::exception&) {
                safe_invoke(self->get_uncaught_exception_handler(),
                            std::current_exception(), request, resp);
            }
            break;
        }
        case 2: {
            safe_invoke(self->get_error_handler(), *std::get_if<2>(&uv),
                        request, resp);
            break;
        }
        case 3: {
            safe_invoke(self->get_uncaught_exception_handler(),
                        *std::get_if<3>(&uv), request, resp);
            break;
        }
        default: {
            assert(false);
        }
        }
        uv.template emplace<0>();
    }

    void operator()(backend_timeout, request_type& req, response&& resp) {
        safe_invoke(self->get_error_handler(),
                    http::status_code::Gateway_Timeout, req, resp);
    }

    void operator()(ev::request_4xx, status_code code, request_type& req,
                    response&& resp) {
        safe_invoke(self->get_error_handler(), code, req, resp);
    }

  protected:
    Dispatcher* const self;

    std::variant<
        std::monostate,
        std::pair<controller_base*, std::shared_ptr<controller_context_base>>,
        status_code, std::exception_ptr>
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