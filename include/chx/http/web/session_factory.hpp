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

    void operator()(header_complete, const request_type& request,
                    response&& resp) {
        assert(uv.index() == 0);
        auto [preferred_, controller_] = self->get(request);
        if (controller_) {
            auto& [controller, session_data] = uv.template emplace<1>(
                controller_, controller_->create_session());
            try {
                controller->on_header_complete(session_data.get(), request);
            } catch (const std::exception&) {
                uv.template emplace<3>(std::current_exception());
            }
        } else {
            // u.deferred_error = preferred_;
            uv.template emplace<2>(preferred_);
        }
    }

    void operator()(data_block, const request_type& request, response&& resp,
                    const unsigned char* begin, const unsigned char* end) {
        if (auto* p = std::get_if<1>(&uv); p) {
            try {
                p->first->on_data_block(p->second.get(), request, begin, end);
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
                p.first->on_message_complete(p.second.get(), request,
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

    void operator()(backend_timeout, const request_type& req, response&& resp) {
        safe_invoke(self->get_error_handler(),
                    http::status_code::Gateway_Timeout, req, resp);
    }

  protected:
    Dispatcher* const self;

    std::variant<
        std::monostate,
        std::pair<controller_base*, std::unique_ptr<controller_context_base>>,
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