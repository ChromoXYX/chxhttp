#pragma once

#include "./detail/check_path.hpp"
#include "./error_handler_base.hpp"
#include "./controller_base.hpp"
#include "./uncaught_exception_handler_base.hpp"
#include "../events.hpp"

namespace chx::http::web {
template <typename DispatchImpl>
class basic_dispatcher : protected DispatchImpl {
    std::unique_ptr<error_handler_base> __M_err;
    std::unique_ptr<uncaught_exception_handler_base> __M_uncaught;

    controller_base* get(method_type meth, const std::string& path) const
        noexcept(true) {
        return DispatchImpl::get(meth, path);
    }
    struct __session_t {
        constexpr __session_t(basic_dispatcher* s) noexcept(true) : self(s) {
            u.union_fill = 0;
        }
        constexpr __session_t(__session_t&& other) noexcept(true)
            : self(other.self) {
            controller = other.controller;
            u = other.u;
            other.controller = nullptr;
            other.u = {};
        }
        ~__session_t() noexcept(true) {
            if (controller) {
                controller->delete_session(u.ses);
            }
        }

        void operator()(header_complete, const request_type& request,
                        response&& resp) {
            assert(u.union_fill == 0);
            if (!detail::check_path(request.request_target)) {
                u.deferred_error = status_code::Bad_Request;
                return;
            }
            controller = self->get(request.method, request.request_target);
            if (controller) {
                u.ses = controller->create_session();
                controller->on_header_complete(u.ses, request);
            } else {
                u.deferred_error = status_code::Not_Found;
            }
        }

        void operator()(data_block, const request_type& request,
                        response&& resp, const unsigned char* begin,
                        const unsigned char* end) {
            if (controller) {
                controller->on_data_block(u.ses, request, begin, end);
            }
        }

        void operator()(message_complete, request_type& request,
                        response&& resp) {
            if (controller) {
                try {
                    controller->on_message_complete(u.ses, request,
                                                    std::move(resp));
                } catch (const std::exception&) {
                    controller->delete_session(u.ses);
                    controller = nullptr;
                    safe_invoke(self->__M_uncaught, std::current_exception(),
                                request, std::move(resp));
                    u = {};
                    return;
                } catch (const net::fatal_exception&) {
                    controller->delete_session(u.ses);
                    controller = nullptr;
                    std::rethrow_exception(std::current_exception());
                }
                controller->delete_session(u.ses);
                controller = nullptr;
            } else {
                safe_invoke(self->__M_err, u.deferred_error, request,
                            std::move(resp));
            }
            u = {};
        }

      protected:
        basic_dispatcher* const self;
        controller_base* controller = nullptr;
        union {
            std::size_t union_fill;
            controller_session_base* ses;
            status_code deferred_error;
        } u = {};
        static_assert(sizeof(u) == sizeof(u.union_fill));

        template <typename T, typename... Args>
        static void safe_invoke(std::unique_ptr<T>& ptr, Args&&... args) {
            if (ptr) {
                (*ptr)(std::forward<Args>(args)...);
            }
        }
    };

  public:
    basic_dispatcher()
        : __M_err(new error_handler_base),
          __M_uncaught(new uncaught_exception_handler_base) {}

    template <typename... Ts>
    decltype(auto) add(std::unique_ptr<controller_base> controller,
                       method_type meth, Ts&&... ts) {
        return DispatchImpl::add(std::move(controller), meth,
                                 std::forward<Ts>(ts)...);
    }

    void
    set_error_handler(std::unique_ptr<error_handler_base> ptr) noexcept(true) {
        __M_err.swap(ptr);
    }
    void set_uncaught_exception_handler(
        std::unique_ptr<uncaught_exception_handler_base> ptr) noexcept(true) {
        __M_uncaught.swap(ptr);
    }

    error_handler_base* get_error_handler() const noexcept(true) {
        return __M_err.get();
    }
    uncaught_exception_handler_base* get_uncaught_exception_handler() const
        noexcept(true) {
        return __M_uncaught.get();
    }

    constexpr auto session_factory() noexcept(true) {
        return [this]() -> __session_t { return this; };
    }
};
}  // namespace chx::http::web