#pragma once

#include <coroutine>
#include <span>
#include <map>
#include <any>

#include <chx/net/coroutine2.hpp>
#include <chx/net/detached.hpp>
#include <chx/net/detail/scope_exit.hpp>

#include "../request.hpp"
#include "../response.hpp"

#include "./controller_base.hpp"
#include "./controller_context_base.hpp"

namespace chx::http::web {
namespace detail {
template <typename T> struct is_shared_ptr : std::false_type {};
template <typename T>
struct is_shared_ptr<std::shared_ptr<T>> : std::true_type {};
}  // namespace detail

class middleware_base;

struct middleware_chain {
    std::vector<std::shared_ptr<middleware_base>> chain;

    void add(const std::shared_ptr<middleware_base>& ptr) {
        chain.push_back(ptr);
    }

    template <typename Fn, typename = std::enable_if_t<
                               !detail::is_shared_ptr<std::decay_t<Fn>>::value>>
    void add(Fn&& fn, bool accept_exception = false);
};

class middleware_controller : public controller_base {
    struct data_receiver {
        const unsigned char *begin = nullptr, *end = nullptr;
        std::function<void(data_block_args)> callback;
    };
    struct promise_package {
        data_receiver d;
        action_result r;
    };
    using task = net::task<promise_package>;

    // std::vector<std::shared_ptr<middleware_base>> __M_mw;
    middleware_chain __M_chain;

    net::task<promise_package>
    perform_header_complete(request_type request,
                            std::shared_ptr<response_type> resp,
                            std::function<void(header_complete_args)> callback);
    void do_on_header_complete(
        request_type& request, response_type& resp,
        std::function<void(header_complete_args)>&& callback) override {
        co_spawn(resp.get_associated_io_context(),
                 perform_header_complete(std::move(request), resp.make_shared(),
                                         std::move(callback)),
                 net::detached);
    }

    void
    do_on_data_block(controller_context& session, request_type& request,
                     response_type& resp, const unsigned char* begin,
                     const unsigned char* end,
                     std::function<void(data_block_args)>&& callback) override {
        assert(session.index() == 2);
        const controller_context_anchor& s = std::get<2>(session);
        if (!s.anchor.valid() || begin == end) {
            return callback({resp});
        }
        auto h = std::coroutine_handle<
            net::task<promise_package>::promise_type>::from_address(s.ptr);
        promise_package& p = h.promise();
        p.d = {begin, end, std::move(std::move(callback))};
        h.resume();
    }

    void do_on_message_complete(controller_context& session,
                                request_type& request,
                                response_type&& response) override {
        assert(session.index() == 2);
        const controller_context_anchor& s = std::get<2>(session);
        if (!s.anchor.valid()) {
            return;
        }
        auto h = std::coroutine_handle<
            net::task<promise_package>::promise_type>::from_address(s.ptr);
        promise_package& p = h.promise();
        p.d.callback = {};
        h.resume();
    }

    void do_on_destruct(controller_context& session) noexcept(true) override {
        // final_suspend of task is suspend_never, so it would destruct
        // immediately after co_return, ie, anchor is invalid
        assert(session.index() == 2);
        controller_context_anchor& c = *std::get_if<2>(&session);
        if (c.anchor.valid()) {
            std::coroutine_handle<>::from_address(c.ptr).destroy();
        }
    }

    std::vector<net::future<>> mw;

    enum Stage { Header, Data, Complete };

    struct control_env {
        std::vector<net::future_view<>> future_list;
        promise_package& p;
        response_type& resp;
        Stage stage;
        std::map<std::string, std::any> data;
        std::vector<std::exception_ptr> ex;

        bool encountered_exception = false;
    };
    struct control_args {
        std::coroutine_handle<> h;
        const std::size_t index;

        control_env& env;
    };

  public:
    middleware_controller& add(const std::shared_ptr<middleware_base>& ptr) {
        __M_chain.add(ptr);
        return *this;
    }

    template <typename Fn, typename = std::enable_if_t<
                               !detail::is_shared_ptr<std::decay_t<Fn>>::value>>
    middleware_controller& add(Fn&& fn, bool accept_exception = false) {
        __M_chain.add(std::forward<Fn>(fn), accept_exception);
        return *this;
    }

    class control : public control_args {
        friend middleware_controller;

        struct awaitable_base : std::suspend_always {
            constexpr awaitable_base(control& s) noexcept(true) : self(s) {}
            control& self;
            auto await_suspend(std::coroutine_handle<>) noexcept(true) {
                return self.h;
            }
        };

      public:
        control(const control&) = default;
        constexpr control(const control_args& args) noexcept(true)
            : control_args(args) {}

        constexpr auto schedule() noexcept(true) {
            return awaitable_base{*this};
        }

        net::future<> wait_till_complete() {
            auto h = std::exchange(env.future_list[index].h,
                                   co_await net::this_coro);
            net::detail::scope_exit guard(
                [this, h]() { env.future_list[index].h = h; });
            while (env.stage != Stage::Complete) {
                co_await awaitable_base(*this);
            }
            co_return;
        }

        constexpr action_result& result() noexcept(true) { return env.p.r; }
    };
};

class middleware_base {
    virtual bool do_accept_exception() const noexcept(true) { return false; }
    virtual net::future<> do_invoke(const request_type& req,
                                    response_type& resp,
                                    middleware_controller::control cntl) = 0;

  public:
    virtual ~middleware_base() = default;

    bool accept_exception() const noexcept(true) {
        return do_accept_exception();
    }

    net::future<> operator()(const request_type& req, response_type& resp,
                             middleware_controller::control cntl) {
        return do_invoke(req, resp, cntl);
    }
};

template <typename Fn, typename>
void middleware_chain::add(Fn&& fn, bool accept_exception) {
    class impl : std::decay_t<Fn>, public middleware_base {
        const bool __accept_exception;

        bool do_accept_exception() const noexcept(true) override {
            return __accept_exception;
        }
        net::future<> do_invoke(const request_type& req, response_type& resp,
                                middleware_controller::control cntl) override {
            return static_cast<Fn>(*this)(req, resp, cntl);
        }

      public:
        impl(Fn&& fn, bool a)
            : std::decay_t<Fn>(std::forward<Fn>(fn)), __accept_exception(a) {}
    };
    add(std::make_shared<impl>(std::forward<Fn>(fn), accept_exception));
}

inline auto middleware_controller::perform_header_complete(
    request_type request, std::shared_ptr<response_type> resp,
    std::function<void(header_complete_args)> callback)
    -> net::task<promise_package> {
    struct awaitable_for_resume : std::suspend_always {
        net::detail::anchor& a;
        constexpr bool await_ready() noexcept(true) { return !a.valid(); }
    };

    control_env env{.p = (co_await net::this_coro).promise(), .resp = *resp};
    struct mw_info {
        net::future<> future;
        net::future<>::awaitable a;
        middleware_base* self = nullptr;
    };
    std::vector<mw_info> mw;
    const std::size_t n = __M_chain.chain.size();

    env.future_list.reserve(n);
    mw.reserve(n);
    for (std::size_t i = 0; i < __M_chain.chain.size(); ++i) {
        net::future<> fu = (*__M_chain.chain[i])(
            request, *resp, {{co_await net::this_coro, i, env}});
        auto a = fu.operator co_await();
        mw.push_back({std::move(fu), std::move(a), __M_chain.chain[i].get()});
        env.future_list.emplace_back(mw.back().future.h);
        co_await mw.back().a;
    }
    auto [a, b] = net::detail::anchor::create();
    {
        resp->get_associated_io_context().async_nop(
            [resp,
             c = controller_context_anchor{(co_await net::this_coro).address(),
                                           std::move(b)},
             cb = std::move(callback)](const std::error_code&) mutable {
                cb({*resp, std::move(c)});
            });
        co_await awaitable_for_resume{{}, a};
    }
    env.stage = Stage::Data;
    while (env.p.d.callback) {
        // wait for data
        for (std::size_t i = 0; i < n; ++i) {
            if ((!env.encountered_exception ||
                 mw[i].self->accept_exception()) &&
                !env.future_list[i].h.done()) {
                // actually it will never throw
                co_await env.future_list[i];
                if (mw[i].a.__M_ex) {
                    env.ex.push_back(std::exchange(mw[i].a.__M_ex, {}));
                    env.encountered_exception = true;
                }
            }
        }
        resp->get_associated_io_context().async_nop(
            [cb = std::move(env.p.d.callback), resp](const std::error_code&) {
                cb({*resp});
            });
        co_await awaitable_for_resume{{}, a};
    }
    env.stage = Stage::Complete;
    // now message
    for (std::size_t i = 0; i < n; ++i) {
        while ((!env.encountered_exception || mw[i].self->accept_exception()) &&
               !env.future_list[i].h.done()) {
            co_await env.future_list[i];
            if (mw[i].a.__M_ex) {
                env.ex.push_back(std::exchange(mw[i].a.__M_ex, {}));
                env.encountered_exception = true;
            }
        }
    }
    co_return resp->end(std::move(env.p.r));
}
}  // namespace chx::http::web
