#pragma once

#include <coroutine>
#include <span>

#include <chx/net/coroutine2.hpp>
#include <chx/net/detached.hpp>
#include <chx/net/detail/scope_exit.hpp>

#include "../request.hpp"
#include "../response.hpp"

#include "./controller_base.hpp"
#include "./controller_context_base.hpp"

namespace chx::http::web::middleware {
class middleware_interrupted : public net::exception {
  public:
    using exception::exception;
};
class middleware_interrupted_4xx : public middleware_interrupted {
  public:
    using middleware_interrupted::middleware_interrupted;
};
class middleware_interrupted_5xx : public middleware_interrupted {
  public:
    using middleware_interrupted::middleware_interrupted;
};

namespace detail {
template <typename T> struct is_shared_ptr : std::false_type {};
template <typename T>
struct is_shared_ptr<std::shared_ptr<T>> : std::true_type {};

struct data_receiver {
    const unsigned char *begin = nullptr, *end = nullptr;
    std::function<void(data_block_args)> callback;
};
struct promise_package {
    data_receiver d;
    action_result r;
};
}  // namespace detail

template <typename T> struct safe_pointer {
    constexpr safe_pointer() noexcept(true) {}
    constexpr safe_pointer(T* t) noexcept(true) : ptr(t) {}
    T* ptr = nullptr;

    constexpr operator bool() const noexcept(true) { return ptr; }

    constexpr T* operator->() {
        if (!ptr) {
            __CHXNET_THROW_CSTR("Cannot dereference a null pointer");
        }
        return ptr;
    }
    constexpr T& operator*() {
        if (!ptr) {
            __CHXNET_THROW_CSTR("Cannot dereference a null pointer");
        }
        return *ptr;
    }

    constexpr operator auto() noexcept(true) { return ptr; }
};
template <> struct safe_pointer<void> {
    constexpr safe_pointer() noexcept(true) {}
    constexpr safe_pointer(void* t) noexcept(true) : ptr(t) {}
    void* ptr = nullptr;

    constexpr operator bool() const noexcept(true) { return ptr; }
    constexpr operator auto() noexcept(true) { return ptr; }
};

class middleware_base;

struct middleware_error {
    http::status_code code;
    std::string error_msg;

    std::exception_ptr ex;
};

struct mw_info {
    net::future<> future;
    net::future<>::awaitable a;
    middleware_base* self = nullptr;
};

class middleware_chain {
  protected:
    std::vector<std::shared_ptr<middleware_base>> chain;

    template <typename Fn>
    std::tuple<std::vector<net::future_view<>>, std::vector<mw_info>>
    boot(const request_type& req, response_type& resp, Fn&& cntl_factory) {
        std::vector<net::future_view<>> views;
        std::vector<mw_info> mw;
        const std::size_t n = chain.size();

        mw.reserve(n);
        views.reserve(n);
        for (std::size_t i = 0; i < n; ++i) {
            net::future<> fu = (*chain[i])(req, resp, cntl_factory(i));
            auto a = fu.operator co_await();
            mw.push_back({std::move(fu), std::move(a), chain[i].get()});
            views.push_back(mw.back().future.h);
        }
        return std::make_tuple(std::move(views), std::move(mw));
    }

    net::future<> exec(struct control_g_env& g, struct control_l_env& l);

  public:
    middleware_chain& add(const std::shared_ptr<middleware_base>& ptr) {
        chain.push_back(ptr);
        return *this;
    }
    template <typename Fn, typename = std::enable_if_t<
                               !detail::is_shared_ptr<std::decay_t<Fn>>::value>>
    middleware_chain& add(Fn&& fn, bool accept_error = false);
    template <auto Fn> middleware_chain& add(bool accept_error = false);
};

struct data_reference {
    net::detail::anchor anchor;
    void* ptr = nullptr;

    constexpr bool valid() const noexcept(true) {
        return ptr && anchor.valid();
    }
    constexpr operator bool() const noexcept(true) { return valid(); }

    template <typename T> constexpr T* cast() noexcept(true) {
        return static_cast<T*>(ptr);
    }
    template <typename T> constexpr const T* cast() const noexcept(true) {
        return static_cast<const T*>(ptr);
    }
};
struct control_base {
    enum Stage { Header, Data, Complete, PostProcess };
};

struct control_env;
struct control_g_env {
    detail::promise_package& p;
    response_type& resp;
    control_base::Stage stage = control_base::Header;

    std::exception_ptr ex;

    bool short_circuited = false;

    std::vector<unsigned char> body;

    constexpr bool encountered_exception() const noexcept(true) { return !!ex; }
    constexpr bool encountered_error() const noexcept(true) {
        return p.r.code >= 400 && p.r.code <= 499;
    }
};
struct control_l_env {
    control_g_env& g;
    std::coroutine_handle<> h;
    control_l_env* const parent;

    std::vector<std::pair<std::string, data_reference>> mdata;

    std::vector<net::future_view<>> future_list;
    std::vector<mw_info> mw;
};

class controller : public controller_base, public middleware_chain {
    using promise_package = detail::promise_package;
    using task = net::task<promise_package>;

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
};

class control : public control_base {
    friend controller;

    struct awaitable_base : std::suspend_always {
        constexpr awaitable_base(control& s) noexcept(true) : self(s) {}
        control& self;
        auto await_suspend(std::coroutine_handle<>) noexcept(true) {
            return self.l_env.h;
        }
        void await_resume();
    };

  public:
    control_l_env& l_env;
    const std::size_t index;

    constexpr control_l_env
    child_l_env(std::coroutine_handle<> child_h) noexcept(true) {
        return {.g = l_env.g, .h = child_h, .parent = &l_env};
    }

    net::future<> schedule() {
        auto h =
            std::exchange(l_env.future_list[index].h, co_await net::this_coro);
        net::detail::scope_exit guard(
            [this, h]() { l_env.future_list[index].h = h; });
        co_return co_await awaitable_base{*this};
    }

    constexpr action_result& result() noexcept(true) { return l_env.g.p.r; }
    std::span<const unsigned char> payload() noexcept(true) {
        if (l_env.g.stage == control::Data) {
            return {l_env.g.p.d.begin, l_env.g.p.d.end};
        } else {
            return {};
        }
    }

    bool short_circuited() noexcept(true) { return l_env.g.short_circuited; }
    void short_circuit() noexcept(true) { l_env.g.short_circuited = true; }

    Stage stage() const noexcept(true) { return l_env.g.stage; }

    template <typename T = void> constexpr auto& mdata() noexcept(true) {
        return l_env.mdata;
    }
    template <typename T = void>
    constexpr safe_pointer<T> mdata(std::string_view key) noexcept(true) {
        return get_mdata<T>(key);
    }
    template <typename T = void>
    constexpr T* get_mdata(std::string_view key) noexcept(true) {
        control_l_env* node = &l_env;
        while (node) {
            auto ite =
                std::find_if(node->mdata.begin(), node->mdata.end(),
                             [&](const auto& p) { return p.first == key; });
            if (ite != node->mdata.end()) {
                return ite->second.valid() ? ite->second.template cast<T>()
                                           : nullptr;
            } else {
                node = node->parent;
            }
        }
        return nullptr;
    }
    template <typename T>
    [[nodiscard]] net::detail::anchor set_mdata(const std::string& name, T* t) {
        auto [a, b] = net::detail::anchor::create();
        l_env.mdata.emplace_back(name, data_reference{std::move(b), t});
        return std::move(a);
    }

    auto& body() noexcept(true) { return l_env.g.body; }
};

class middleware_base {
    virtual bool do_accept_error() const noexcept(true) { return false; }
    virtual bool do_accept_exception_interrupt() const noexcept(true) {
        return false;
    }
    virtual net::future<> do_invoke(const request_type& req,
                                    response_type& resp, control cntl) = 0;

  public:
    virtual ~middleware_base() = default;

    bool accept_error() const noexcept(true) { return do_accept_error(); }
    bool accept_exception_interrupt() const noexcept(true) {
        return do_accept_exception_interrupt();
    }

    net::future<> operator()(const request_type& req, response_type& resp,
                             control cntl) {
        return do_invoke(req, resp, cntl);
    }
};

inline void control::awaitable_base::await_resume() {
    if (!self.l_env.mw[self.index].self->accept_exception_interrupt()) {
        return;
    }
    if (self.l_env.g.encountered_exception()) {
        throw middleware_interrupted_5xx{};
    }
    if (self.l_env.g.encountered_error()) {
        throw middleware_interrupted_4xx{};
    }
}

template <typename Fn, typename>
middleware_chain& middleware_chain::add(Fn&& fn, bool accept_error) {
    class impl : std::decay_t<Fn>, public middleware_base {
        const bool __accept_error;

        bool do_accept_error() const noexcept(true) override {
            return __accept_error;
        }
        net::future<> do_invoke(const request_type& req, response_type& resp,
                                control cntl) override {
            return static_cast<Fn>(*this)(req, resp, cntl);
        }

      public:
        impl(Fn&& fn, bool a)
            : std::decay_t<Fn>(std::forward<Fn>(fn)), __accept_error(a) {}
    };
    return add(std::make_shared<impl>(std::forward<Fn>(fn), accept_error));
}
template <auto Fn> middleware_chain& middleware_chain::add(bool accept_error) {
    return add([](const request_type& req, response_type& resp,
                  control cntl) { return Fn(req, resp, std::move(cntl)); },
               accept_error);
}

inline net::future<> middleware_chain::exec(control_g_env& g,
                                            control_l_env& l) {
    auto prev_coro = l.h;
    l.h = co_await net::this_coro;
    net::detail::scope_exit _g([&l, prev_coro]() { l.h = prev_coro; });
    for (std::size_t i = 0; i < chain.size(); ++i) {
        if (((!g.encountered_error() && !g.encountered_exception()) ||
             l.mw[i].self->accept_error()) &&
            !l.future_list[i].h.done()) {
            auto old_parent =
                std::exchange(l.future_list[i].h.promise().__M_parent,
                              co_await net::this_coro);
            co_await l.future_list[i];
            l.future_list[i].h.promise().__M_parent = old_parent;
            if (l.mw[i].a.__M_ex) {
                g.ex = std::exchange(l.mw[i].a.__M_ex, {});
            }
        }
    }
}

inline auto controller::perform_header_complete(
    request_type request, std::shared_ptr<response_type> resp,
    std::function<void(header_complete_args)> callback)
    -> net::task<promise_package> {
    try {
        struct awaitable_for_resume : std::suspend_always {
            net::detail::anchor& a;
            constexpr bool await_ready() noexcept(true) { return !a.valid(); }
        };

        control_g_env g{.p = (co_await net::this_coro).promise(),
                        .resp = *resp};
        control_l_env l{.g = g, .h = (co_await net::this_coro)};

        const std::size_t n = chain.size();
        std::tie(l.future_list, l.mw) =
            boot(request, *resp,
                 [&, h = co_await net::this_coro](std::size_t i) -> control {
                     return control{{}, l, i};
                 });
        for (auto& [future, a, self] : l.mw) {
            co_await a;
        }

        auto [a, b] = net::detail::anchor::create();
        {
            resp->get_associated_io_context().async_nop(
                [resp,
                 c =
                     controller_context_anchor{
                         (co_await net::this_coro).address(), std::move(b)},
                 cb = std::move(callback)](const std::error_code&) mutable {
                    cb({*resp, std::move(c)});
                });
            co_await awaitable_for_resume{{}, a};
        }
        g.stage = control::Data;
        while (g.p.d.callback) {
            // wait for data
            co_await exec(g, l);
            resp->get_associated_io_context().async_nop(
                [cb = std::move(g.p.d.callback), resp](const std::error_code&) {
                    cb({*resp});
                });
            co_await awaitable_for_resume{{}, a};
        }
        g.stage = control::Complete;
        // now message
        co_await exec(g, l);
        g.stage = control::PostProcess;
        if (!g.short_circuited) {
            resp->end(std::move(g.p.r));
        }
        co_await exec(g, l);
        co_return;
    } catch (const session_closed&) {
        co_return;
    }
}
}  // namespace chx::http::web::middleware
