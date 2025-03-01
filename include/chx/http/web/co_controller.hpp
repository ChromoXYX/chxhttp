#pragma once

#include <tuple>

#include "./controller_base.hpp"
#include "./controller_context_base.hpp"
#include "./component_results.hpp"

#include <chx/net/coroutine2.hpp>
#include <chx/net/detached.hpp>

namespace chx::http::web {
namespace detail {
template <typename T, typename = void> struct ref_container;
template <typename T> struct ref_container<T&&> : protected std::decay_t<T> {
    constexpr ref_container(const ref_container&) = default;
    constexpr ref_container(ref_container&&) = default;
    constexpr ref_container(T&& t) : std::decay_t<T>(std::move(t)) {}

    constexpr std::decay_t<T>& get() noexcept(true) {
        return static_cast<std::decay_t<T>&>(*this);
    }
    constexpr const std::decay_t<T>& get() const noexcept(true) {
        return static_cast<const std::decay_t<T>&>(*this);
    }
};
template <typename T> struct ref_container<T&> {
    constexpr ref_container(const ref_container&) = default;
    constexpr ref_container(ref_container&&) = default;
    constexpr ref_container(T& r) noexcept(true) : t(r) {}

    constexpr T& get() noexcept(true) { return t; }
    constexpr const T& get() const noexcept(true) { return t; }

  private:
    T& t;
};
template <typename T> struct ref_container<T*> {
    constexpr ref_container(const ref_container&) = default;
    constexpr ref_container(ref_container&&) = default;
    constexpr ref_container(T* r) noexcept(true) : t(r) {}

    constexpr T& get() noexcept(true) { return *t; }
    constexpr const T& get() const noexcept(true) { return *t; }

  private:
    T* t = nullptr;
};

template <typename T> struct ref_container<std::unique_ptr<T>&&> {
    constexpr ref_container(const ref_container&) = default;
    constexpr ref_container(ref_container&&) = default;
    constexpr ref_container(std::unique_ptr<T>&& r) noexcept(true) : t(r) {}

    constexpr T& get() noexcept(true) { return *t; }
    constexpr const T& get() const noexcept(true) { return *t; }

  private:
    std::unique_ptr<T> t;
};

template <typename T> struct ref_container<std::shared_ptr<T>&&> {
    constexpr ref_container(const ref_container&) = default;
    constexpr ref_container(ref_container&&) = default;
    constexpr ref_container(const std::shared_ptr<T>& r) noexcept(true)
        : t(r) {}

    constexpr T& get() noexcept(true) { return *t; }
    constexpr const T& get() const noexcept(true) { return *t; }

  private:
    std::shared_ptr<T> t;
};
template <typename T>
struct ref_container<const std::shared_ptr<T>&>
    : ref_container<std::shared_ptr<T>&&> {};
template <typename T>
struct ref_container<std::shared_ptr<T>&>
    : ref_container<std::shared_ptr<T>&&> {};

template <typename T> struct is_future : std::false_type {};
template <typename T> struct is_future<chx::net::future<T>> : std::true_type {
    using future_type = T;
};

template <typename Action, typename ComponentsTp> class co_controller_impl;
template <typename Action, typename... Components>
class co_controller_impl<Action, std::tuple<Components...>>
    : public controller_base,
      protected ref_container<Action>,
      protected ref_container<Components>... {
    struct storage_t : controller_context_base {
        int n = 0;
        std::tuple<
            std::optional<typename std::decay_t<Components>::storage_type>...>
            d;
        std::exception_ptr ex;
    };

    template <std::size_t... Is>
    chx::net::task<>
    perform_header_complete(const request_type& req,
                            std::shared_ptr<response_type> resp,
                            std::function<void(header_complete_args)> callback,
                            std::integer_sequence<std::size_t, Is...>) {
        std::shared_ptr<storage_t> st = std::make_shared<storage_t>();
        ComponentResults last = ComponentResults::Continue;
        (... &&
         (resp->get_guard() &&
          (++st->n,
           (last = co_await ref_container<Components>::get().on_header_complete(
                std::get<Is>(st->d), req, resp)) ==
               ComponentResults::Continue)));
        if (last == ComponentResults::Break) {
            st->n = -1;
        }
        co_return callback({*resp, st});
    }

    void do_on_header_complete(
        request_type& request, response_type& resp,
        std::function<void(header_complete_args)>&& callback) override {
        if constexpr (sizeof...(Components)) {
            co_spawn(resp.get_associated_io_context(),
                     perform_header_complete(
                         request, resp.make_shared(), std::move(callback),
                         std::make_integer_sequence<std::size_t,
                                                    sizeof...(Components)>{}),
                     chx::net::detached);
        } else {
            callback({resp, {}});
        }
    }

    template <std::size_t... Is>
    chx::net::task<> perform_on_data_block(
        std::shared_ptr<storage_t> storage, const request_type& req,
        std::shared_ptr<response_type> resp, const unsigned char* begin,
        const unsigned char* end, std::function<void(data_block_args)> callback,
        std::integer_sequence<std::size_t, Is...>) {
        int cnt = 0;
        ComponentResults last = ComponentResults::Continue;
        (... &&
         (cnt < storage->n && last == ComponentResults::Continue &&
          resp->get_guard() &&
          (last = co_await ref_container<Components>::get().on_data_block(
               std::get<Is>(storage->d), req, resp, begin, end),
           ++cnt)));
        storage->n = (last != ComponentResults::Break ? cnt : -1);
        co_return callback({*resp});
    }

    void
    do_on_data_block(controller_context& session, request_type& request,
                     response_type& resp, const unsigned char* begin,
                     const unsigned char* end,
                     std::function<void(data_block_args)>&& callback) override {
        if constexpr (sizeof...(Components)) {
            assert(session.index() == 0);
            std::shared_ptr st =
                std::static_pointer_cast<storage_t>(std::get<0>(session));
            if (st->n != -1 && st->n != 0) {
                co_spawn(
                    resp.get_associated_io_context(),
                    perform_on_data_block(
                        st, request, resp.make_shared(), begin, end,
                        std::move(callback),
                        std::make_integer_sequence<std::size_t,
                                                   sizeof...(Components)>{}),
                    chx::net::detached);
            } else {
                callback({resp});
            }
        } else {
            callback({resp});
        }
    }

    template <std::size_t... Is>
    chx::net::task<>
    perform_message_complete(std::shared_ptr<storage_t> storage,
                             request_type req,
                             std::shared_ptr<response_type> resp,
                             std::integer_sequence<std::size_t, Is...>) {
        std::tuple<
            std::optional<typename std::decay_t<Components>::result_type>...>
            ctx;
        int cnt = 0;
        ComponentResults last = ComponentResults::Continue;
        (... &&
         (cnt < storage->n && last == ComponentResults::Continue &&
          resp->get_guard() &&
          (last = co_await ref_container<Components>::get().on_message_complete(
               std::get<Is>(storage->d), std::get<Is>(ctx), req, resp),
           ++cnt)));
        if (last != ComponentResults::Break) {
            using action_return_t = typename is_future<std::invoke_result_t<
                decltype(ref_container<Action>::get()), decltype(req),
                decltype(resp), decltype(ctx)>>::future_type;
            if constexpr (std::is_same_v<action_return_t, void>) {
                co_await ref_container<Action>::get()(req, resp,
                                                      std::move(ctx));
            } else {
                resp->end(co_await ref_container<Action>::get()(
                    req, resp, std::move(ctx)));
            }
        }
    }

    void do_on_message_complete(controller_context& session,
                                request_type& request,
                                response_type&& response) override {
        assert(session.index() == 0);
        std::shared_ptr st =
            std::static_pointer_cast<storage_t>(std::get<0>(session));
        if (st && st->n == -1) {
            return;
        }
        co_spawn(response.get_associated_io_context(),
                 perform_message_complete(
                     st, std::move(request), response.make_shared(),
                     std::make_integer_sequence<std::size_t,
                                                sizeof...(Components)>{}),
                 net::detached);
    }

  public:
    template <typename A, typename... C>
    co_controller_impl(A&& a, C&&... c)
        : ref_container<Action>(std::forward<A>(a)),
          ref_container<Components>(std::forward<C>(c))... {}
};
}  // namespace detail

template <typename Action, typename... Components>
std::unique_ptr<
    detail::co_controller_impl<Action&&, std::tuple<Components&&...>>>
co_controller(Action&& action, Components&&... components) {
    return std::make_unique<
        detail::co_controller_impl<Action&&, std::tuple<Components&&...>>>(
        std::forward<Action>(action), std::forward<Components>(components)...);
}
}  // namespace chx::http::web
