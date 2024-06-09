#pragma once

#include <type_traits>
#include <tuple>
#include <memory>
#include <vector>
#include <chx/net/iovec_buffer.hpp>

namespace chx::http::detail {
struct payload_store {
    virtual ~payload_store() = default;

    template <typename... Ts> auto static create(Ts&&... ts) {
        struct impl : payload_store {
            impl(impl&&) = default;
            impl(Ts&&... ts) : data(std::forward<Ts>(ts)...) {}

            std::tuple<std::remove_reference_t<Ts>...> data;

            using data_len = std::integral_constant<std::size_t, sizeof...(Ts)>;
        };
        return std::make_unique<impl>(std::forward<Ts>(ts)...);
    }
};
struct payload_rep {
    payload_rep() = default;
    payload_rep(payload_rep&&) = default;
    template <typename T>
    payload_rep(std::unique_ptr<T> ptr) : payload(ptr.release()) {}

    payload_rep& operator=(payload_rep&&) = default;

    std::unique_ptr<payload_store> payload;

    using value_type = unsigned char;
    constexpr const value_type* data() const noexcept(true) { return nullptr; }
    constexpr std::size_t size() const noexcept(true) { return 0; }
};
struct payload_monostate {
    using value_type = unsigned char;
    constexpr unsigned char* data() noexcept(true) { return nullptr; }
    constexpr std::size_t size() const noexcept(true) { return 0; }
};

template <typename... Ts>
inline std::vector<net::iovec_buffer>
create_iovec_vector(std::tuple<Ts...>& tp) {
    std::vector<net::iovec_buffer> _r;
    _r.reserve(sizeof...(Ts));
    std::apply(
        [&](const auto&... item) { (..., _r.emplace_back(net::buffer(item))); },
        tp);
    return std::move(_r);
}
template <typename... Ts>
inline std::vector<net::iovec_buffer> create_iovec_vector_ts(Ts&&... ts) {
    std::vector<net::iovec_buffer> _r;
    _r.reserve(sizeof...(Ts));
    (..., _r.emplace_back(net::buffer(ts)));
    return std::move(_r);
}
}  // namespace chx::http::detail
