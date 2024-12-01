#pragma once

#include <type_traits>
#include <tuple>
#include <memory>
#include <vector>
#include <chx/net/iovec_buffer.hpp>

namespace chx::http::detail {
struct payload_storage {
    virtual ~payload_storage() = default;

    template <typename... Ts> auto static create(Ts&&... ts) {
        struct impl : payload_storage {
            impl(impl&&) = default;
            impl(Ts&&... ts) : data(std::forward<Ts>(ts)...) {}

            std::tuple<std::conditional_t<std::is_lvalue_reference_v<Ts&&>,
                                          Ts&&, std::remove_reference_t<Ts>>...>
                data;

            using data_len = std::integral_constant<std::size_t, sizeof...(Ts)>;
        };
        return std::make_unique<impl>(std::forward<Ts>(ts)...);
    }
};
struct payload_storage_wrapper {
    payload_storage_wrapper() = default;
    payload_storage_wrapper(payload_storage_wrapper&&) = default;
    template <typename T>
    payload_storage_wrapper(std::unique_ptr<T> ptr) : payload(std::move(ptr)) {}

    payload_storage_wrapper& operator=(payload_storage_wrapper&&) = default;

    std::unique_ptr<payload_storage> payload;

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
