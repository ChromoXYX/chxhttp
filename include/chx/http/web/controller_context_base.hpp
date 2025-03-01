#pragma once

#include <cstdint>
#include <memory>
#include <variant>
#include <chx/net/detail/tracker.hpp>

namespace chx::http::web {
class controller_context_base {
  public:
    virtual ~controller_context_base() = default;
};

struct controller_context_trivial {
    union {
        void* ptr1;
        std::uint64_t v1;
    };
    union {
        void* ptr2;
        std::uint64_t v2;
    };
};

struct controller_context_anchor {
    union {
        void* ptr;
        std::uint64_t v;
    };
    net::detail::anchor anchor;
};

using controller_context =
    std::variant<std::shared_ptr<controller_context_base>,
                 controller_context_trivial, controller_context_anchor>;
}  // namespace chx::http::web
