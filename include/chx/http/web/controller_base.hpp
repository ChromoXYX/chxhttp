#pragma once

#include "../request.hpp"
#include "../response.hpp"
#include "./controller_context_base.hpp"

namespace chx::http::web {
class controller_base {
  public:
    virtual ~controller_base() = default;

    virtual std::shared_ptr<controller_context_base>
    on_header_complete(request_type& request, response& resp) {
        return nullptr;
    }
    virtual void
    on_data_block(const std::shared_ptr<controller_context_base>& session,
                  request_type& request, response& resp,
                  const unsigned char* begin, const unsigned char* end) {}
    virtual void
    on_message_complete(const std::shared_ptr<controller_context_base>& session,
                        request_type& request, response&& response) = 0;
};

template <typename Fn>
std::unique_ptr<controller_base> create_simple_controller(Fn&& fn) {
    using base_fn = std::remove_reference_t<Fn>;
    class __impl : protected base_fn, public controller_base {
      public:
        __impl(Fn&& fn) : base_fn(std::forward<Fn>(fn)) {}

        void on_message_complete(controller_context_base* session,
                                 request_type& request,
                                 response&& response) override {
            static_cast<Fn&&>(static_cast<base_fn&>(*this))(
                request, std::move(response));
        }
    };
    return std::make_unique<__impl>(std::forward<Fn>(fn));
}
}  // namespace chx::http::web
