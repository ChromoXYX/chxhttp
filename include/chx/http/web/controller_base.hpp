#pragma once

#include "../request.hpp"
#include "../response.hpp"
#include "./controller_context_base.hpp"

#include <chx/net/detail/tracker.hpp>
#include <functional>

namespace chx::http::web {
struct header_complete_args {
    response_type& resp;
    controller_context ctx;
};
struct data_block_args {
    response_type& resp;
};

class controller_base {
  public:
    virtual ~controller_base() = default;

    void
    on_header_complete(request_type& request, response_type& resp,
                       std::function<void(header_complete_args)>&& callback) {
        return do_on_header_complete(request, resp, std::move(callback));
    }

    void on_data_block(controller_context& session, request_type& request,
                       response_type& resp, const unsigned char* begin,
                       const unsigned char* end,
                       std::function<void(data_block_args)>&& callback) {
        return do_on_data_block(session, request, resp, begin, end,
                                std::move(callback));
    }

    void on_message_complete(controller_context& session, request_type& request,
                             response_type&& response) {
        return do_on_message_complete(session, request, std::move(response));
    }

    void on_destruct(controller_context& session) noexcept(true) {
        return do_on_destruct(session);
    }

  private:
    virtual void do_on_header_complete(
        request_type& request, response_type& resp,
        std::function<void(header_complete_args)>&& callback) {
        callback({resp, nullptr});
    }
    virtual void
    do_on_data_block(controller_context& session, request_type& request,
                     response_type& resp, const unsigned char* begin,
                     const unsigned char* end,
                     std::function<void(data_block_args)>&& callback) {
        callback({resp});
    }
    virtual void do_on_message_complete(controller_context& session,
                                        request_type& request,
                                        response_type&& response) = 0;

    virtual void do_on_destruct(controller_context& session) noexcept(true) {}
};
}  // namespace chx::http::web
