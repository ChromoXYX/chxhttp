#include "./server.hpp"

#include "../global_ctx.hpp"
#include "../global_timer.hpp"
#include "../info_type.hpp"
#include "./static_file_service.hpp"

#include <chx/http/async_http.hpp>
#include <chx/net.hpp>
#include <vector>

namespace net = chx::net;
namespace http = chx::http;

struct h11_session {
    const info_type& info;

    void operator()(http::message_complete, http::request_type& req,
                    const http::response& resp) {
        resp.co_spawn(static_file_service(std::move(req), resp.copy(), info));
    }
};

struct h11_server {
    info_type info;
    net::ip::tcp::acceptor __M_acceptor;

    h11_server(const net::ip::tcp::endpoint& ep,
               const global_conf::server_conf& c)
        : info{net::file{global_ctx, c.root_dir, O_DIRECTORY}, c.root_dir, c},
          __M_acceptor(global_ctx, ep) {}

    void do_accept() {
        __M_acceptor.async_accept([this](const std::error_code& e,
                                         net::ip::tcp::socket sock) {
            if (!e) {
                http::async_http(
                    std::move(sock), h11_session{info}, global_timer,
                    [](const std::error_code& e) {
                        printf("Connection closed, %s, outstanding tasks %lu\n",
                               e.message().c_str(),
                               global_ctx.outstanding_tasks());
                    });
                do_accept();
            } else {
                __CHXNET_THROW_EC(e);
            }
        });
    }
};

static std::vector<std::unique_ptr<h11_server>> srv_list;

std::size_t boot_h11() {
    for (const auto& s : global_conf.server_list) {
        if (s.http_version == 1) {
            for (const auto& ep : s.listen_list) {
                srv_list.emplace_back(new h11_server(ep, s));
                srv_list.back()->do_accept();
            }
        }
    }
    return srv_list.size();
}