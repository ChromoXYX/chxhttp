#include "./h1_1.hpp"
#include "./global_conf.hpp"
#include "./session.hpp"
#include "./tail_fn.hpp"

#include <chx/net/io_context.hpp>
#include <chx/net/file.hpp>
#include <chx/net/tcp.hpp>
#include <chx/net/ssl/ssl.hpp>
#include <netinet/tcp.h>

struct server {
    info_type info;

    net::ip::tcp::acceptor acceptor;
    net::ssl::context ssl_context;

    server(net::io_context& ctx, const net::ip::tcp::endpoint& ep,
           const global_conf::server_conf& c)
        : info{net::file{global_ctx, c.root_dir, O_DIRECTORY}, c},
          acceptor(ctx, ep), ssl_context(ssl_context.tls_server) {
        if (info.conf.ssl_conf.enable) {
            ssl_context.use_certificate_chain_file(
                info.conf.ssl_conf.certificate.c_str());
            ssl_context.use_PrivateKey_file(
                info.conf.ssl_conf.certificate_key.c_str(), ssl_context.pem);
            ssl_context.set_min_proto_version(ssl_context.tls1_2);
            ssl_context.set_max_proto_version(ssl_context.tls1_2);
            ssl_context.set_options(SSL_OP_ENABLE_KTLS);
            ssl_context.set_alpn_select_cb([](const std::vector<
                                               std::string_view>& alpn)
                                               -> std::string_view {
                static constexpr char __h1_alpn[] = {8,   'h', 't', 't', 'p',
                                                     '/', '1', '.', '1'};
                static constexpr std::string_view __h1_alpn_sv{__h1_alpn, 9};
                if (std::find(alpn.begin(), alpn.end(), __h1_alpn_sv) !=
                    alpn.end()) {
                    return __h1_alpn_sv;
                } else {
                    return {};
                }
            });
        }
    }
    void do_accept() {
        acceptor.async_accept([this](const std::error_code& e,
                                     net::ip::tcp::socket sock) {
            if (!e) {
                sock.set_option(IPPROTO_TCP, TCP_NODELAY, true);
                ++tail_fn.cnt;
                if (!info.conf.ssl_conf.enable) {
                    http::async_http(std::move(sock), session(info), tail_fn);
                } else {
                    sock.set_option(SOL_TCP, TCP_ULP, "tls");
                    net::async_combine_reference_count<const std::error_code&>(
                        global_ctx, tail_fn,
                        net::detail::type_identity<session::ssl_operation>{},
                        info, ssl_context, std::move(sock));
                }
            }
            do_accept();
        });
    }
};

static std::vector<std::unique_ptr<server>> h1_1_srv_list;

std::size_t boot_h1() {
    for (const auto& s : global_conf.server_list) {
        if (s.http_version == 1) {
            for (const auto& ep : s.listen_list) {
                h1_1_srv_list.emplace_back(new server(global_ctx, ep, s))
                    ->do_accept();
                log_norm(CHXLOG_STR("Start listening on %s:%u, root %s\n"),
                         ep.address().to_string(), ep.port(), s.root_dir);
            }
        }
    }
    return h1_1_srv_list.size();
}