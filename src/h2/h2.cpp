#include "../info_type.hpp"
#include "../global_ctx.hpp"
#include "../global_conf.hpp"
#include "../global_timer.hpp"
#include "../tail_fn.hpp"
#include "./hpack.hpp"
#include "../log.hpp"
#include "./h2_log.hpp"
#include "../http_related/mime.hpp"
#include "../http_related/etag.hpp"

#include <chx/http/h2/async_http2.hpp>
#include <chx/net/file.hpp>
#include <chx/net/ssl/ssl.hpp>
#include <netinet/tcp.h>

namespace net = chx::net;
namespace http = chx::http;
namespace h2 = http::h2;
namespace log = chx::log;

using namespace std::literals;
using namespace log::literals;

class h2_session {
  public:
    struct stream_userdata_type : CHXNET_NONCOPYABLE {
        stream_userdata_type() : preq(new request_type) {}
        std::shared_ptr<request_type> preq;
    };

    const info_type& info;

    h2_session(const info_type& i) : info(i) {}

    template <typename Cntl>
    net::future<>
    cowork_sendfile(Cntl& cntl, net::file f, h2::stream_id_type strm_id,
                    std::string_view mime, const struct stat64& st,
                    std::shared_ptr<request_type> req) {
        if (!cntl.get_guard()) {
            co_return;
        }

        std::error_code e;
        std::size_t s = 0;

        h2::fields_type h;
        h.set_field("Server", "chxhttp.h2");
        h.set_field("Content-Length", log::format("%lu"_str, st.st_size));
        h.set_field("Content-Type", mime);
        log_norm_h2(*req, cntl.stream(), http::status_code::OK);
        if (st.st_size <= 2 * 1024 * 1024) {
            std::vector<unsigned char> buf(st.st_size);
            std::tie(e, s) = co_await f.async_read_some(
                net::buffer(buf),
                cntl.cntl().next_then(net::as_tuple(net::use_coro)));
            if (!cntl.get_guard()) {
                co_return;
            }
            if (!e) {
                co_return response_2xx(cntl, strm_id, http::status_code::OK,
                                       mime, std::move(buf));
            } else {
                co_return response_5xx(
                    cntl, strm_id, http::status_code::Internal_Server_Error);
            }
        } else {
            net::mapped_file mapped;
            mapped.map(f, st.st_size, PROT_READ, MAP_SHARED, 0, e);
            if (!e) {
                co_return response_2xx(cntl, strm_id, http::status_code::OK,
                                       mime, std::move(mapped));
            } else {
                log_warn_h2(
                    *req, cntl.stream(),
                    log::format("Failed to map file: %s"_str, e.message()));
                co_return response_5xx(
                    cntl, strm_id, http::status_code::Internal_Server_Error);
            }
        }
    }

    template <typename Cntl>
    net::task cowork(Cntl& cntl, h2::stream_id_type strm_id,
                     std::shared_ptr<request_type> req) {
        if (!cntl.get_guard()) [[unlikely]] {
            co_return;
        }

        std::error_code e;
        net::file file(global_ctx);
        file.openat(info.root, req->path.begin(), {.resolve = RESOLVE_IN_ROOT},
                    e);
        if (!e) {
            struct stat64 st = {};
            if (fstat64(file.native_handler(), &st) != 0) {
                log_warn_h2(
                    *req, cntl.stream(),
                    log::format("fstat64 failed: %s\n"_str, strerror(errno)));
                co_return response_5xx(
                    cntl, strm_id, http::status_code::Internal_Server_Error);
            }
            if (S_ISREG(st.st_mode)) {
                co_return co_await cowork_sendfile(
                    cntl, std::move(file), strm_id,
                    query_mime(
                        std::filesystem::path(req->path).extension().c_str()),
                    st, req);
            } else {
                log_norm_h2(*req, cntl.stream(), http::status_code::Forbidden);
                co_return response_4xx(cntl, strm_id,
                                       http::status_code::Forbidden);
            }
        } else {
            if (e == net::errc::no_such_file_or_directory) {
                log_norm_h2(*req, cntl.stream(), http::status_code::Not_Found);
                co_return response_4xx(cntl, strm_id,
                                       http::status_code::Not_Found);
            } else if (e == net::errc::cross_device_link) {
                log_norm_h2(*req, cntl.stream(), http::status_code::Forbidden);
                co_return response_4xx(cntl, strm_id,
                                       http::status_code::Forbidden);
            } else {
                log_norm_h2(*req, cntl.stream(),
                            http::status_code::Internal_Server_Error);
                co_return response_5xx(
                    cntl, strm_id, http::status_code::Internal_Server_Error);
            }
        }
    }

    template <typename Cntl>
    void work(Cntl& cntl, h2::stream_id_type strm_id,
              std::shared_ptr<request_type> req) {
        if (req->method != http::method_type::GET) [[unlikely]] {
            log_norm_h2(*req, cntl.stream(),
                        http::status_code::Not_Implemented);
            return response_5xx(cntl, strm_id,
                                http::status_code::Not_Implemented);
        }

        co_spawn(global_ctx, cowork(cntl, strm_id, req),
                 cntl.cntl().next_then([&cntl](const std::error_code& e) {
                     cntl.cntl().complete(e);
                 }));
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, h2::stream_id_type strm_id,
                    stream_userdata_type& strm,
                    h2::views::headers_type header_frame) {
        if (strm.preq.use_count() > 1) {
            __CHXHTTP_H2RT_THROW(h2::make_ec(h2::ErrorCodes::PROTOCOL_ERROR));
        }
        request_type& req = *strm.preq;
        req.fields = std::move(header_frame.fields);
        h2::fields_type& fields = req.fields;
        std::string_view psd_mth;
        if (auto ite = fields.find(":method"); ite != fields.end()) {
            psd_mth = ite->second;
        } else {
            return response_4xx(cntl, strm_id, http::status_code::Bad_Request);
        }
        if (psd_mth == "GET") {
            req.method = http::method_type::GET;
        } else if (psd_mth == "POST") {
            req.method = http::method_type::POST;
        } else if (psd_mth == "HEAD") {
            req.method = http::method_type::HEAD;
        } else if (psd_mth == "PUT") {
            req.method = http::method_type::PUT;
        } else if (psd_mth == "DELETE") {
            req.method = http::method_type::DELETE;
        } else if (psd_mth == "CONNECT") {
            req.method = http::method_type::CONNECT;
        } else if (psd_mth == "OPTIONS") {
            req.method = http::method_type::OPTIONS;
        } else if (psd_mth == "TRACE") {
            req.method = http::method_type::TRACE;
        } else {
            return response_4xx(cntl, strm_id, http::status_code::Bad_Request);
        }
        if (req.method != http::method_type::CONNECT) {
            if (auto ite = fields.find(":scheme"); ite != fields.end()) {
                req.scheme = ite->second;
            } else {
                log_norm_h2(req, cntl.stream(), http::status_code::Bad_Request);
                return response_4xx(cntl, strm_id,
                                    http::status_code::Bad_Request);
            }
            if (auto ite = fields.find(":path"); ite != fields.end()) {
                req.path = ite->second;
            } else {
                log_norm_h2(req, cntl.stream(), http::status_code::Bad_Request);
                return response_4xx(cntl, strm_id,
                                    http::status_code::Bad_Request);
            }
        }
        if (auto ite = fields.find(":authority"); ite != fields.end()) {
            req.authority = ite->second;
        } else {
            log_norm_h2(req, cntl.stream(), http::status_code::Bad_Request);
            return response_4xx(cntl, strm_id, http::status_code::Bad_Request);
        }
        if (header_frame.get_END_STREAM()) {
            work(cntl, strm_id, strm.preq);
        }
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, h2::stream_id_type strm_id,
                    stream_userdata_type& strm,
                    h2::views::data_type data_frame) {
        if (strm.preq.use_count() > 1) {
            __CHXHTTP_H2RT_THROW(h2::make_ec(h2::ErrorCodes::PROTOCOL_ERROR));
        }
        bool is_END_STREAM = data_frame.get_END_STREAM();
        request_type& req = *strm.preq;
        if (!ignore_DATA_frame(strm)) {
            if (auto ite = req.fields.find("content-length");
                ite != req.fields.end()) {
                std::size_t content_length = 0;
                std::from_chars_result r = std::from_chars(
                    ite->second.c_str(),
                    ite->second.c_str() + ite->second.size(), content_length);
                if (r.ptr != ite->second.c_str() + ite->second.size())
                    [[unlikely]] {
                    log_norm_h2(req, cntl.stream(),
                                http::status_code::Bad_Request);
                    return response_4xx(cntl, strm_id,
                                        http::status_code::Bad_Request);
                }
                std::size_t recv_len = data_frame.end() - data_frame.begin();
                for (auto& v : req.payload) {
                    recv_len += v.size();
                }
                if (recv_len > content_length) [[unlikely]] {
                    log_norm_h2(req, cntl.stream(),
                                http::status_code::Bad_Request);
                    return response_4xx(cntl, strm_id,
                                        http::status_code::Bad_Request);
                }
            }
            if (data_frame.get_PADDED()) {
                req.payload.emplace_back(data_frame.begin(), data_frame.end());
            } else {
                req.payload.emplace_back(std::move(data_frame.payload));
            }
        }
        if (is_END_STREAM) {
            work(cntl, strm_id, strm.preq);
        }
    }

    template <typename Cntl, typename... Ts>
    static void response_2xx(Cntl& cntl, h2::stream_id_type strm_id,
                             http::status_code code, std::string_view mime,
                             Ts&&... ts) {
        h2::fields_type fields;
        fields.set_field(
            ":status",
            log::format(CHXLOG_STR("%u"), static_cast<unsigned int>(code)));
        fields.set_field("server", "chxhttp.h2");
        if constexpr (sizeof...(Ts)) {
            fields.set_field(
                "content-length",
                log::format(CHXLOG_STR("%lu"), (... + net::buffer(ts).size())));
            fields.set_field("content-type", mime);
        }
        cntl.create_HEADER_frame(h2::frame_type::NO_FLAG, strm_id, fields);
        cntl.create_DATA_frame(h2::frame_type::END_STREAM, strm_id,
                               std::forward<Ts>(ts)...);
        cntl.do_send();
    }

    template <typename Cntl>
    static void response_4xx(Cntl& cntl, h2::stream_id_type strm_id,
                             http::status_code code) {
        h2::fields_type fields;
        fields.set_field(
            ":status",
            log::format(CHXLOG_STR("%u"), static_cast<unsigned int>(code)));
        fields.set_field("server", "chxhttp.h2");
        cntl.create_HEADER_frame(h2::frame_type::END_STREAM, strm_id, fields);
        cntl.create_RST_STREAM_frame(strm_id, h2::ErrorCodes::NO_ERROR);
        cntl.do_send();
    }

    template <typename Cntl>
    static void response_5xx(Cntl& cntl, h2::stream_id_type strm_id,
                             http::status_code sc) {
        h2::fields_type fields;
        fields.set_field(":status", log::format(CHXLOG_STR("%u"),
                                                static_cast<unsigned int>(sc)));
        fields.set_field("server", "chxhttp.h2");
        cntl.create_HEADER_frame(h2::frame_type::END_STREAM, strm_id, fields);
        cntl.h2_shutdown_recv(h2::ErrorCodes::INTERNAL_ERROR);
        cntl.do_send();
    }

    bool ignore_DATA_frame(const stream_userdata_type& strm) noexcept(true) {
        return strm.preq->method != http::method_type::POST;
    }
};

struct h2_ssl_operation {
    const info_type& info;

    struct handshake {};
    struct handshake_timeout {};
    struct http_ {};

    template <typename CntlType> using rebind = h2_ssl_operation;

    h2_ssl_operation(const info_type& i, net::ssl::context& ssl_ctx,
                     net::ip::tcp::socket&& sock)
        : info(i), stream(ssl_ctx, std::move(sock)) {}

    net::ssl::stream<net::ip::tcp::socket> stream;
    net::cancellation_signal cncl_cgnl;

    template <typename Cntl> void operator()(Cntl& cntl) {
        global_timer.async_register(
            3s,
            bind_cancellation_signal(
                cncl_cgnl, cntl.template next_with_tag<handshake_timeout>()));
        stream.async_do_handshake(cntl.template next_with_tag<handshake>());
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, handshake) {
        cncl_cgnl.emit();
        if (!e) {
            h2::async_http2(stream, std::make_unique<h2_session>(info),
                            hpack_nghttp2{4096}, global_timer,
                            cntl.template next_with_tag<http_>());
        }
        cntl.complete(e);
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, handshake_timeout) {
        if (!e) {
            stream.cancel();
        }
        cntl.complete(e);
    }

    template <typename Cntl>
    void operator()(Cntl& cntl, const std::error_code& e, http_) {
        cntl.complete(e);
    }
};

struct h2_server {
    info_type info;
    net::ip::tcp::acceptor acceptor;
    net::ssl::context ssl_context;

    h2_server(net::io_context& ctx, const net::ip::tcp::endpoint& ep,
              const global_conf::server_conf& c)
        : info{net::file{global_ctx, c.root_dir, O_DIRECTORY}, c},
          acceptor(ctx, ep), ssl_context(ssl_context.tls_server) {
        assert(info.conf.ssl_conf.enable);
        ssl_context.use_certificate_chain_file(
            info.conf.ssl_conf.certificate.c_str());
        ssl_context.use_PrivateKey_file(
            info.conf.ssl_conf.certificate_key.c_str(), ssl_context.pem);
        ssl_context.set_min_proto_version(ssl_context.tls1_2);
        ssl_context.set_max_proto_version(ssl_context.tls1_2);
        ssl_context.set_options(SSL_OP_ENABLE_KTLS);
        ssl_context.set_alpn_select_cb(
            [](const std::vector<std::string_view>& alpn) -> std::string_view {
                static constexpr char __h2_alpn[] = {2, 'h', '2'};
                static constexpr std::string_view __h2_alpn_sv{__h2_alpn, 3};
                if (std::find(alpn.begin(), alpn.end(), __h2_alpn_sv) !=
                    alpn.end()) {
                    return __h2_alpn_sv;
                } else {
                    return {};
                }
            });
        this->do_accept();
    }

    void do_accept() {
        acceptor.async_accept(
            [&](const std::error_code& e, net::ip::tcp::socket sock) {
                if (!e) {
                    sock.set_option(IPPROTO_TCP, TCP_NODELAY, true);
                    ++tail_fn.cnt;
                    sock.set_option(SOL_TCP, TCP_ULP, "tls");
                    net::async_combine_reference_count<const std::error_code&>(
                        global_ctx, tail_fn,
                        net::detail::type_identity<h2_ssl_operation>{}, info,
                        ssl_context, std::move(sock));
                }
                do_accept();
            });
    }
};

static std::vector<std::unique_ptr<struct h2_server>> h2_srv_list;

std::size_t boot_h2() {
    for (const auto& s : global_conf.server_list) {
        if (s.http_version == 2) {
            for (const auto& ep : s.listen_list) {
                h2_srv_list.emplace_back(new h2_server(global_ctx, ep, s));
                log_norm(CHXLOG_STR("Start listening on %s:%u, root %s\n"),
                         ep.address().to_string(), ep.port(), s.root_dir);
            }
        }
    }
    return h2_srv_list.size();
}