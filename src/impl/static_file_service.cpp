#include "./static_file_service.hpp"

#include "../http_related/etag.hpp"
#include "../http_related/mime.hpp"

#include <filesystem>
#include <chx/net/file.hpp>
#include <chx/net/error_code.hpp>

namespace net = chx::net;
namespace http = chx::http;

net::future<> static_file_service(chx::http::request_type request,
                                  std::unique_ptr<chx::http::response> response,
                                  const info_type& info) {
    http::fields_type fields;
    fields["server"] = "chxhttp";
    if (request.method != http::method_type::GET) {
        co_return response->end(http::status_code::Forbidden,
                                std::move(fields));
    }

    net::file f(co_await net::this_context);
    std::error_code e;
    f.openat(info.root_fd, request.request_target.c_str(),
             {.resolve = RESOLVE_IN_ROOT}, e);
    if (e) {
        if (e == net::errc::no_such_file_or_directory) {
            co_return response->end(http::status_code::Not_Found,
                                    std::move(fields));
        } else {
            __CHXNET_THROW_EC(e);
        }
    }

    std::string_view request_target = request.request_target;
    struct stat64 st = {};
    if (fstat64(f.native_handler(), &st)) {
        __CHXNET_THROW_STR("fstat64 failed");
    }
    if (S_ISDIR(st.st_mode)) {
        st = {};
        std::error_code e = net::make_ec(net::errc::no_such_file_or_directory);
        for (const auto& i : info.conf.index_list) {
            f.openat(f, i.c_str(), {.resolve = RESOLVE_IN_ROOT}, e);
            if (!e) {
                request_target = i;
                break;
            }
        }
        if (!e) {
            if (fstat64(f.native_handler(), &st)) {
                __CHXNET_THROW_STR("fstat64 failed");
            }
        } else {
            co_return response->end(http::status_code::Forbidden,
                                    std::move(fields));
        }
    } else if (!S_ISREG(st.st_mode)) {
        co_return response->end(http::status_code::Forbidden,
                                std::move(fields));
    }

    // content-type
    fields["content-type"] =
        query_mime(std::filesystem::path(request_target).extension().string());

    // etag
    const std::string etag_ = etag(st.st_mtim);
    fields["etag"] = etag_;
    if (request.fields.exactly_contains("if-non-match", etag_)) {
        co_return response->end(http::status_code::Not_Modified,
                                std::move(fields));
    }
    std::size_t file_sz = st.st_size;
    net::mapped_file mapped;
    mapped.map(f, file_sz, PROT_READ, MAP_SHARED, 0);
    co_return response->end(http::status_code::OK, std::move(fields),
                            std::move(mapped), file_sz);
}
