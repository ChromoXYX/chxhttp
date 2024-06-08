#include "./h2_log.hpp"
#include "../log.hpp"

namespace log = chx::log;
using namespace log::literals;

void log_norm_h2(const request_type& req, const chx::net::ip::tcp::socket& sock,
                 chx::http::status_code st) {
    std::string_view ua;
    if (auto ite = req.fields.find("user-agent"); ite != req.fields.end()) {
        ua = ite->second;
    }
    log_norm("%s %s %s \"%s\" %u\n"_str,
             sock.remote_endpoint().address().to_string(),
             chx::http::method_name(req.method), req.path, ua,
             static_cast<unsigned short>(st));
}

void log_warn_h2(const request_type& req, const chx::net::ip::tcp::socket& sock,
                 std::string_view what) {
    std::string_view ua;
    if (auto ite = req.fields.find("user-agent"); ite != req.fields.end()) {
        ua = ite->second;
    }

    log_warn("%s %s %s \"%s\" %s\n"_str, get_remote_address(sock),
             chx::http::method_name(req.method), req.path, ua, what);
}