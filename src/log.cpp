#include "./log.hpp"

using namespace chx::log::literals;

void log_norm_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   chx::http::status_code st) {
    std::string_view ua;
    if (auto ite = req.fields.find("User-Agent"); ite != req.fields.end()) {
        ua = ite->second;
    }
    log_norm("%s %s %s \"%s\" %u\n"_str,
             sock.remote_endpoint().address().to_string(),
             chx::http::method_name(req.method), req.request_target, ua,
             static_cast<unsigned short>(st));
}

std::string get_remote_address(const chx::net::ip::tcp::socket& sock) {
    std::error_code e;
    auto remote_ep = sock.remote_endpoint(e);
    if (!e) {
        return remote_ep.address().to_string();
    } else {
        return "DISCONNECTED";
    }
}

void log_warn_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   std::string_view what) {
    std::string_view ua;
    if (auto ite = req.fields.find("User-Agent"); ite != req.fields.end()) {
        ua = ite->second;
    }

    log_warn("%s %s %s \"%s\" %s\n"_str, get_remote_address(sock),
             chx::http::method_name(req.method), req.request_target, ua, what);
}

void log_warn_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   chx::http::status_code st, std::string_view what) {
    std::string_view ua;
    if (auto ite = req.fields.find("User-Agent"); ite != req.fields.end()) {
        ua = ite->second;
    }
    log_warn("%s %s %s \"%s\" %u %s\n"_str, get_remote_address(sock),
             chx::http::method_name(req.method), req.request_target, ua,
             static_cast<unsigned short>(st), what);
}
