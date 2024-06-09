#pragma once

#include "../session.hpp"
#include "../http_related/byte_range.hpp"

template <typename Conn>
void send_byte_range(session& ses, net::file f, std::string_view mime,
                     struct stat64 st, const http::request_type& req,
                     Conn& conn) {
    std::vector<std::pair<std::size_t, std::size_t>> range;
    http::fields_type h;
    h.add_field("Server", "chxhttp");
    if (!parse_byte_range(req.fields.find("range")->second, range) ||
        range.empty()) {
        h.add_field("Connection", "close");
        log_norm_resp(req, conn.stream(), http::status_code::Bad_Request);
        return conn.response(http::status_code::Bad_Request, h);
    }

    auto [begin, tail] = range.front();
    std::size_t len = tail - begin + 1;
    if (begin + len > st.st_size) {
        h.add_field("Connection", "close");
        log_norm_resp(req, conn.stream(),
                      http::status_code::Range_Not_Satisfiable);
        return conn.response(http::status_code::Range_Not_Satisfiable, h);
    }

    net::mapped_file mapped;
    std::error_code e;

    // mapped.map(f, len, PROT_READ, MAP_SHARED, 0, e);

    std::size_t true_begin =
        (begin / global_conf.os.page_size) * global_conf.os.page_size;
    std::size_t true_len = tail - true_begin + 1;
    mapped.map(f, true_len, PROT_READ, MAP_SHARED, true_begin, e);

    if (e) {
        log_warn_resp(
            req, conn.stream(),
            chx::log::format("Failed to map file: %s"_str, e.message()));
        return conn.response(http::status_code::Internal_Server_Error,
                             ses.ise_raw);
    }

    h.add_field("Content-Range", chx::log::format("bytes %lu-%lu/%lu"_str,
                                                  begin, tail, st.st_size));
    h.add_field("Content-Length", chx::log::format("%lu"_str, len));
    log_norm_resp(req, conn.stream(), http::status_code::Partial_Content);
    if (!conn.h11_would_close()) {
        ses.reset_timer(3s);
        h.add_field("Connection", "keep-alive");
        h.add_field("Keep-Alive", "timeout=3");
        return conn.response(
            http::status_code::Partial_Content, h,
            net::carrier{std::move(mapped), begin - true_begin, len});
    } else {
        h.add_field("Connection", "close");
        return conn.response(
            http::status_code::Partial_Content, h,
            net::carrier{std::move(mapped), begin - true_begin, len});
    }
}