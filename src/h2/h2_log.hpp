#pragma once

#include "./h2.hpp"

#include <chx/net/tcp.hpp>
#include <chx/http/h2/types.hpp>
#include <chx/http/status_code.hpp>

void log_norm_h2(const request_type& req, const chx::net::ip::tcp::socket& sock,
                 chx::http::status_code st);

void log_warn_h2(const request_type& req, const chx::net::ip::tcp::socket& sock,
                 std::string_view what);
