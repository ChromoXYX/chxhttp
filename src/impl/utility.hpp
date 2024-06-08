#pragma once

#include "../session.hpp"

net::future<>
request_preprocess(session& ses, http::request_type& req,
                   http::response_type<session::norm_conn_type> resp);
net::future<>
request_preprocess(session& ses, http::request_type& req,
                   http::response_type<session::ssl_conn_type> resp);

net::future<>
static_file_find(session& ses, http::request_type& req,
                 http::response_type<session::norm_conn_type> resp);
net::future<>
static_file_find(session& ses, http::request_type& req,
                 http::response_type<session::ssl_conn_type> resp);

net::future<>
static_file_resp(session& ses, net::file f, std::string_view mime,
                 struct stat64 st, const http::request_type& req,
                 http::response_type<session::norm_conn_type> resp);
net::future<>
static_file_resp(session& ses, net::file f, std::string_view mime,
                 struct stat64 st, const http::request_type& req,
                 http::response_type<session::ssl_conn_type> resp);
