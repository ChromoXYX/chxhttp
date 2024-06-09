#pragma once

#include "../session.hpp"

net::future<bool> request_preprocess(session& ses, http::request_type& req,
                                     session::norm_conn_type& resp);
net::future<bool> request_preprocess(session& ses, http::request_type& req,
                                     session::ssl_conn_type& conn);

net::future<> static_file_find(session& ses, http::request_type& req,
                               session::norm_conn_type& conn);
net::future<> static_file_find(session& ses, http::request_type& req,
                               session::ssl_conn_type& conn);

net::future<> static_file_resp(session& ses, net::file f, std::string_view mime,
                               struct stat64 st, const http::request_type& req,
                               session::norm_conn_type& conn);
net::future<> static_file_resp(session& ses, net::file f, std::string_view mime,
                               struct stat64 st, const http::request_type& req,
                               session::ssl_conn_type& conn);
