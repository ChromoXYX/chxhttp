#pragma once

#include <string>
#include <time.h>

#include <chx/http/request.hpp>
#include <chx/net/file_descriptor.hpp>

std::string etag(const struct timespec& ts);
bool if_none_match(const chx::http::request_type& req, std::string_view etag);
