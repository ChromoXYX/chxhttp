#pragma once

#include <chx/net/coroutine2.hpp>
#include <chx/http/request.hpp>
#include <chx/http/response.hpp>
#include "../info_type.hpp"

chx::net::future<>
static_file_service(chx::http::request_type request,
                    std::unique_ptr<chx::http::response> response,
                    const info_type& info);
