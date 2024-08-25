#pragma once

#include "./global_conf.hpp"
#include <chx/net/file.hpp>

struct info_type {
    chx::net::file root_fd;
    std::string root_str;
    const global_conf::server_conf& conf;
};