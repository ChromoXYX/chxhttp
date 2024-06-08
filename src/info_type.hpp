#pragma once

#include "./global_conf.hpp"
#include <chx/net/file.hpp>

struct info_type {
    chx::net::file root;
    const global_conf::server_conf& conf;
};