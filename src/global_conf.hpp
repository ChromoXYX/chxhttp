#pragma once

#include <vector>
#include <string>
#include <chx/net/tcp.hpp>

struct global_conf {
    struct server_conf {
        int http_version = 1;
        std::vector<std::string> server_name;

        std::string root_dir = "/var/www/html";
        std::vector<std::string> index_list;

        std::vector<chx::net::ip::tcp::endpoint> listen_list;

        struct {
            bool enable = false;
            std::string certificate;
            std::string certificate_key;
        } ssl_conf;
    };
    std::vector<server_conf> server_list;

    struct {
        std::size_t page_size = {};
    } os;
} inline global_conf;

void application_init(int argc, char** argv);
