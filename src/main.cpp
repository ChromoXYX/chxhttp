#include <chx/http/async_http.hpp>
#include <chx/http/h2/async_http2.hpp>
#include <chx/net.hpp>

#include "./global_ctx.hpp"
#include "./global_timer.hpp"
#include "./impl/server.hpp"
#include "./global_conf.hpp"
#include "./log.hpp"

namespace net = chx::net;
using namespace chx::log::literals;
using namespace std::literals;

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);

    application_init(argc, argv);

    net::signal sig(global_ctx);
    sig.add(SIGINT);
    sig.async_wait([](const std::error_code& e, int) {
        if (!e) {
            printf("Exit...\n");
            global_ctx.stop();
            terminate_log_backend();
        }
    });

    boot_h11();

    global_timer.listen();
    global_ctx.run();
}
