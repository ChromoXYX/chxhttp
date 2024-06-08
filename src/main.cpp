#include <chx/http/async_http.hpp>
#include <chx/http/h2/async_http2.hpp>
#include <chx/net.hpp>

#include "./global_timer.hpp"
#include "./global_conf.hpp"
#include "./global_ctx.hpp"
#include "./log.hpp"
#include "./h1_1.hpp"
#include "./h2/h2.hpp"

namespace net = chx::net;
using namespace chx::log::literals;
using namespace std::literals;

int main(int argc, char** argv) {
    try {
        signal(SIGPIPE, SIG_IGN);
        application_init(argc, argv);

        net::signal sig(global_ctx);

        std::size_t outstanding_cnt = boot_h1() + boot_h2();
        if (outstanding_cnt) {
            sig.add(SIGINT);
            sig.async_wait([&](const std::error_code& e, int sig) {
                log_warn("Server stopping...\n"_str);
                global_ctx.stop();
                terminate_log_backend();
            });
            global_timer.set_interval(100ms);
            global_timer.listen();
        } else {
            log_norm("No active server\n"_str);
            terminate_log_backend();
        }
        global_ctx.run();
    } catch (const net::exception& e) {
        log_fatal_direct("chx::net::exception: %s\n"_str, e.what());
    } catch (const std::exception& e) {
        log_fatal_direct("std::exception: %s\n"_str, e.what());
    }
}
