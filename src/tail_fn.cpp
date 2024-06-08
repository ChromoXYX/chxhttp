#include "./tail_fn.hpp"
#include "./global_ctx.hpp"
#include "./log.hpp"

using namespace chx::log::literals;
void tail_fn_t::operator()(const std::error_code& e) const {
    log_info("Session close, \"%s\", remain %lu, outstanding tasks %lu\n"_str,
             e.message(), --cnt, global_ctx.outstanding_tasks());
}
