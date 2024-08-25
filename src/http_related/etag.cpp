#include "./etag.hpp"

#include <chx/log.hpp>

std::string etag(const struct timespec& ts) {
    return chx::log::format(CHXLOG_STR("W/\"%:x:ld-%:x:ld\""), ts.tv_sec,
                            ts.tv_nsec);
}

bool if_none_match(const chx::http::fields_type& fields,
                   std::string_view true_tag) {
    if (auto ite = fields.find("if-none-match"); ite != fields.end()) {
        std::string_view sv = ite->second;
        if (sv != "*") {
            while (!sv.empty()) {
                std::size_t delim = sv.find(", ");
                if (sv.substr(0, delim) == true_tag) {
                    return false;
                }
                if (delim != sv.npos) {
                    sv.remove_prefix(delim + 2);
                } else {
                    return true;
                }
            }
            return true;
        }
        return false;
    } else {
        return true;
    }
}