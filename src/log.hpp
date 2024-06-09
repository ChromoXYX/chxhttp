#pragma once

#include <chx/log.hpp>
#include <chx/log/chrono.hpp>
#include <chx/net.hpp>
#include <chx/http/request.hpp>
#include <chx/http/status_code.hpp>

void set_log_sink(int fd) noexcept(true);
int get_log_sink() noexcept(true);
void log_backend(std::string&& str);
void terminate_log_backend() noexcept(true);
std::string get_remote_address(const chx::net::ip::tcp::socket& sock);

template <char... Cs, typename... Rs>
void log_info(chx::log::string<Cs...> str, Rs&&... rs) {
    log_backend(chx::log::format(concat(CHXLOG_STR("[%:%F %T:C][Info]"), str),
                                 std::chrono::system_clock::now(),
                                 std::forward<Rs>(rs)...));
}

template <char... Cs, typename... Rs>
void log_norm(chx::log::string<Cs...> str, Rs&&... rs) {
    log_backend(chx::log::format(concat(CHXLOG_STR("[%:%F %T:C][Norm]"), str),
                                 std::chrono::system_clock::now(),
                                 std::forward<Rs>(rs)...));
}

template <char... Cs, typename... Rs>
void log_warn(chx::log::string<Cs...> str, Rs&&... rs) {
    log_backend(chx::log::format(concat(CHXLOG_STR("[%:%F %T:C][Warn]"), str),
                                 std::chrono::system_clock::now(),
                                 std::forward<Rs>(rs)...));
}

template <char... Cs, typename... Rs>
void log_error(chx::log::string<Cs...> str, Rs&&... rs) {
    log_backend(chx::log::format(concat(CHXLOG_STR("[%:%F %T:C][Error]"), str),
                                 std::chrono::system_clock::now(),
                                 std::forward<Rs>(rs)...));
}

template <char... Cs, typename... Rs>
void log_info_direct(chx::log::string<Cs...> str, Rs&&... rs) {
    chx::log::fprintf(stderr, concat(CHXLOG_STR("[%:%F %T:C][Info]"), str),
                      std::chrono::system_clock::now(),
                      std::forward<Rs>(rs)...);
}

template <char... Cs, typename... Rs>
void log_norm_direct(chx::log::string<Cs...> str, Rs&&... rs) {
    chx::log::fprintf(stderr, concat(CHXLOG_STR("[%:%F %T:C][Norm]"), str),
                      std::chrono::system_clock::now(),
                      std::forward<Rs>(rs)...);
}

template <char... Cs, typename... Rs>
void log_warn_direct(chx::log::string<Cs...> str, Rs&&... rs) {
    chx::log::fprintf(stderr, concat(CHXLOG_STR("[%:%F %T:C][Warn]"), str),
                      std::chrono::system_clock::now(),
                      std::forward<Rs>(rs)...);
}

template <char... Cs, typename... Rs>
void log_error_direct(chx::log::string<Cs...> str, Rs&&... rs) {
    chx::log::fprintf(stderr, concat(CHXLOG_STR("[%:%F %T:C][Error]"), str),
                      std::chrono::system_clock::now(),
                      std::forward<Rs>(rs)...);
}

template <char... Cs, typename... Rs>
void log_fatal_direct(chx::log::string<Cs...> str, Rs&&... rs) {
    chx::log::fprintf(stderr, concat(CHXLOG_STR("[%:%F %T:C][Fatal]"), str),
                      std::chrono::system_clock::now(),
                      std::forward<Rs>(rs)...);
    terminate_log_backend();
}

void log_norm_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   chx::http::status_code st);

void log_warn_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   std::string_view what);

void log_warn_resp(const chx::http::request_type& req,
                   const chx::net::ip::tcp::socket& sock,
                   chx::http::status_code st, std::string_view what);
