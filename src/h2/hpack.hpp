#pragma once

#include <cstdint>
#include <chx/net/detail/noncopyable.hpp>
#include <chx/http/h2/error_codes.hpp>
#include <chx/http/h2/types.hpp>
#include <chx/http/header.hpp>
#include <nghttp2/nghttp2.h>

class hpack_nghttp2 : CHXNET_NONCOPYABLE {
  public:
    hpack_nghttp2(std::size_t header_table_size);
    hpack_nghttp2(hpack_nghttp2&& other) noexcept(true);
    ~hpack_nghttp2() noexcept(true);

    void decode(const unsigned char* begin, std::size_t len,
                chx::http::h2::fields_type& fields);
    void decode_block(const unsigned char* begin, std::size_t len, bool final,
                      chx::http::h2::fields_type& fields);
    void encode(const chx::http::h2::fields_type& fields,
                std::vector<unsigned char>& out);

    void decoder_set_header_table_size(std::uint32_t value);
    void encoder_set_header_table_size(std::uint32_t value);
    // chx::http::h2::ErrorCodes set_max_header_list_size(std::uint32_t value);

  protected:
    nghttp2_hd_inflater* __M_inflater = nullptr;
    nghttp2_hd_deflater* __M_deflater = nullptr;
};