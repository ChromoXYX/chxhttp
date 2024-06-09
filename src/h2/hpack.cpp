#include "./hpack.hpp"
#include "chx/http/h2/exception.hpp"
#include <chx/net/error_code.hpp>
#include <utility>

namespace http = chx::http;
namespace net = chx::net;
namespace h2 = http::h2;

hpack_nghttp2::hpack_nghttp2(std::size_t header_table_size) {
    auto r = nghttp2_hd_deflate_new(&__M_deflater, header_table_size);
    if (r != 0) [[unlikely]] {
        __CHXNET_THROW(net::errc::not_enough_memory);
    }
    r = nghttp2_hd_inflate_new(&__M_inflater);
    if (r != 0) [[unlikely]] {
        __CHXNET_THROW(net::errc::not_enough_memory);
    }
}

hpack_nghttp2::hpack_nghttp2(hpack_nghttp2&& other) noexcept(true)
    : __M_deflater(std::exchange(other.__M_deflater, nullptr)),
      __M_inflater(std::exchange(other.__M_inflater, nullptr)) {}

hpack_nghttp2::~hpack_nghttp2() noexcept(true) {
    if (__M_deflater) {
        nghttp2_hd_deflate_del(__M_deflater);
    }
    if (__M_inflater) {
        nghttp2_hd_inflate_del(__M_inflater);
    }
}

void hpack_nghttp2::decode(const unsigned char* begin, std::size_t len,
                           h2::fields_type& fields) {
    for (;;) {
        nghttp2_nv nv = {};
        int inflate_flags = 0;

        ssize_t rv = nghttp2_hd_inflate_hd2(__M_inflater, &nv, &inflate_flags,
                                            begin, len, 1);
        if (rv < 0) [[unlikely]] {
            switch (rv) {
            case nghttp2_error::NGHTTP2_ERR_HEADER_COMP: {
                __CHXHTTP_H2RT_THROW(
                    make_ec(h2::ErrorCodes::COMPRESSION_ERROR));
            }
            case nghttp2_error::NGHTTP2_ERR_BUFFER_ERROR: {
                __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::PROTOCOL_ERROR));
            }
            case nghttp2_error::NGHTTP2_ERR_NOMEM: {
                __CHXNET_THROW(net::errc::not_enough_memory);
            }
            default: {
                __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::INTERNAL_ERROR));
            }
            }
        }
        begin += rv;
        len -= rv;
        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            fields.add_field(std::string{(const char*)nv.name, nv.namelen},
                             std::string{(const char*)nv.value, nv.valuelen});
        }
        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            nghttp2_hd_inflate_end_headers(__M_inflater);
            break;
        }
        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && len == 0) {
            break;
        }
    }
    return;
}

void hpack_nghttp2::decode_block(const unsigned char* in, std::size_t inlen,
                                 bool final, h2::fields_type& fields) {
    for (;;) {
        nghttp2_nv nv = {};
        int inflate_flags = 0;

        ssize_t rv = ::nghttp2_hd_inflate_hd2(__M_inflater, &nv, &inflate_flags,
                                              in, inlen, final);
        if (rv < 0) [[unlikely]] {
            switch (rv) {
            case nghttp2_error::NGHTTP2_ERR_HEADER_COMP: {
                __CHXHTTP_H2RT_THROW(
                    make_ec(h2::ErrorCodes::COMPRESSION_ERROR));
            }
            case nghttp2_error::NGHTTP2_ERR_BUFFER_ERROR: {
                __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::PROTOCOL_ERROR));
            }
            case nghttp2_error::NGHTTP2_ERR_NOMEM: {
                __CHXNET_THROW(net::errc::not_enough_memory);
            }
            default: {
                return;
            }
            }
        }
        in += rv;
        inlen -= rv;
        if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
            fields.add_field(std::string{(const char*)nv.name, nv.namelen},
                             std::string{(const char*)nv.value, nv.valuelen});
        }
        if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
            if (!final) [[unlikely]] {
                __CHXHTTP_H2RT_THROW(
                    make_ec(h2::ErrorCodes::COMPRESSION_ERROR));
            }
            nghttp2_hd_inflate_end_headers(__M_inflater);
            break;
        }
        if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
            break;
        }
    }
    return;
}

void hpack_nghttp2::encode(const h2::fields_type& fields,
                           std::vector<unsigned char>& out) {
    std::vector<nghttp2_nv> nvs(fields.size());
    std::transform(fields.begin(), fields.end(), nvs.begin(),
                   [](const auto& pair) -> nghttp2_nv {
                       nghttp2_nv nv = {};
                       nv.name = (unsigned char*)pair.first.c_str();
                       nv.namelen = pair.first.size();
                       nv.value = (unsigned char*)pair.second.c_str();
                       nv.valuelen = pair.second.size();
                       return nv;
                   });
    out.resize(nghttp2_hd_deflate_bound(__M_deflater, nvs.data(), nvs.size()));
    ssize_t rv = nghttp2_hd_deflate_hd(__M_deflater, out.data(), out.size(),
                                       nvs.data(), nvs.size());
    if (rv >= 0) {
        out.resize(rv);
        return;
    } else {
        out.clear();
        __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::INTERNAL_ERROR));
    }
}

void hpack_nghttp2::decoder_set_header_table_size(std::uint32_t value) {
    if (nghttp2_hd_inflate_change_table_size(__M_inflater, value) == 0) {
        return;
    } else {
        __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::INTERNAL_ERROR));
    }
}
void hpack_nghttp2::encoder_set_header_table_size(std::uint32_t value) {
    if (nghttp2_hd_deflate_change_table_size(__M_deflater, value) == 0) {
        return;
    } else {
        __CHXHTTP_H2RT_THROW(make_ec(h2::ErrorCodes::INTERNAL_ERROR));
    }
}