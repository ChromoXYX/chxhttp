#include "./sha256.hpp"
#include <openssl/evp.h>

int utility::sha256(const unsigned char* input, std::size_t input_size,
                    unsigned char* output,
                    std::size_t& output_size) noexcept(true) {
    return EVP_Q_digest(nullptr, "SHA2-256", "provider=default", input,
                        input_size, output, &output_size);
}
