#include <openssl/evp.h>

void test_evp_cipher() {
    const EVP_CIPHER *cipher = EVP_aes_256_gcm(); // Noncompliant {{AES-256-GCM}}
}
