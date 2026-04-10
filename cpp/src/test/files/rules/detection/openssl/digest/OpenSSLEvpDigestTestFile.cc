#include <openssl/evp.h>

void test_evp_digest() {
    const EVP_MD *md = EVP_sha256(); // Noncompliant {{SHA-256}}
}
