#include <openssl/evp.h>

void test_legacy_digest() {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL); // Noncompliant {{SHA-256}}
}
