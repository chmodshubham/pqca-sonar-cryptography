#include <openssl/evp.h>

void test_evp_keygen() {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(6, (ENGINE *)0); // Noncompliant {{RSA}}
}
