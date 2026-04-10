#include <openssl/evp.h>

void test_evp_key_agreement() {
    EVP_PKEY_derive(NULL, NULL, NULL); // Noncompliant {{DH}}
}
