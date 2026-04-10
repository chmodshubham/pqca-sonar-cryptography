#include <openssl/evp.h>

void test_evp_cipher_fetch() {
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "AES-256-SIV", NULL); // Noncompliant {{AES-256-SIV}}
}
