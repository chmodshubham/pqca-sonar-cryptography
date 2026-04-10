#include <openssl/evp.h>

void test_evp_mac() {
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "HMAC", NULL); // Noncompliant {{HMAC-MD5}}
}
