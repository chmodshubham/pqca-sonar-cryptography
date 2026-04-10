#include <openssl/evp.h>

void test_evp_signature() {
    EVP_DigestSignInit(NULL, NULL, NULL, NULL, NULL); // Noncompliant {{RSA-SHA1}}
}
