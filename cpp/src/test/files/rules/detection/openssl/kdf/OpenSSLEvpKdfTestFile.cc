#include <openssl/kdf.h>

void test_evp_kdf() {
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "PBKDF2", NULL); // Noncompliant {{PBKDF2-HMAC-SHA1}}
}
