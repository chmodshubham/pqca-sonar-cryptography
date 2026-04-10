#include <openssl/rsa.h>

void test_legacy_rsa() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL); // Noncompliant {{RSA-2048}}
}
