#include <openssl/dsa.h>

void test_legacy_dsa() {
    DSA* dsa = NULL;
    BN_CTX* ctx = NULL;
    unsigned char buf[32];
    unsigned int siglen = 0;

    // Rule-class registration order
    DSA_new();
    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);

    DSA_sign(0, buf, 32, buf, &siglen, dsa);
    DSA_sign_setup(dsa, ctx, NULL, NULL);
    DSA_verify(0, buf, 32, buf, 32, dsa);
    DSA_do_sign(buf, 32, dsa);
    DSA_do_verify(buf, 32, NULL, dsa);

    DSA_size(dsa);
    DSA_bits(dsa);
    DSA_security_bits(dsa);

    DSA_dup_DH(dsa);
}
