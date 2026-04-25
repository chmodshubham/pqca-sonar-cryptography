#include <openssl/evp.h>

void test_evp_keygen() {
    EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pkey = NULL;

    EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-512", NULL);

    EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, 2048);

    EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, 2048);

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, 415);

    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);

    EVP_PKEY_keygen(ctx, &pkey);

    EVP_PKEY_keygen_init(ctx);
}
