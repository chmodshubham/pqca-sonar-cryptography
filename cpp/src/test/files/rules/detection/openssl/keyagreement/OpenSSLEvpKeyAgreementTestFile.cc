#include <openssl/evp.h>

void test_evp_key_agreement() {
    EVP_PKEY_CTX* ctx = NULL;
    unsigned char buf[256];
    size_t len = 0;

    // EVP_PKEY_derive → 5 KeyAgreementContext findings
    EVP_PKEY_derive(ctx, buf, &len);

    // CTX_new_id fires KeyGen (KeyContext) + KeyAgreement rules
    EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_CTX_new_id(EVP_PKEY_X448, NULL);

    // EVP_PKEY_encapsulate → 7 findings
    EVP_PKEY_encapsulate(ctx, buf, &len, buf, &len);

    // EVP_PKEY_decapsulate → 7 findings
    EVP_PKEY_decapsulate(ctx, buf, &len, buf, 256);
}
