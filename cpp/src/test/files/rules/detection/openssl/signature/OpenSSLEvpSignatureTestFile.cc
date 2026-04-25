#include <openssl/evp.h>

void test_evp_signature() {
    EVP_MD_CTX* ctx = NULL;
    EVP_PKEY_CTX* pctx = NULL;
    unsigned char buf[64];
    size_t len = 0;

    EVP_DigestSignInit(ctx, NULL, NULL, NULL, NULL);
    EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, NULL);

    EVP_DigestSign(ctx, buf, &len, buf, 64);
    EVP_DigestVerify(ctx, buf, 64, buf, 64);

    EVP_PKEY_sign(pctx, buf, &len, buf, 64);
    EVP_PKEY_verify(pctx, buf, 64, buf, 64);

    EVP_PKEY_CTX_set_rsa_padding(pctx, 6);
}
