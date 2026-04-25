#include <openssl/rsa.h>

void test_legacy_rsa() {
    RSA* rsa = NULL;
    BIGNUM* e = NULL;
    unsigned char buf[256];
    unsigned int len = 0;
    unsigned char em[256];
    unsigned char mhash[64];

    RSA_new();
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    RSA_generate_multi_prime_key(rsa, 2048, 3, e, NULL);

    RSA_public_encrypt(32, buf, buf, rsa, 1);
    RSA_private_decrypt(32, buf, buf, rsa, 1);

    RSA_sign(0, buf, 32, buf, &len, rsa);
    RSA_verify(0, buf, 32, buf, 32, rsa);
    RSA_sign_ASN1_OCTET_STRING(0, buf, 32, buf, &len, rsa);
    RSA_verify_ASN1_OCTET_STRING(0, buf, 32, buf, 32, rsa);

    RSA_private_encrypt(32, buf, buf, rsa, 1);
    RSA_public_decrypt(32, buf, buf, rsa, 1);

    RSA_check_key(rsa);
    RSA_check_key_ex(rsa, NULL);

    RSA_padding_add_PKCS1_PSS(rsa, em, mhash, NULL, 32);
    RSA_padding_add_PKCS1_PSS_mgf1(rsa, em, mhash, NULL, NULL, 32);
    RSA_verify_PKCS1_PSS(rsa, mhash, NULL, em, 32);
    RSA_verify_PKCS1_PSS_mgf1(rsa, mhash, NULL, NULL, em, 32);

    RSA_padding_add_PKCS1_OAEP(buf, 256, buf, 32, buf, 16);
    RSA_padding_add_PKCS1_OAEP_mgf1(buf, 256, buf, 32, buf, 16, NULL, NULL);
}
