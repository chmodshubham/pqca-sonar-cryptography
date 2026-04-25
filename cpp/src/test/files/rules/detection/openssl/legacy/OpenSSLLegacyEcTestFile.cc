#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>

void test_legacy_ec() {
    EC_KEY* key = NULL;
    EC_GROUP* grp = NULL;
    EC_POINT* pt = NULL;
    BIGNUM* bn = NULL;
    BN_CTX* ctx = NULL;
    ECDSA_SIG* sig = NULL;
    unsigned char buf[64];
    unsigned int siglen = 0;

    EC_KEY_new();
    EC_KEY_new_by_curve_name(415);
    EC_KEY_generate_key(key);
    EC_KEY_check_key(key);
    EC_KEY_set_public_key(key, pt);
    EC_KEY_set_private_key(key, bn);

    ECDSA_sign(0, buf, 32, buf, &siglen, key);
    ECDSA_verify(0, buf, 32, buf, 32, key);
    ECDSA_do_sign(buf, 32, key);
    ECDSA_do_verify(buf, 32, sig, key);
    ECDSA_sign_setup(key, ctx, NULL, NULL);
    ECDSA_sign_ex(0, buf, 32, buf, &siglen, bn, bn, key);
    ECDSA_do_sign_ex(buf, 32, bn, bn, key);
    ECDSA_size(key);

    ECDH_compute_key(buf, 32, pt, key, NULL);

    EC_GROUP_new_by_curve_name(415);
    EC_GROUP_new_curve_GFp(bn, bn, bn, ctx);
    EC_GROUP_new_curve_GF2m(bn, bn, bn, ctx);

    EC_POINT_new(grp);
    EC_POINT_mul(grp, pt, bn, pt, bn, ctx);
}
