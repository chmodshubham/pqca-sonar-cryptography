#include <openssl/dh.h>

void test_legacy_dh() {
    DH* dh = NULL;
    BIGNUM* pub = NULL;
    unsigned char key[256];
    int codes = 0;

    DH_new();
    DH_generate_parameters_ex(dh, 2048, 2, NULL);
    DH_generate_key(dh);
    DH_check(dh, &codes);
    DH_check_params_ex(dh);
    DH_check_ex(dh);
    DH_check_pub_key_ex(dh, pub);

    DH_compute_key(key, pub, dh);
    DH_compute_key_padded(key, pub, dh);

    DH_get_1024_160();
    DH_get_2048_224();
    DH_get_2048_256();

    DH_size(dh);
    DH_bits(dh);
    DH_security_bits(dh);
}
