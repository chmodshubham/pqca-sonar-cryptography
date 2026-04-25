#include <openssl/aes.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/des.h>
#include <openssl/idea.h>
#include <openssl/rc2.h>
#include <openssl/rc4.h>

void test_legacy_cipher() {
    unsigned char buf[64];
    unsigned char iv[16];
    int num = 0;
    unsigned int unum = 0;
    AES_KEY ak;
    DES_key_schedule ds;
    DES_cblock dc;
    BF_KEY bk;
    RC2_KEY r2;
    RC4_KEY r4;
    CAST_KEY ck;
    IDEA_KEY_SCHEDULE ik;

    // AES family
    AES_set_encrypt_key(buf, 128, &ak);
    AES_set_decrypt_key(buf, 128, &ak);
    AES_encrypt(buf, buf, &ak);
    AES_decrypt(buf, buf, &ak);
    AES_ecb_encrypt(buf, buf, &ak, 1);
    AES_cbc_encrypt(buf, buf, 64, &ak, iv, 1);
    AES_cfb128_encrypt(buf, buf, 64, &ak, iv, &num, 1);
    AES_ofb128_encrypt(buf, buf, 64, &ak, iv, &num);
    AES_ctr128_encrypt(buf, buf, 64, &ak, iv, iv, &unum);
    AES_ige_encrypt(buf, buf, 64, &ak, iv, 1);
    AES_wrap_key(&ak, iv, buf, buf, 64);
    AES_unwrap_key(&ak, iv, buf, buf, 64);

    // DES family
    DES_set_key(&dc, &ds);
    DES_set_key_checked(&dc, &ds);
    DES_set_key_unchecked(&dc, &ds);
    DES_ecb_encrypt(&dc, &dc, &ds, 1);
    DES_ncbc_encrypt(buf, buf, 64, &ds, &dc, 1);
    DES_cbc_encrypt(buf, buf, 64, &ds, &dc, 1);
    DES_cfb64_encrypt(buf, buf, 64, &ds, &dc, &num, 1);
    DES_cfb_encrypt(buf, buf, 8, 64, &ds, &dc, 1);
    DES_ofb64_encrypt(buf, buf, 64, &ds, &dc, &num);
    DES_ede3_cbc_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, 1);
    DES_ecb3_encrypt(&dc, &dc, &ds, &ds, &ds, 1);
    DES_ede3_cfb64_encrypt(buf, buf, 64, &ds, &ds, &ds, &dc, &num, 1);

    // Blowfish family
    BF_set_key(&bk, 16, buf);
    BF_ecb_encrypt(buf, buf, &bk, 1);
    BF_cbc_encrypt(buf, buf, 64, &bk, iv, 1);
    BF_cfb64_encrypt(buf, buf, 64, &bk, iv, &num, 1);
    BF_ofb64_encrypt(buf, buf, 64, &bk, iv, &num);

    // RC4
    RC4_set_key(&r4, 16, buf);
    RC4(&r4, 64, buf, buf);

    // RC2 family
    RC2_set_key(&r2, 16, buf, 128);
    RC2_ecb_encrypt(buf, buf, &r2, 1);
    RC2_cbc_encrypt(buf, buf, 64, &r2, iv, 1);
    RC2_cfb64_encrypt(buf, buf, 64, &r2, iv, &num, 1);
    RC2_ofb64_encrypt(buf, buf, 64, &r2, iv, &num);

    // CAST5 family
    CAST_set_key(&ck, 16, buf);
    CAST_ecb_encrypt(buf, buf, &ck, 1);
    CAST_cbc_encrypt(buf, buf, 64, &ck, iv, 1);
    CAST_cfb64_encrypt(buf, buf, 64, &ck, iv, &num, 1);
    CAST_ofb64_encrypt(buf, buf, 64, &ck, iv, &num);

    // IDEA family
    IDEA_set_encrypt_key(buf, &ik);
    IDEA_set_decrypt_key(&ik, &ik);
    IDEA_ecb_encrypt(buf, buf, &ik);
    IDEA_cbc_encrypt(buf, buf, 64, &ik, iv, 1);
    IDEA_cfb64_encrypt(buf, buf, 64, &ik, iv, &num, 1);
    IDEA_ofb64_encrypt(buf, buf, 64, &ik, iv, &num);
}
