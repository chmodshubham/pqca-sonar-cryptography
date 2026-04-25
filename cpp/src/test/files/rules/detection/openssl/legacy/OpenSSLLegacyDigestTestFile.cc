#include <openssl/md5.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

void test_legacy_digest() {
    MD5_CTX mc;
    SHA_CTX s1;
    SHA256_CTX s2;
    SHA512_CTX s5;
    RIPEMD160_CTX r;
    unsigned char buf[64];

    MD5_Init(&mc);
    MD5_Update(&mc, buf, 64);
    MD5_Final(buf, &mc);
    MD5(buf, 64, buf);

    SHA1_Init(&s1);
    SHA1_Update(&s1, buf, 64);
    SHA1_Final(buf, &s1);
    SHA1(buf, 64, buf);

    SHA224_Init(&s2);
    SHA224_Update(&s2, buf, 64);
    SHA224_Final(buf, &s2);
    SHA224(buf, 64, buf);

    SHA256_Init(&s2);
    SHA256_Update(&s2, buf, 64);
    SHA256_Final(buf, &s2);
    SHA256(buf, 64, buf);

    SHA384_Init(&s5);
    SHA384_Update(&s5, buf, 64);
    SHA384_Final(buf, &s5);
    SHA384(buf, 64, buf);

    SHA512_Init(&s5);
    SHA512_Update(&s5, buf, 64);
    SHA512_Final(buf, &s5);
    SHA512(buf, 64, buf);

    RIPEMD160_Init(&r);
    RIPEMD160_Update(&r, buf, 64);
    RIPEMD160_Final(buf, &r);
    RIPEMD160(buf, 64, buf);
}
