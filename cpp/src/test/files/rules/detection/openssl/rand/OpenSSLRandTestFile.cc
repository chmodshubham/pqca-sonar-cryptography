#include <openssl/evp.h>
#include <openssl/rand.h>

void test_rand() {
    unsigned char buf[32];

    // Legacy RAND API (order matches OpenSSLRand.rules() registration)
    RAND_bytes(buf, 32);
    RAND_priv_bytes(buf, 32);
    RAND_pseudo_bytes(buf, 32);
    RAND_seed(buf, 32);
    RAND_add(buf, 32, 1.0);
    RAND_poll();

    // CTR-DRBG (fires AES128, AES192, AES256 variants in registration order)
    EVP_RAND_fetch(NULL, "CTR-DRBG", NULL);

    // HASH-DRBG (fires SHA1, SHA256, SHA384, SHA512)
    EVP_RAND_fetch(NULL, "HASH-DRBG", NULL);

    // HMAC-DRBG (fires SHA1, SHA256, SHA384, SHA512)
    EVP_RAND_fetch(NULL, "HMAC-DRBG", NULL);

    // Entropy sources
    EVP_RAND_fetch(NULL, "SEED-SRC", NULL);
    EVP_RAND_fetch(NULL, "JITTER", NULL);
    EVP_RAND_fetch(NULL, "TEST-RAND", NULL);
}
