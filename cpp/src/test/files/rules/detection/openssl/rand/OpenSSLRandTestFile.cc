#include <openssl/rand.h>

void test_rand() {
    unsigned char buf[32];
    RAND_bytes(buf, sizeof(buf)); // Noncompliant {{RAND}}
}
