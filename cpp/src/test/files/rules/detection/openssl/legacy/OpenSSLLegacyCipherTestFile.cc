#include <openssl/aes.h>

void test_legacy_cipher() {
    unsigned char userkey[16];
    AES_set_encrypt_key(userkey, 128, (AES_KEY *)0); // Noncompliant {{AES}}
}
