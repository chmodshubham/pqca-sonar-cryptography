#include <openssl/ssl.h>

void test_ssl() {
    const SSL_METHOD *method = TLS_method(); // Noncompliant {{TLS}}
}
