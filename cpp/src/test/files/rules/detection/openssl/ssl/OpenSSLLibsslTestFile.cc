#include <openssl/prov_ssl.h>
#include <openssl/ssl.h>

void test_ssl() {
    SSL_CTX* ctx = NULL;
    SSL* s = NULL;
    unsigned long wrote = 0;
    unsigned char buf[64];

    // TLS generic
    TLS_method();
    TLS_client_method();
    TLS_server_method();

    // TLS 1.3
    TLSv1_3_method();
    TLSv1_3_client_method();
    TLSv1_3_server_method();

    // TLS 1.2
    TLSv1_2_method();
    TLSv1_2_client_method();
    TLSv1_2_server_method();

    // TLS 1.1
    TLSv1_1_method();
    TLSv1_1_client_method();
    TLSv1_1_server_method();

    // TLS 1.0
    TLSv1_method();
    TLSv1_client_method();
    TLSv1_server_method();

    // SSL 3.0
    SSLv3_method();
    SSLv3_client_method();
    SSLv3_server_method();

    // DTLS generic
    DTLS_method();
    DTLS_client_method();
    DTLS_server_method();

    // DTLS 1.2
    DTLSv1_2_method();
    DTLSv1_2_client_method();
    DTLSv1_2_server_method();

    // DTLS 1.0
    DTLSv1_method();
    DTLSv1_client_method();
    DTLSv1_server_method();

    // QUIC
    OSSL_QUIC_client_method();
    OSSL_QUIC_client_thread_method();
    OSSL_QUIC_server_method();

    // Context + cipher configuration
    SSL_CTX_new(NULL);
    SSL_CTX_set_cipher_list(ctx, "HIGH");
    SSL_set_cipher_list(s, "HIGH");
    SSL_CTX_set_ciphersuites(ctx, "TLS_AES_128_GCM_SHA256");
    SSL_set_ciphersuites(s, "TLS_AES_128_GCM_SHA256");

    // Protocol-version configuration
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Connection operations
    SSL_connect(s);
    SSL_accept(s);
    SSL_do_handshake(s);

    // TLS 1.3 Early Data
    SSL_write_early_data(s, buf, 64, &wrote);
    SSL_read_early_data(s, buf, 64, &wrote);
}
