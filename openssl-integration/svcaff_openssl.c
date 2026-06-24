/* Mainstream-stack interop for the service-affinity PoC using OpenSSL.
 *
 * Demonstrates the migration_support extension (0xFE4D) emitted/observed via
 * OpenSSL's public custom-extension API (SSL_CTX_add_custom_ext) -- no fork.
 *
 *   ./svcaff_openssl client HOST PORT          # emits migration_support
 *   ./svcaff_openssl server PORT CERT KEY      # observes migration_support
 *
 * migration_allowed (a NewSessionTicket extension) and migrate_request (a new
 * post-handshake message) are NOT done here: OpenSSL's custom-ext API does not
 * cover NST extensions or new handshake messages, which would need state-machine
 * changes. migration_support is the tractable mainstream-stack slice.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MIGRATION_SUPPORT 0xFE4D

static int add_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char **out, size_t *outlen,
                  X509 *x, size_t chainidx, int *al, void *arg)
{
    (void)s; (void)ext_type; (void)context; (void)x; (void)chainidx; (void)al; (void)arg;
    *out = NULL; /* empty extension body */
    *outlen = 0;
    return 1; /* 1 => include the extension */
}

static int parse_cb(SSL *s, unsigned int ext_type, unsigned int context, const unsigned char *in, size_t inlen,
                    X509 *x, size_t chainidx, int *al, void *arg)
{
    (void)s; (void)context; (void)in; (void)x; (void)chainidx; (void)al; (void)arg;
    if (ext_type == MIGRATION_SUPPORT)
        fprintf(stderr, "[openssl] observed migration_support (0x%04X) len=%zu\n", ext_type, inlen);
    return 1;
}

static SSL_CTX *make_ctx(int server)
{
    SSL_CTX *ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());
    if (ctx == NULL) { ERR_print_errors_fp(stderr); exit(1); }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (!server)
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); /* PoC: skip cert check */
    /* register migration_support so it is emitted (client) and parsed (server) */
    if (SSL_CTX_add_custom_ext(ctx, MIGRATION_SUPPORT, SSL_EXT_CLIENT_HELLO, add_cb, NULL, NULL, parse_cb, NULL) != 1) {
        fprintf(stderr, "SSL_CTX_add_custom_ext failed\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    return ctx;
}

static int do_client(const char *host, int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { perror("connect"); return 1; }

    SSL_CTX *ctx = make_ctx(0);
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, "svc.example");
    if (SSL_connect(ssl) != 1) { ERR_print_errors_fp(stderr); return 1; }
    fprintf(stderr, "[openssl-client] handshake OK (%s); emitted migration_support (0xFE4D)\n", SSL_get_version(ssl));
    /* close immediately, before reading any post-handshake messages */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(fd);
    SSL_CTX_free(ctx);
    return 0;
}

static int do_server(int port, const char *cert, const char *key)
{
    SSL_CTX *ctx = make_ctx(1);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) { perror("bind"); return 1; }
    listen(lfd, 5);
    fprintf(stderr, "[openssl-server] listening on 127.0.0.1:%d\n", port);
    for (;;) {
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) continue;
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, fd);
        if (SSL_accept(ssl) == 1)
            fprintf(stderr, "[openssl-server] handshake OK (%s)\n", SSL_get_version(ssl));
        else
            ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(fd);
    }
}

int main(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[1], "client") == 0)
        return do_client(argv[2], atoi(argv[3]));
    if (argc >= 5 && strcmp(argv[1], "server") == 0)
        return do_server(atoi(argv[2]), argv[3], argv[4]);
    fprintf(stderr, "usage: %s client HOST PORT | server PORT CERT KEY\n", argv[0]);
    return 2;
}
