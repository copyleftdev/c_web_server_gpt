#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_BUFFER 4096
#define SERVER_PORT 80

// Function prototypes
void init_openssl();
void cleanup_openssl();
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
int create_server_socket(int port);
void handle_client_connection(SSL *ssl);

int main() {
    int server_socket, client_socket;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX *ctx;

    // Initialize OpenSSL
    init_openssl();
    ctx = create_ssl_context();
    configure_ssl_context(ctx);

    // Create server socket
    server_socket = create_server_socket(SERVER_PORT);

    // Server main loop
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Unable to accept client connection");
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handle_client_connection(ssl);
        }

        SSL_free(ssl);
        close(client_socket);
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    return 0;
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_ssl_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx) {
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int create_server_socket(int port) {
    int server_socket;
    struct sockaddr_in server_addr;

    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Failed to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to bind socket");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 10) < 0) {
        perror("Failed to listen on socket");
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

void handle_client_connection(SSL *ssl) {
    char buffer[MAX_BUFFER];
    int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);

    if (bytes > 0) {
        buffer[bytes] = '\0';
        printf("Received: %s\n", buffer);
        SSL_write(ssl, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, HTTPS world!", 64);
    } else {
        ERR_print_errors_fp(stderr);
    }
}
