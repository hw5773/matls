#ifndef __MB_SERVER_H__
#define __MB_SERVER_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#define DEFAULT_BUF_SIZE 1024
#define MAX_CLNT_SIZE 10

#define DEFAULT_CERT "matls_cert.crt"
#define DEFAULT_PRIV "matls_priv.pem"
#define DEFAULT_CA_PATH "/etc/ssl/certs"

SSL_CTX *ctx;

struct ssl_client
{
  int fd;

  SSL *ssl;

  BIO *rbio; /* SSL reads from, we write to. */
  BIO *wbio; /* SSL writes to, we read from. */

  /* Bytes waiting to be written to socket. This is data that has been generated
   * by the SSL object, either due to encryption of user input, or, writes
   * requires due to peer-requested SSL renegotiation. */
  char* write_buf;
  size_t write_len;

  /* Bytes waiting to be fed into the SSL object for encryption. */
  char* encrypt_buf;
  size_t encrypt_len;

  /* Method to invoke when unencrypted bytes are available. */
  void (*io_on_read)(char *buf, size_t len);
} client;

enum sslstatus { SSLSTATUS_OK, SSLSTATUS_WANT_IO, SSLSTATUS_FAIL};

void handle_error(const char *file, int lineno, const char *msg);
void die(const char *msg);
void print_unencrypted_data(char *buf, size_t len);

void ssl_init(char *cert, char *priv);
void ssl_client_init(struct ssl_client *p);
void ssl_client_cleanup(struct ssl_client *p);
int ssl_client_want_write(struct ssl_client *cp);
void send_unencrypted_bytes(const char *buf, size_t len);
void queue_encrypted_bytes(const char *buf, size_t len);
int on_read_cb(char *src, size_t len);

int do_encrypt();
int do_sock_read();
int do_sock_write();

void msg_callback(int write, int version, int content_type, 
    const void *buf, size_t len, SSL *ssl, void *arg);

#endif /* __MB_SERVER_H__ */
