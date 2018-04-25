#ifndef __SERVER_SIDE_MB_H__
#define __SERVER_SIDE_MB_H__

#include <stdio.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "../common/nio.h"
#include "../common/logs.h"

// concurrency
#define MAX_SERV_SIDE 1000
#define MAX_CLNT_SIDE 1000

enum ssl_status { SSL_STATUS_OK, SSL_STATUS_WANT_IO, SSL_STATUS_FAIL };

struct client_info
{
  int fd;
  //struct sockaddr *peer_addr;
  //socklen_t peer_addr_len;

  SSL *ssl;
  BIO *rbio;
  BIO *wbio;

  char *write_buf;
  size_t write_len;

  char *encrypt_buf;
  size_t encrypt_len;

  void (*io_on_read)(char *buf, size_t len);
};

void ssl_init(char *cert, char *priv, char *cacert);
void ssl_client_init(struct client_info *p);
void ssl_client_cleanup(struct client_info *p);

int ssl_client_want_write(struct client_info *p);

void send_unencrypted_bytes(struct client_info *p, const char *buf, size_t len);
void queue_encrypted_bytes(struct client_info *p, const char *buf, size_t len);
int on_read_cb(struct client_info *p, char *src, size_t len);

int do_encrypt(struct client_info *p);
void do_stdin_read(struct client_info *p);
int do_sock_read(struct client_info *p);
int do_sock_write(struct client_info *p);

void *client_run(void *data);

SSL_CTX *ctx;

#endif /* __SERVER_SIDE_MB_H__ */
