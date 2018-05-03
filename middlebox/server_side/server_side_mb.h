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
#define MAX_SERV_SIDE 10
#define MAX_CLNT_SIDE 10

struct buf_mem
{
  unsigned char *mem;
  int len;
  int max;
};

struct client_info
{
  int ret;
  struct pollfd *client;
  struct sockaddr *peer_addr;
  socklen_t peer_addr_len;

  SSL *ssl;
  BIO *rbio;
  BIO *wbio;

  struct buf_mem *rbuf;
  struct buf_mem *wbuf;
};

int ssl_init(char *cert, char *priv, char *cacert);
int ssl_client_init(struct pollfd *client, struct sockaddr *peer_addr, 
    socklen_t peer_addr_len, struct client_info *p);
int ssl_read_operation(struct client_info *p);
int ssl_write_operation(struct client_info *p);
int ssl_io_operation(struct client_info *p);
void ssl_client_cleanup(struct client_info *p);

int do_sock_read(struct client_info *p);
int do_sock_write(struct client_info *p);

int on_read(struct client_info *p);

void *client_run(void *data);

SSL_CTX *ctx;

#endif /* __SERVER_SIDE_MB_H__ */
