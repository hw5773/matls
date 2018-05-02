/**
 * @file mssl.c
 * @author Hyunwoo Lee
 * @date 25 Apr 2018
 * @brief The server side middlebox's functions
 */

#include <poll.h>
#include <fcntl.h>
#include <errno.h>

#include "server_side_mb.h"
#include "../common/logs.h"

int get_ssl_status(SSL *ssl, int n)
{
  int err;
  err = SSL_get_error(ssl, n);

  switch(err)
  {
    case SSL_ERROR_NONE:
      MA_LOG("SSL_ERROR_NONE");
      break;
    case SSL_ERROR_WANT_READ:
      MA_LOG("SSL_ERROR_WANT_READ");
      break;
    case SSL_ERROR_WANT_WRITE:
      MA_LOG("SSL_ERROR_WANT_WRITE");
      break;
    case SSL_ERROR_ZERO_RETURN:
      MA_LOG("SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_SYSCALL:
      MA_LOG("SSL_ERROR_SYSCALL");
      break;
    default:
      MA_LOG1d("SSL_SUCCESS", err);
  }

  return err;
}


void msg_callback(int write, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
  int i;
  unsigned char *p;
  p = (unsigned char *)buf;

  printf("write operation? %d\n", write);
  printf("version? 0x%x\n", version);
  printf("content type? ");

  switch(content_type)
  {
    case 20:
      printf("change cipher spec\n");
      break;
    case 21:
      printf("alert\n");
      break;
    case 22:
      printf("handshake\n");
      break;
    case 23:
      printf("application data\n");
      break;
    default:
      printf("invalid\n");
  }

  for (i=0; i<len; i++)
  {
    printf("%02X ", p[i]);
    if (i % 8 == 7)
      printf("\n");
  }
  printf("\n");
}

int ssl_init(char *cert, char *priv, char *capath)
{
  MA_LOG("Initialize SSL");

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  printf("SSL library version: %s\n", SSLeay_version(SSLEAY_VERSION));

  ctx = SSL_CTX_new(TLSv1_2_server_method());
  if (!ctx)
  {
    perror("SSL_CTX_new error");
    exit(EXIT_FAILURE);
  }

  if (SSL_CTX_load_verify_locations(ctx, NULL, capath) != 1) goto err;
  if (SSL_CTX_set_default_verify_paths(ctx) != 1) goto err;
  if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0) goto err;
  if (SSL_CTX_use_PrivateKey_file(ctx, priv, SSL_FILETYPE_PEM) <= 0) goto err;
  if (SSL_CTX_check_private_key(ctx) != 1) goto err;

//  SSL_CTX_set_msg_callback(ctx, msg_callback);
  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  return SUCCESS;

err:
  return FAILURE;
}

int ssl_client_init(struct pollfd *client, struct sockaddr *peer_addr, 
    socklen_t peer_addr_len, struct client_info *p)
{
  ssize_t n;
  memset(p, 0, sizeof(struct client_info));

  p->client = client;
  p->ret = 0;
  p->peer_addr = peer_addr;
  p->peer_addr_len = peer_addr_len;
  p->rbio = BIO_new(BIO_s_mem());
  p->wbio = BIO_new(BIO_s_mem());
  p->ssl = SSL_new(ctx);

  p->rbuf = (struct buf_mem *)malloc(sizeof(struct buf_mem));
  p->rbuf->max = DEFAULT_BUF_SIZE;
  p->rbuf->len = 0;
  p->rbuf->mem = (unsigned char *)malloc(p->rbuf->max);

  p->wbuf = (struct buf_mem *)malloc(sizeof(struct buf_mem));
  p->wbuf->max = DEFAULT_BUF_SIZE;
  p->wbuf->len = 0;
  p->wbuf->mem = (unsigned char *)malloc(p->wbuf->max);

//  fcntl(p->client->fd, F_SETFL, O_NONBLOCK);
//  BIO_set_nbio(p->rbio, 1);
//  BIO_set_nbio(p->wbio, 1);

  p->client->events = POLLIN | POLLERR | POLLHUP | POLLNVAL;
  SSL_set_accept_state(p->ssl);
  SSL_set_bio(p->ssl, p->rbio, p->wbio);

  return SUCCESS;
err:
  return FAILURE;
}

int ssl_io_operation(struct client_info *p)
{
  unsigned char buf[DEFAULT_BUF_SIZE];
  ssize_t n;
  int ret;

  ret = SSL_get_error(p->ssl, p->ret);

  switch(ret)
  {
    case SSL_ERROR_NONE:
      MA_LOG("I/O operation completed");
      break;
    case SSL_ERROR_ZERO_RETURN:
      MA_LOG("SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_SYSCALL:
      MA_LOG("SSL_ERROR_SYSCALL");
      goto err;
    case SSL_ERROR_SSL:
      MA_LOG("SSL_ERROR_SSL");
      break;
    case SSL_ERROR_WANT_READ:
      break;
    case SSL_ERROR_WANT_WRITE:
      MA_LOG("Wanting write operation");

      n = BIO_read(p->wbio, p->wbuf->mem + p->wbuf->len, p->wbuf->max - p->wbuf->len);
      p->wbuf->len += n;
      p->ret = n;
      MA_LOG1ld("Read from write buffer", n);

      while (p->wbuf->len == p->wbuf->max)
      {
        p->wbuf->mem = (unsigned char *)realloc(p->wbuf->mem, p->wbuf->max + DEFAULT_BUF_SIZE);
        p->wbuf->max += DEFAULT_BUF_SIZE;
        n = BIO_read(p->wbio, p->wbuf->mem + p->wbuf->len, p->wbuf->max - p->wbuf->len);
        p->wbuf->len += n;
        MA_LOG1ld("Read from write buffer", n);
      }
      p->ret = n;

      MA_LOG1d("In write buffer", p->wbuf->len);

      break;
    case SSL_ERROR_WANT_X509_LOOKUP:
      MA_LOG("Wanting to look up X.509");
      break;
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_WANT_ACCEPT:
      MA_LOG("Unwanted state");
      break;
    default:
      MA_LOG("Invalid state");
      goto err;
  }

  return SUCCESS;
err:
  MA_LOG("error happened");
  ssl_client_cleanup(p);
  return FAILURE;
}

int queue_to_write_buf(struct client_info *p, unsigned char *buf, ssize_t n)
{
  MA_LOG("queue to write buf");
  if (n > (p->wbuf->max - p->wbuf->len))
  {
    p->wbuf->mem = (unsigned char *)realloc(p->wbuf->mem, p->wbuf->max + DEFAULT_BUF_SIZE);

    if (!p->wbuf->mem)
      return -1;

    p->wbuf->max += DEFAULT_BUF_SIZE;
  }

  memcpy(p->wbuf->mem + p->wbuf->len, buf, n);

  MA_LOG1ld("to write size", n);
  p->wbuf->len += n;

  return n;
}
/*
int process_accept(struct client_info *p)
{
  MA_LOG("process accept");
  ssize_t n;
  int err, ret;
  unsigned char buf[DEFAULT_BUF_SIZE];

  n = SSL_accept(p->ssl);
  MA_LOG1ld("after accept", n);

  err = get_ssl_status(p->ssl, n);

  ret = 0;
  if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE))
  {
    do {
      n = BIO_read(p->wbio, buf, DEFAULT_BUF_SIZE);
      MA_LOG1ld("after read", n);
      if (n > 0)
      {
        n = queue_to_write_buf(p, buf, n);
        ret += n;
      }
      else if (!BIO_should_retry(p->wbio))
        return -1;
    } while (n > 0);
  }

  if (err == 1)
    return -1;

  MA_LOG1d("SSL_is_init_finished", SSL_is_init_finished(p->ssl));
  if (!SSL_is_init_finished(p->ssl))
    return 0;
  return n;
}
*/
int on_read_cb(struct client_info *p, char *src, size_t len)
{
  char buf[DEFAULT_BUF_SIZE];
  int n, err;

  while (len > 0)
  {
    n = BIO_write(p->rbio, src, len);
    if (n <= 0)
      return -1;

    src += n;
    len -= n;

    if (!SSL_is_init_finished(p->ssl))
    {
      n = SSL_accept(p->ssl);
      err = get_ssl_status(p->ssl, n);

      if ((err == SSL_ERROR_WANT_READ) || (err == SSL_ERROR_WANT_WRITE))
        do {
          n = BIO_read(p->wbio, buf, sizeof(buf));
          if (n>0)
            queue_to_write_buf(p, buf, n);
          else if (!BIO_should_retry(p->wbio))
            return -1;
        } while (n > 0);

      if (err == 1)
        return -1;

      if (!SSL_is_init_finished(p->ssl))
        return 0;
    }
  }

  return 0;
}

int do_sock_read(struct client_info *p)
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(p->client->fd, buf, sizeof(buf));

  if (n > 0)
    return on_read_cb(p, buf, (size_t)n);
  else
     return -1;
}

int do_sock_write(struct client_info *p)
{
  MA_LOG("do_sock_write");
  ssize_t n = 0;

  n = write(p->client->fd, p->wbuf->mem, p->wbuf->len);
  MA_LOG1ld("Write to Socket", n);

  if (n>0)
  {
    if ((size_t)n < p->wbuf->len)
      memmove(p->wbuf->mem, p->wbuf->mem + n, p->wbuf->len - n);
    p->wbuf->len -= n;
    p->wbuf->mem = (unsigned char *)realloc(p->wbuf->mem, p->wbuf->len);
    return 0;
  }
  else
    return -1;
}

void ssl_client_cleanup(struct client_info *p)
{
  close(p->client->fd);
  p->client->fd = -1;
  SSL_free(p->ssl);
}
