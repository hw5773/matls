/**
 * @file mssl.c
 * @author Hyunwoo Lee
 * @date 25 Apr 2018
 * @brief The server side middlebox's functions
 */

#include "server_side_mb.h"
#include "../common/logs.h"

void print_unencrypted_data(char *buf, size_t len)
{
  printf("%.*s", (int)len, buf);
}

void ssl_init(char *cert, char *priv, char *capath)
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

  SSL_CTX_set_options(ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
  return;

err:
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

void ssl_client_init(struct client_info *p)
{
  memset(p, 0, sizeof(struct client_info));

  p->rbio = BIO_new(BIO_s_mem());
  p->wbio = BIO_new(BIO_s_mem());
  p->ssl = SSL_new(ctx);

  SSL_set_accept_state(p->ssl);
  SSL_set_bio(p->ssl, p->rbio, p->wbio);

  p->io_on_read = print_unencrypted_data;
}

void ssl_client_cleanup(struct client_info *p)
{
  SSL_free(p->ssl);
  free(p->write_buf);
  free(p->encrypt_buf);
}

int ssl_client_want_write(struct client_info *p)
{
  return (p->write_len > 0);
}

static enum ssl_status get_ssl_status(SSL *ssl, int n)
{
  switch (SSL_get_error(ssl, n))
  {
    case SSL_ERROR_NONE:
      return SSL_STATUS_OK;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
      return SSL_STATUS_WANT_IO;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
      return SSL_STATUS_FAIL;
  }
}

int do_sock_write(struct client_info *p)
{
  ssize_t n = write(p->fd, p->write_buf, p->write_len);
  if (n > 0)
  {
    if ((size_t) n < p->write_len)
      memmove(p->write_buf, p->write_buf + n, p->write_len - n);
    p->write_len -= n;
    p->write_buf = (char *)realloc(p->write_buf, p->write_len);
    return 0;
  }
  return -1;
}

int do_sock_read(struct client_info *p)
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(p->fd, buf, sizeof(buf));

  if (n > 0)
    return on_read_cb(p, buf, (size_t)n);
  else
    return -1;
}

void do_stdin_read(struct client_info *p)
{
  char buf[DEFAULT_BUF_SIZE];
  ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
  if (n > 0)
    send_unencrypted_bytes(p, buf, (size_t)n);
}

int do_encrypt(struct client_info *p)
{
  int n;
  char buf[DEFAULT_BUF_SIZE];
  enum ssl_status status;

  if (!SSL_is_init_finished(p->ssl))
    return 0;

  while (p->encrypt_len > 0)
  {
    n = SSL_write(p->ssl, p->encrypt_buf, p->encrypt_len);
    status = get_ssl_status(p->ssl, n);

    if (n > 0)
    {
      if ((size_t) n < p->encrypt_len)
        memmove(p->encrypt_buf, p->encrypt_buf + n, p->encrypt_len - n);
      p->encrypt_len -= n;
      p->encrypt_buf = (char *)realloc(p->encrypt_buf, p->encrypt_len);

      do {
        n = BIO_read(p->wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(p, buf, n);
        else if (!BIO_should_retry(p->wbio))
          return -1;
      } while (n > 0);
    }

    if (status == SSL_STATUS_FAIL)
      return -1;

    if (n == 0)
      break;
  }

  return 0;
}

int on_read_cb(struct client_info *p, char *src, size_t len)
{
  char buf[DEFAULT_BUF_SIZE];
  enum ssl_status status;
  int n;

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
      status = get_ssl_status(p->ssl, n);

      if (status == SSL_STATUS_WANT_IO)
        do {
          n = BIO_read(p->wbio, buf, sizeof(buf));
          if (n > 0)
            queue_encrypted_bytes(p, buf, n);
          else if (!BIO_should_retry(p->wbio))
            return -1;
        } while (n > 0);

      if (status == SSL_STATUS_FAIL)
        return -1;

      if (!SSL_is_init_finished(p->ssl))
        return 0;
    }

    do {
      n = SSL_read(p->ssl, buf, sizeof(buf));
      if (n > 0)
        p->io_on_read(buf, (size_t) n);
    } while (n > 0);

    status = get_ssl_status(p->ssl, n);

    if (status == SSL_STATUS_WANT_IO)
      do {
        n = BIO_read(p->wbio, buf, sizeof(buf));
        if (n > 0)
          queue_encrypted_bytes(p, buf, n);
        else if (!BIO_should_retry(p->wbio))
          return -1;
      } while (n > 0);

    if (status == SSL_STATUS_FAIL)
      return -1;
  }

  return 0;
}

void send_unencrypted_bytes(struct client_info *p, const char *buf, size_t len)
{
  p->encrypt_buf = (char *)realloc(p->encrypt_buf, p->encrypt_len + len);
  memcpy((p->encrypt_buf) + (p->encrypt_len), buf, len);
  p->encrypt_len += len;
}

void queue_encrypted_bytes(struct client_info *p, const char *buf, size_t len)
{
  p->write_buf = (char *)realloc(p->write_buf, p->write_len + len);
  memcpy(p->write_buf + p->write_len, buf, len);
  p->write_len += len;
}
