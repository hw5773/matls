#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/time.h>
#include <sys/socket.h>
#include "mssl.h"
#include "../common/logs.h"

#define FAIL    -1
#define BUF_SIZE 1024

int open_listener(int port);
SSL_CTX* init_middlebox_ctx();
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void print_pubkey(EVP_PKEY *pkey);
BIO *bio_err;
void *mb_run(void *data);
int get_total_length(char *buf, int rcvd);

struct info
{
  int sock;
};

// Origin Server Implementation
int main(int count, char *strings[])
{  
	int server, client, rc, tidx = 0, i;
	char *portnum, *cert, *key, *forward_file;
  void *status;

	if ( count != 5 )
	{
		printf("Usage: %s <portnum> <cert_file> <key_file> <forward_file>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	key = strings[3];
  forward_file = strings[4];

	ctx = init_middlebox_ctx();        /* initialize SSL */
	load_certificates(ctx, cert, key);
  init_forward_table(forward_file);
  init_thread_config();

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (1)
	{
    client = accept(server, (struct sockaddr *)&addr, &len);

    if (client < 0)
    {
      MA_LOG("error in accept");
      exit(EXIT_FAILURE);
    }

    struct info *info = (struct info *)malloc(sizeof(struct info));
    info->sock = client;
    rc = pthread_create(&threads[tidx], &attr, mb_run, info);

    if (rc < 0)
    {
      MA_LOG("error in pthread create");
      exit(EXIT_FAILURE);
    }

    pthread_attr_destroy(&attr);

    for (i=0; i<MAX_THREADS; i++)
    {
      rc = pthread_join(threads[i], &status);

      if (rc)
      {
        MA_LOG("error in join");
        return 1;
      }
    }
	}

  free_forward_table();
	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

void *mb_run(void *data)
{
  MA_LOG("start server loop\n");
  struct info *info;
  int client, ret, rcvd, sent, tot_len = -1, head_len = -1, body_len = -1;
  unsigned char buf[BUF_SIZE];

  SSL *ssl;

  info = (struct info *)data;
  client = info->sock;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);

#ifdef MATLS
  SSL_enable_mb(ssl);
  MA_LOG("matls enabled");
#else
  SSL_disable_mb(ssl);
  MA_LOG("split tls enabled");
#endif

  ret = SSL_accept(ssl);
  if (SSL_is_init_finished(ssl))
    MA_LOG("complete handshake");
  MA_LOG1d("end matls handshake", ret);

  while (!(SSL_is_init_finished(ssl) && SSL_is_init_finished(ssl->pair))) {}

  while (1)
  {
    rcvd = SSL_read(ssl, buf, BUF_SIZE);
    MA_LOG1d("Received from Client-side", rcvd);
    MA_LOG1s("Message from Client-side", buf);

    sent = SSL_write(ssl->pair, buf, rcvd);
    MA_LOG1d("Sent to Server-side", sent);

    do {
      rcvd = SSL_read(ssl->pair, buf, BUF_SIZE);
      MA_LOG1d("Received from Server-side", rcvd);
      MA_LOG1s("Message", buf);
      
      sent = SSL_write(ssl, buf, rcvd);
      MA_LOG1d("Sent to Client-side", sent);

      if (tot_len < 0)
        tot_len = get_total_length(buf, rcvd);

      MA_LOG1d("Total Length", tot_len);

      tot_len -= rcvd;

      if (tot_len <= 0)
        break;
    } while(1);

    break;
  }

  SSL_free(ssl);
  close(client);
}

int get_total_length(char *buf, int rcvd)
{
  int tot_len, head_len, body_len, index, tok_len;
  const char *clen = "Content-Length";
  char *token = NULL;
  char val[4];

  head_len = strstr(buf, "\r\n\r\n") - buf + 4;
  MA_LOG1d("Header Length", head_len);
  
  token = strtok(buf, "\n");

  while (token)
  {
    tok_len = strlen(token);
    index = strstr(token, ":") - token;

    if (strncmp(token, clen, index - 1) == 0)
    {
      memcpy(val, token + index + 1, tok_len - index - 1);
      body_len = atoi(val);
      MA_LOG1d("Body Length", body_len);
      break;
    }

    token = strtok(NULL, "\n");
  }

  tot_len = head_len + body_len;

  return tot_len;
}

int open_listener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, MAX_CLNT_SIZE) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

void apps_ssl_info_callback(const SSL *s, int where, int ret)
{
	const char *str;
	int w;

	w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) str = "SSL_connect";
	else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
	else str = "Undefined";

	if (where & SSL_CB_LOOP)
	{
		BIO_printf(bio_err, "%s:%s\n", str, SSL_state_string_long(s));
	}
	else if (where & SSL_CB_ALERT)
	{
		str = (where & SSL_CB_READ)? "read" : "write";
		BIO_printf(bio_err, "SSL3 alert %s:%s:%s\n",
				str,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
	}
	else if (where & SSL_CB_EXIT)
	{
		if (ret == 0)
			BIO_printf(bio_err, "%s:failed in %s\n",
				str, SSL_state_string_long(s));
		else if (ret < 0)
		{
			BIO_printf(bio_err, "%s:error in %s\n",
				str, SSL_state_string_long(s));
		}
	}
}

SSL_CTX* init_middlebox_ctx()
{   
	SSL_METHOD *method;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		printf("[matls] SSL_CTX init failed!");
		abort();
	}

	SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
	SSL_CTX_set_msg_callback(ctx, msg_callback);
  SSL_CTX_set_sni_callback(ctx, sni_callback);
  printf("set info callback, msg callback, sni callback complete\n");
  ctx->middlebox = 1;
  //SSL_CTX_is_middlebox(ctx);

	return ctx;
}

void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_use_certificate_file success\n");

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_check_private_key success\n");

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}
