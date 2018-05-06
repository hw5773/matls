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

int open_listener(int port);
SSL_CTX* init_server_ctx();
void load_certificates(SSL_CTX* ctx, char* cert_file, char* key_file);
void print_pubkey(EVP_PKEY *pkey);
BIO *bio_err;
void *mb_run(void *data);

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

	ctx = init_server_ctx();        /* initialize SSL */
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
  printf("[matls] start server loop\n");
  struct info *info;
  int client, ret;
  SSL *ssl;

  info = (struct info *)data;
  client = info->sock;
  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, client);
//  SSL_enable_mb(ssl);

  MA_LOG("[matls] start matls handshake");
  ret = SSL_accept(ssl);
  if (SSL_is_init_finished(ssl))
    MA_LOG("complete handshake");
  
  MA_LOG1d("[matls] end matls handshake", ret);

  SSL_free(ssl);
  close(client);
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

SSL_CTX* init_server_ctx()
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
	//SSL_CTX_set_msg_callback(ctx, msg_callback);
  SSL_CTX_set_sni_callback(ctx, sni_callback);

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
