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
#include "logger.h"

#define FAIL    -1

int open_listener(int port);
SSL_CTX* init_server_CTX(BIO *outbio);
void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cacert_file, char* cert_file, char* key_file);
void print_pubkey(BIO *outbio, EVP_PKEY *pkey);
void msg_callback(int, int, int, const void *, size_t, SSL *, void *);
BIO *bio_err;

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *outbio = NULL;
	int server, client;
	char *portnum, *cert, *key, *cacert;
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>Test Alice's Page!</h1></body></html>";
	int response_len = strlen(response);
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);

	if ( count != 5 )
	{
		BIO_printf(outbio, "Usage: %s <portnum> <cert_file> <ca_cert_file> <key_file>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	cacert = strings[3];
	key = strings[4];

	ctx = init_server_CTX(outbio);        /* initialize SSL */
	load_certificates(outbio, ctx, cacert, cert, key);
	BIO_printf(outbio, "load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	unsigned char buf[2048];
	socklen_t len = sizeof(addr);

	while ((client = accept(server, (struct sockaddr *)&addr, &len)))
	{
		BIO_printf(outbio, "New Connection\n");
		ssl = SSL_new(ctx);/* get new SSL state with context */
		BIO_printf(outbio, "SSL_new() Success\n");
		SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		BIO_printf(outbio, "SSL_set_fd() Success\n");
		SSL_enable_mb(ssl);

		unsigned long hs_start, hs_end;
		BIO_printf(outbio, "PROGRESS: TLS Handshake Start\n");
		hs_start = get_current_microseconds();
		if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			ERR_print_errors_fp(stderr);
		hs_end = get_current_microseconds();
		BIO_printf(outbio, "PROGRESS: TLS Handshake Complete!\n");

		BIO_printf(outbio, "ELAPSED TIME: %lu us\n", hs_end - hs_start);

		int sent = 0;

		SSL_read(ssl, buf, sizeof(buf));
		sent = SSL_write(ssl, response, response_len);

		BIO_printf(outbio, "SERVER: HTTP Response Length: %d\n", response_len);
		BIO_printf(outbio, "SERVER: Send the HTTP Test Page Success: %d\n", sent);

		//close(client);
		//printf("free client\n");
		//SSL_free(ssl);
		//printf("free ssl\n");
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);         /* release context */
	close(client);
	close(server);          /* close server socket */

	return 0;
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
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

void msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	/*
	if (write_p == 2)
		printf("buf: %s\n", (unsigned char *)buf);
	else
	{
	}
	*/
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

SSL_CTX* init_server_CTX(BIO *outbio)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		BIO_printf(outbio, "SSL_CTX init failed!");
		abort();
	}

//	SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
	SSL_CTX_set_msg_callback(ctx, msg_callback);

	return ctx;
}

void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cacert_file, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_certificate_file success\n");

	if ( SSL_CTX_register_id(ctx) <= 0 )
	{
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_register_id success\n");

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_check_private_key success\n");

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}

// Print the public key from the certificate
void print_pubkey(BIO *outbio, EVP_PKEY *pkey)
{
	if (pkey)
	{
		switch (EVP_PKEY_id(pkey))
		{
			case EVP_PKEY_RSA:
				BIO_printf(outbio, "%d bit RSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				BIO_printf(outbio, "%d bit DSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_EC:
				BIO_printf(outbio, "%d bit EC Key\n", EVP_PKEY_bits(pkey));
				break;
			default:
				BIO_printf(outbio, "%d bit non-RSA/DSA/EC Key\n", EVP_PKEY_bits(pkey));
				break;
		}
	}

	if (!PEM_write_bio_PUBKEY(outbio, pkey))
		BIO_printf(outbio, "Error writing public key data in PEM format\n");
}

