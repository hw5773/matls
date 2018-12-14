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
#include <signal.h>
#include "logger.h"
#include "logs.h"
#include <netinet/tcp.h>

#define FAIL    -1
#define DHFILE  "dh1024.pem"

int open_listener(int port);
SSL_ctx* init_server_ctx();
void load_certificates(SSL_ctx* ctx, char* cert_file, char* key_file);
void load_dh_params(SSL_ctx *ctx, char *file);
void msg_callback(int, int, int, const void *, size_t, SSL *, void *);
BIO *bio_err;
log_t time_log[NUM_OF_LOGS];
char *rname;
char *fname;
int running = 1; 
FILE *fp;

void int_handler(int dummy)
{
  if (fp)
    fclose(fp);

  MA_LOG("End of experiment");
  running = 0;
  exit(0);
}

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_ctx *ctx;
	int server, client, sent = 0, rcvd = 0;
	char *portnum, *cert, *key;
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>Test Alice's Page!</h1></body></html>";
	size_t response_len;


	if ((count < 5) || (count > 6))
	{
		printf("Usage: %s <portnum> <cert_file> <key_file> <index_file> <log_file>\n", strings[0]);
		exit(0);
	}

  signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	key = strings[3];
  rname = strings[4];

  if (count == 6)
  {
    fname = strings[5];
    fp = fopen(fname, "w");
  }

  INITIALIZE_LOG(time_log);
	ctx = init_server_ctx();        /* initialize SSL */
  load_dh_params(ctx, DHFILE);
	load_certificates(ctx, cert, key);
	printf("load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	unsigned char buf[2048];
	socklen_t len = sizeof(addr);

	while (running)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
		  printf("New Connection\n");
		  ssl = SSL_new(ctx);/* get new SSL state with context */
		  printf("SSL_new() Success\n");
		  SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
      ssl->time_log = time_log;
		  printf("SSL_set_fd() Success\n");

		  unsigned long hs_start, hs_end, elapsed_time;
		  hs_start = get_process_nanoseconds();
		  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			  ERR_print_errors_fp(stderr);
      hs_end = get_process_nanoseconds();
      elapsed_time = hs_end - hs_start;

      if (elapsed_time < 0)
        elapsed_time += 1000000000L;
		  printf("ELAPSED TIME: %lu, %lu, %lu ns\n", hs_start, hs_end, elapsed_time);
      fprintf(fp, "%lu, %lu, %lu\n", hs_start, hs_end, elapsed_time);

		  rcvd = SSL_read(ssl, buf, sizeof(buf));
      printf("Request (%d): %s\n", rcvd, buf);
		  sent = SSL_write(ssl, response, response_len);

		  printf("SERVER: HTTP Response Length: %d\n", response_len);
		  printf("SERVER: Send the HTTP Test Page Success: %d\n", sent);

		  close(client);
		  SSL_free(ssl);
	  }
  }
	SSL_ctx_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

int open_listener(int port)
{   
  int sd, optval = 1;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

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

SSL_ctx* init_server_ctx(BIO *outbio)
{   
	SSL_METHOD *method;
	SSL_ctx *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
	ctx = SSL_ctx_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		printf("SSL_ctx init failed!");
		abort();
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();

  SSL_ctx_set_cipher_list(ctx, "DHE-RSA-AES256-SHA256");

#ifdef MATLS
  SSL_ctx_enable_mb(ctx);
#else
  SSL_ctx_disable_mb(ctx);
#endif /* MATLS */

	return ctx;
}

void load_certificates(SSL_ctx* ctx, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_ctx_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_ctx_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_ctx_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_use_certificate_file success\n");

  if (ctx->mb_enabled == 1)
  {
	  if ( SSL_ctx_register_id(ctx) <= 0 )
	  {
		  abort();
	  }
	  else
		  printf("SSL_ctx_register_id success\n");
  }

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_ctx_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_ctx_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_check_private_key success\n");

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}

// Load parameters from "dh1024.pem"
void load_dh_params(SSL_ctx *ctx, char *file){
  DH *ret=0;
  BIO *bio;

  if ((bio=BIO_new_file(file,"r")) == NULL){
    perror("Couldn't open DH file");
  }

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if(SSL_ctx_set_tmp_dh(ctx,ret) < 0){
    perror("Couldn't set DH parameters");
  }
}
