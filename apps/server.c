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
#define BUF_SIZE 16384

int open_listener(int port);
SSL_CTX* init_server_ctx();
void load_certificates(SSL_CTX *ctx, char* cert_file, char* key_file);
void load_dh_params(SSL_CTX *ctx, char *file);
void msg_callback(int, int, int, const void *, size_t, SSL *, void *);
BIO *bio_err;
log_t time_log[NUM_OF_LOGS];
char *rname;
char *fname;
int running = 1; 
FILE *fp, *resp;

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
	SSL_CTX *ctx;
	int server, client, sent = 0, rcvd = 0, cnt = 0, set = 0;
	char *portnum, *cert, *key, *response, *p;
	const char *header = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: ";
  const char *delimiter = "\r\n";
	size_t tlen, hlen, response_len, sz;


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

  resp = fopen(rname, "rb");
  fseek(resp, 0L, SEEK_END);
  sz = ftell(resp);
  fseek(resp, 0L, SEEK_SET);

  hlen = strlen(header);
  response = (unsigned char *)malloc(hlen + sz + 10);
  memset(response, 0x0, hlen + sz + 10);
  p = response;

  memcpy(p, header, hlen);
  p += hlen;
  sprintf(p, "%d", (int)sz);
  printf("Current: %s\n", response);
  tlen = strlen(response);
  p = response + tlen;
  printf("Current Length: %lu\n", tlen);
  memcpy(p, delimiter, 2);
  p += 2;
  memcpy(p, delimiter, 2);
  p += 2;
  fread(p, 1, sz, resp);
  fclose(resp);

  printf("Result: %s\n", response);
  response_len = strlen(response);
  printf("Final Length: %lu\n", response_len);

  INITIALIZE_LOG(time_log);
	ctx = init_server_ctx();        /* initialize SSL */
  load_dh_params(ctx, DHFILE);
	load_certificates(ctx, cert, key);
	printf("load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	unsigned char buf[BUF_SIZE];
  unsigned long start, end, curr;
	socklen_t len = sizeof(addr);

	while (running)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
		  MA_LOG("New Connection");
		  ssl = SSL_new(ctx);/* get new SSL state with context */
		  MA_LOG("SSL_new() Success");
		  SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
      ssl->time_log = time_log;
		  MA_LOG("SSL_set_fd() Success");

		  unsigned long hs_start, hs_end, elapsed_time;
		  hs_start = get_process_nanoseconds();
		  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			  ERR_print_errors_fp(stderr);
      hs_end = get_process_nanoseconds();
      elapsed_time = hs_end - hs_start;

      if (elapsed_time < 0)
        elapsed_time += 1000000000L;
		  MA_LOG("ELAPSED TIME: %lu, %lu, %lu ns", hs_start, hs_end, elapsed_time);
      fprintf(fp, "%lu, %lu, %lu\n", hs_start, hs_end, elapsed_time);

		  rcvd = SSL_read(ssl, buf, sizeof(buf));
      MA_LOG("Request (%d): %s", rcvd, buf);
		  sent = SSL_write(ssl, response, response_len);

		  MA_LOG("SERVER: HTTP Response Length: %ld", response_len);
		  MA_LOG("SERVER: Send the HTTP Test Page Success: %d", sent);
      cnt++;

      if (cnt > 0)
      {
        if (set == 0)
        {
          printf("Start Counting\n");
          start = get_current_microseconds();
          printf("Start Time: %lu\n", start);
          end = start + 10000000;
          printf("End Time: %lu\n", end);
          set++;
        }
        else if (set == 1)
        {
          curr = get_current_microseconds();
          if (curr >= end)
          {
            printf("Count: %d\n", cnt);
            cnt = 0;
            set++;
          }
        }
      }

		  close(client);
		  SSL_free(ssl);
	  }
  }
	SSL_CTX_free(ctx);         /* release context */
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
	if ( listen(sd, 1000) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
	return sd;
}

SSL_CTX* init_server_ctx(BIO *outbio)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		printf("SSL_ctx init failed!");
		abort();
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();

  SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-SHA256");

#ifdef MATLS
  SSL_CTX_enable_mb(ctx);
#else
  SSL_CTX_disable_mb(ctx);
#endif /* MATLS */

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
		printf("SSL_ctx_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_use_certificate_file success\n");

  if (ctx->mb_enabled == 1)
  {
	  if ( SSL_CTX_register_id(ctx) <= 0 )
	  {
		  abort();
	  }
	  else
		  printf("SSL_ctx_register_id success\n");
  }

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_ctx_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
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
void load_dh_params(SSL_CTX *ctx, char *file){
  DH *ret=0;
  BIO *bio;

  if ((bio=BIO_new_file(file,"r")) == NULL){
    perror("Couldn't open DH file");
  }

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if(SSL_CTX_set_tmp_dh(ctx,ret) < 0){
    perror("Couldn't set DH parameters");
  }
}
