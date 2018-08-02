#include "proof.h"

// Main Function
int main(int argc, char *argv[])
{
	// Declare the variables needed
	BIO *server = NULL;
	BIO *server_key = NULL;
	BIO *out_bio = NULL;
	X509 *server_cert = NULL;
	X509 *mb_crt = NULL;
  FILE *mb_fp = NULL;
	EVP_PKEY *server_pub = NULL;
	EVP_PKEY *server_priv = NULL;
	int i, plen, slen, proof_length;

  unsigned char *proof, *proof_body, *sigblk, *p;
  mb_crt = X509_new();

  mb_fp = fopen("16.der", "r");
  printf("open 16.der file complete\n");
  mb_crt = d2i_X509_fp(mb_fp, NULL);
  printf("change it to X509 structure\n");

	OpenSSL_add_all_algorithms();
  printf("open all algorithms\n");
	ERR_load_BIO_strings();
  printf("load BIO strings\n");
	ERR_load_crypto_strings();
  printf("load crypto strings\n");

	// Initialize the BIOs for certs and keys
	server = BIO_new(BIO_s_file());
	server_key = BIO_new(BIO_s_file());
	out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  printf("set the structures complete\n");

	BIO_read_filename(server, "matls_cert.crt");
  printf("read cert file\n");
	BIO_read_filename(server_key, "matls_priv.pem");
  printf("read private key file\n");

	server_cert = PEM_read_bio_X509(server, NULL, 0, NULL);
  printf("read server bio to X509 structure\n");
	server_pub = X509_get_pubkey(server_cert);
  printf("read public key from X509 structure\n");
	server_priv = PEM_read_bio_PrivateKey(server_key, NULL, 0, NULL);
  printf("read private key from BIO\n");

	BIO_printf(out_bio, "Read Alice's Public Key >>>\n");
	PEM_write_bio_PUBKEY(out_bio, server_pub);

	BIO_printf(out_bio, "PROGRESS: Invoke make_proof_body()\n");
	make_proof_body(&proof_body, mb_crt, &plen);
  make_signature_block(&sigblk, proof_body, plen, server_priv, &slen);

  proof_length = 2 * TIME_LENGTH + slen;
  p = proof = (unsigned char *)malloc(proof_length);
  memcpy(p, proof_body, 2 * TIME_LENGTH);
  p += 2 * TIME_LENGTH;
  memcpy(p, sigblk, slen);

  printf("final server proof\n");
  for (i=0; i<(2*TIME_LENGTH + slen); i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", proof[i]);
  }
  printf("\n");

  verify_server_proof(proof, proof_length, mb_crt, server_pub);

  free(proof);

	return 0;
}

