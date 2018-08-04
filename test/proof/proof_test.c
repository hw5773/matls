#include "proof.h"

// Main Function
int main(int argc, char *argv[])
{
	// Declare the variables needed
	BIO *server = NULL;
	BIO *server_key = NULL;
	BIO *out_bio = NULL;
  BIO *out = NULL;
	X509 *server_cert = NULL;
	X509 *mb_crt = NULL;
  FILE *mb_fp = NULL, *fp = NULL;
	EVP_PKEY *server_pub = NULL;
	EVP_PKEY *server_priv = NULL;
	int i, plen, slen, proof_length;

  unsigned char *proof, *proof_body, *sigblk, *p;
  mb_crt = X509_new();

  mb_fp = fopen("15.der", "r");
  printf("open 15.der file complete\n");
  mb_crt = d2i_X509_fp(mb_fp, NULL);
  fclose(mb_fp);

	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();

	// Initialize the BIOs for certs and keys
	server = BIO_new(BIO_s_file());
	server_key = BIO_new(BIO_s_file());
	out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);

	BIO_read_filename(server, "matls_cert.crt");
	BIO_read_filename(server_key, "matls_priv.pem");

	server_cert = PEM_read_bio_X509(server, NULL, 0, NULL);
	server_pub = X509_get_pubkey(server_cert);
	server_priv = PEM_read_bio_PrivateKey(server_key, NULL, 0, NULL);

	PEM_write_bio_PUBKEY(out_bio, server_pub);

	make_proof_body(&proof_body, mb_crt, &plen);
  make_signature_block(&sigblk, proof_body, plen, server_priv, &slen);

  proof_length = 2 * TIME_LENGTH + slen;
  p = proof = (unsigned char *)malloc(proof_length);
  memcpy(p, proof_body, 2 * TIME_LENGTH);
  p += 2 * TIME_LENGTH;
  memcpy(p, sigblk, slen);

  verify_server_proof(proof, proof_length, mb_crt, server_pub);
  printf("verify server proof\n");

  fp = fopen("proof.txt", "w");
  out = BIO_new_fp(fp, BIO_NOCLOSE);
  BIO_write(out, proof, proof_length);
  BIO_free(out);

  free(proof);
  fclose(fp);

	return 0;
}

