#include "proof.h"

int main()
{
  int proof_length, ret;
  FILE *fp, *mb_fp; 
  BIO *in, *server;
  unsigned char *proof;
  EVP_PKEY *serv_pub;
  X509 *mb_crt, *serv_crt;

  mb_crt = X509_new();
  mb_fp = fopen("16.der", "r");
  mb_crt = d2i_X509_fp(mb_fp, NULL);

  server = BIO_new(BIO_s_file());
  BIO_read_filename(server, "matls_cert.crt");
  serv_crt = PEM_read_bio_X509(server, NULL, 0, NULL);
  serv_pub = X509_get_pubkey(serv_crt);

  fp = fopen("proof.txt", "r");
  in = BIO_new_fp(fp, BIO_NOCLOSE);
  fseek(fp, 0L, SEEK_END);
  proof_length = ftell(fp);
  rewind(fp);

  proof = (unsigned char *)malloc(proof_length);
  proof_length = BIO_read(in, proof, proof_length);
  printf("read: %d\n", proof_length);
  
  ret = verify_server_proof(proof, proof_length, mb_crt, serv_pub);
  printf("result: %d\n", ret);

  return 0;
}
