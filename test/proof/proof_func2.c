#include "proof.h"

// Make warrant content body
// Input
//   out: BIO for the standard output
//   content: warrant content
//   alice_pub: origin's public key
//   carol_pub: edge's public key
//   nid: signature type
//   len: length of the warrant content
// Output Success: 1, Failure: 0
int make_proof_body(unsigned char **content, X509 *mb_crt, int *len)
{
	// Declare the variables related to the relation
	BIO *h = NULL, *md = NULL;
  EVP_MD_CTX *ctx;
	unsigned char sha[SHA256_DIGEST_LENGTH];
  unsigned char tmp[TIME_LENGTH];
  unsigned char *crt, *p, *c;
	int i, rc, clen;
  time_t not_before, not_after;

  (*content) = (unsigned char *)malloc(2 * TIME_LENGTH + SHA256_DIGEST_LENGTH);
  c = (*content);

	// Declare the variables related to the timestamp
  not_before = time(NULL);
	not_after = not_before + 31536000;

  printf("not_before: %ld\n", not_before);
  printf("not_after: %ld\n", not_after);

	printf("Making the proof\n");
  if (!(ctx = EVP_MD_CTX_create())) goto err;
  if (!(h = BIO_new(BIO_s_mem()))) goto err;
	if (!(md = BIO_new(BIO_f_md()))) goto err;
  if (!BIO_set_md(md, EVP_sha256())) goto err;
  BIO_push(md, h);

  not_before = time(NULL);
	not_after = not_before + 31536000;

  printf("not_before: %ld\n", not_before);
  printf("not_after: %ld\n", not_after);

  p = tmp;
  t2n8(not_before, p);
  rc = BIO_write(md, tmp, TIME_LENGTH);
  memcpy(c, tmp, TIME_LENGTH);
  c += TIME_LENGTH;
  if (rc != TIME_LENGTH)
  {
    printf("error in write not_before: %d\n", rc);
    exit(1);
  }

  p = tmp;
  t2n8(not_after, p);
  rc = BIO_write(md, tmp, TIME_LENGTH);
  memcpy(c, tmp, TIME_LENGTH);
  c += TIME_LENGTH;
  if (rc != TIME_LENGTH)
  {
    printf("error in write not_after: %d\n", rc);
    exit(1);
  }

  clen = i2d_X509(mb_crt, NULL);
  crt = (unsigned char *)malloc(clen);
  printf("crt before: %p\n", crt);
  clen = i2d_X509(mb_crt, &crt);
  printf("crt after: %p\n", crt);
  crt -= clen;
  printf("certificate length: %d\n", clen);

  rc = BIO_write(md, crt, clen);
  if (rc != clen)
  {
    printf("error in write crt\n");
    exit(1);
  }

	BIO_gets(md, sha, SHA256_DIGEST_LENGTH);
  memcpy(c, sha, SHA256_DIGEST_LENGTH);

	// Print the info
	printf("print proof hash\n");
	for (i=0; i<SHA256_DIGEST_LENGTH; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02X ", sha[i]);
	}
	printf("\n");

  *len = SHA256_DIGEST_LENGTH + 2 * TIME_LENGTH;
  printf("print proof body\n");
  for (i=0; i<(*len); i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", (*content)[i]);
  }
  printf("\n");

	return 1;
err:
  *len = -1;
  return -1;
}

// Make the signature block composed of (Signature Type || Signature Length || Signature)

int make_signature_block(unsigned char **sigblk, unsigned char *msg, int msg_len, EVP_PKEY *priv, int *sigblk_len)
{
	int i, rc, rc1, rc2;
	EVP_MD_CTX *ctx;
	unsigned char *sig, *p;
	size_t sig_len;
	uint16_t sig_type;

	ctx = EVP_MD_CTX_create();
	if (ctx == NULL)
	{
		printf("EVP_MD_CTX_create failed\n");
		goto err;
	}

	// Initialize the md according to nid
	rc1 = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
	rc2 = EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, priv);

	// Make the signature
	if (rc1 != 1)
	{
		printf("PROGRESS: Digest Init Failed\n");
		goto err;
	}


  for (i=0; i<msg_len; i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", msg[i]);
  }
  printf("\n");

	rc = EVP_DigestSignUpdate(ctx, msg, msg_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Update Failed\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, NULL, &sig_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	if (sig_len <= 0)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	printf("PROGRESS: Signature length: %d\n", (int)sig_len);
	sig = malloc(sig_len);

	if (sig == NULL)
	{
		printf("PROGRESS: OPENSSL_malloc error\n");
		goto err;
	}

	rc = EVP_DigestSignFinal(ctx, sig, &sig_len);
	if (rc != 1)
	{
		printf("PROGRESS: DigestSign Final Failed\n");
		goto err;
	}

	*sigblk_len = sig_len;
	*sigblk = (unsigned char *)malloc(*sigblk_len);
	p = *sigblk;
	memcpy(p, sig, sig_len);

	printf("PROGRESS: Sig in make warrant >>>\n");
	for (i=0; i<sig_len; i++)
	{
		if (i % 10 == 0)
			printf("\n");
		printf("%02X ", sig[i]);
	}
	printf("\n");

	printf("PROGRESS: Length of message: %d\n", msg_len);
	printf("PROGRESS: Length of signature: %d\n", (int)sig_len);

	OPENSSL_free(sig);
	EVP_MD_CTX_cleanup(ctx);

	return 1;

err:
	EVP_MD_CTX_cleanup(ctx);

	return 0;
}

// Verify the proof
// Input
// Output
int verify_server_proof(unsigned char *proof, int plen, X509 *crt, EVP_PKEY *serv)
{
  time_t seconds, not_before = 0, not_after = 0;
  int ret = -1, rc, clen, i;
  BIO *h = NULL, *md = NULL;
  EVP_MD_CTX *ctx;
  unsigned char sha[SHA256_DIGEST_LENGTH];
  unsigned char *p, *q, *cbuf;
  unsigned char *msg;

  if (!(ctx = EVP_MD_CTX_create())) goto err; 
  if (!(h = BIO_new(BIO_s_mem()))) goto err;
  if (!(md = BIO_new(BIO_f_md()))) goto err;
  if (!BIO_set_md(md, EVP_sha256())) goto err;
  if (!EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, serv)) goto err;
  BIO_push(md, h);

	seconds = time(NULL);
	p = proof;

  q = msg = (unsigned char *)malloc(2 * TIME_LENGTH + SHA256_DIGEST_LENGTH);

  BIO_write(md, p, TIME_LENGTH);
  memcpy(q, p, TIME_LENGTH);
  q += TIME_LENGTH;
	n2t8(p, not_before);

  BIO_write(md, p, TIME_LENGTH);
  memcpy(q, p, TIME_LENGTH);
  q += TIME_LENGTH;
	n2t8(p, not_after);

	printf("not before: %lu\n", not_before);
	printf("not after: %lu\n", not_after);

	if ((seconds < not_before) || (seconds > not_after))
	{
		printf("Error in validity period\n");
	}
	else
	{
		printf("Valid in validity period\n");
	}

  clen = i2d_X509(crt, NULL);
	cbuf = (unsigned char *)malloc(clen);
	i2d_X509(crt, &cbuf);
  BIO_write(md, cbuf, clen);
	BIO_gets(md, sha, SHA256_DIGEST_LENGTH);

  printf("hash of cert\n");
  for (i=0; i<SHA256_DIGEST_LENGTH; i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", sha[i]);
  }
  printf("\n");
  memcpy(q, sha, SHA256_DIGEST_LENGTH);

  printf("proof regenerated\n");
  for (i=0; i<(2*TIME_LENGTH + SHA256_DIGEST_LENGTH); i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", msg[i]);
  }
  printf("\n");

	rc = EVP_DigestVerifyUpdate(ctx, sha, SHA256_DIGEST_LENGTH);
	if (rc != 1) goto err;

  printf("digest update\n");

  printf("signature\n");
  for (i=0; i<(plen-2*TIME_LENGTH); i++)
  {
    if (i % 10 == 0)
      printf("\n");
    printf("%02X ", p[i]);
  }
  printf("\n");

	rc = EVP_DigestVerifyFinal(ctx, p, plen - 2 * TIME_LENGTH);
	if (rc != 1) goto err;

	printf("verification success");

  EVP_MD_CTX_cleanup(ctx);

  return 1;
err:
	printf("error\n");
  return 0;
}


