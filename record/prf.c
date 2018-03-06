/** 
 * @file prf.c
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to implement the prf
 */

#include "prf.h"
#include "errors.h"
#include "logs.h"

/**
 * @brief Hash
 * @param sp Security parameters
 * @param msg Message
 * @param mlen Length of Message
 * @return Result (This must be freed outside)
 */
unsigned char *hash(SECURITY_PARAMS *sp, unsigned char *msg, int mlen)
{
  BIO *bio_md = NULL;
  BIO *bio_mem = NULL;
  unsigned char *result = (unsigned char *)malloc(sp->mac_length);
  int bytes;

  if (!(bio_md = BIO_new(BIO_f_md())))
    goto err;

  if (!BIO_set_md(bio_md, sp->mac_algorithm))
    goto md_err;

  if (!(bio_mem = BIO_new(BIO_s_mem())))
    goto md_err;

  BIO_push(bio_md, bio_mem);
  bytes = BIO_write(bio_md, msg, mlen);

  if (bytes != sp->mac_length)
    goto mem_err;

  BIO_gets(bio_md, result, sp->mac_length);

  BIO_free(bio_md);
  BIO_free(bio_mem);

  return result;

mem_err:
  BIO_free(bio_mem);
md_err:
  BIO_free(bio_md);
err:
  return NULL;
}

/**
 * @brief Perform HMAC
 * @param sp Security parameters
 * @param key Secret value
 * @param klen Length of the key
 * @param msg Message to be HMACed
 * @param mlen Length of the message
 * @param result Array of the result
 * @param rlen Length of the result
 * @return Result of HMAC
 */
unsigned char *hmac_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *msg, int mlen, unsigned char *result, int *rlen)
{
  APP_LOG("Perform HMAC");
  return HMAC(sp->mac_algorithm, key, klen, msg, mlen, result, rlen);
}

/**
 * @brief Perform p_hash defined in RFC5246
 * @param sp Security parameters
 * @param key Secret value
 * @param klen Length of the key
 * @param seed Seed value
 * @param slen Length of the seed
 * @param result Array of the result
 * @param rlen Length of the result
 * @return Result of HMAC
 */
unsigned char *p_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *seed, int slen, unsigned char *result, int rlen)
{
  APP_LOG("Perform p_hash");

  int i, num, alen, copy, index = 0;
  unsigned char *a;

  num = rlen / (sp->mac_length);

  if ((rlen % sp->mac_length) > 0)
    num += 1;

  a = seed;
  alen = slen;

  APP_LOG("Start Hashing");
  APP_LOG1d("Index", idx);

  for (i=0; i<num; i++)
  {
    a = hmac_hash(sp, key, klen, a, alen, NULL, &alen);
    
    if (index + alen > rlen)
      copy = rlen - index;
    else
      copy = alen;

    memcpy(result + index, a, copy);
    index += copy;

    APP_LOG1d("Index", index);
    APP_LOG2s("Hash", result, index);
  }

  return result;
}

/**
 * @brief Pseudorandom Function defined in RFC5246 
 * @param sp Security parameters
 * @param key Secret value
 * @param klen Length of the key
 * @param label Label
 * @param llen Length of the label
 * @param seed Seed value
 * @param slen Length of the seed
 * @param rlen Length of the result
 * @return Result of PRF (This value must be freed outside)
 */
unsigned char *prf(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *label, int llen, unsigned char *seed, int slen, int *rlen)
{
  APP_LOG("prf");

  int bytes = 0;
  unsigned char s[llen + slen];
  unsigned char *result;

  if (strncmp(label, "master secret", llen) == 0)
  {
    APP_LOG("master secret");
    bytes = MASTER_SECRET_LENGTH;
  }
  else if (strncmp(label, "client finished", llen) == 0)
  {
    APP_LOG("client finished");
    bytes = FINISHED_LENGTH;
  }
  else if (strncmp(label, "server finished", llen) == 0)
  {
    APP_LOG("server finished");
    bytes = FINISHED_LENGTH;
  }
  else
  {
    APP_LOG("no match");
    bytes = 0;
  }

  APP_LOG1d("bytes", bytes);
  result = (unsigned char *)malloc(bytes);

  memcpy(s, label, llen);
  memcpy(s + llen, seed, slen);

  (*rlen) = bytes;

  return p_hash(sp, key, klen, s, llen + slen, result, bytes);
}
