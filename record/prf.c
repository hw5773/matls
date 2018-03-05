/** 
 * @file prf.c
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to implement the prf
 */

#include "prf.h"
#include "errors.h"
#include "logs.h"

unsigned char *hmac_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *msg, int mlen, unsigned char *result, int *rlen)
{
  APP_LOG("Perform HMAC");
  return HMAC(sp->hash_function, key, klen, msg, mlen, result, rlen);
}


unsigned char *p_hash(SECURITY_PARAMS *sp, unsigned char *key, int klen, unsigned char *seed, int slen, int idx, unsigned char *result, int *rlen)
{
  APP_LOG("Perform p_hash");

  if (idx == 0)
  {
    APP_LOG1d("idx is", idx);
    return seed;
  }

  return SUCCESS;
}

int prf(unsigned char *secret, unsigned char *label, unsigned char *seed, unsigned char *ret)
{
  APP_LOG("prf");
  return SUCCESS;
}
