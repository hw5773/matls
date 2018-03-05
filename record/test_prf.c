/**
 * @file test_prf.c
 * @author Hyunwoo Lee
 * @date 5 Mar 2018
 * @brief This file is to test prf functions
 */

#include "prf.h"
#include "logs.h"
#include "errors.h"

int main(int argc, char *argv[])
{
  SECURITY_PARAMS sp;
  unsigned char *msg = "test message";
  int mlen = strlen(msg);
  unsigned char result[128];
  int i, rlen;

  sp.hash_function = EVP_sha256();
  sp.mac_length = DEFAULT_MAC_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;

  unsigned char secret[sp.key_length];

  for (i=0; i<sp.key_length; i++)
    secret[i] = i;

  hmac_hash(&sp, secret, sp.key_length, msg, mlen, result, &rlen);
  APP_LOG1d("hmac length", rlen);

  return 0;
}
