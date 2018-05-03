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
  unsigned char *result;
  int i, rlen;

  APP_LOG("Start test prf application");

  sp.mac_algorithm = EVP_sha256();
  sp.mac_length = SHA256_DIGEST_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;

  unsigned char secret[sp.key_length];
  unsigned char seed[16];
  unsigned char *label1 = "master secret";
  unsigned char *label2 = "client finished";

  for (i=0; i<sp.key_length; i++)
    secret[i] = i;

  for (i=0; i<16; i++)
    seed[i] = 16 - i;

  result = prf(&sp, secret, sp.key_length, label1, strlen(label1), seed, 16, &rlen);
  APP_LOG2s("Hash Result", result, rlen);
  free(result);

  result = prf(&sp, secret, sp.key_length, label2, strlen(label2), seed, 16, &rlen);
  APP_LOG2s("Hash Result", result, rlen);
  free(result);

  return 0;
}
