/**
 * @file test_record.c
 * @author Hyunwoo Lee
 * @date 5 Mar 2018
 * @brief This file is a test application for the modification record
 */

#include "record.h"
#include "logs.h"

int main(int argc, char *argv[])
{
  MOD_RECORD *mr;
  unsigned char *msg = "test message";
  int mlen = strlen(msg);
  int i;

  APP_LOG1d("message length", mlen);

  SECURITY_PARAMS sp;
  sp.hash_function = EVP_sha256();
  sp.hash_length = SHA256_DIGEST_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;
  sp.mac_length = DEFAULT_MAC_LENGTH;

  unsigned char secret[sp.key_length];

  for (i=0; i<sp.key_length; i++)
    secret[i] = i;

  init_record(&mr, sp.mac_length);

  add_source_mac(&sp, mr, msg, mlen, secret, sp.key_length);

  free_record(mr);
  return 0;
}
