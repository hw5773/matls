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
  unsigned long start, end;
  int mlen = strlen(msg);
  int i;

  APP_LOG1d("message length", mlen);

  SECURITY_PARAMS sp;
  sp.mac_algorithm = EVP_sha256();
  sp.mac_length = SHA256_DIGEST_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;

  unsigned char secret1[sp.key_length];
  unsigned char secret2[sp.key_length];
  unsigned char secret3[sp.key_length];
  unsigned char secret4[sp.key_length];

  for (i=0; i<sp.key_length; i++)
  {
    secret1[i] = i;
    secret2[i] = sp.key_length - i;
    secret3[i] = 3;
    secret4[i] = 4;
  }

  start = get_current_microseconds();
  init_record(&mr, sp.mac_length);
  end = get_current_microseconds();

  APP_LOG1us("Elapsed time for Initializing Modification Record", end - start);

  start = get_current_microseconds();
  add_source_mac(&sp, mr, msg, mlen, secret1, sp.key_length);
  end = get_current_microseconds();

  APP_LOG1us("Elapsed time for Adding Source MAC", end - start);

  free_record(mr);
  return 0;
}
