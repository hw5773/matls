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
  unsigned char *msg1 = "test message";
  unsigned char *msg2 = "modified message";
  unsigned long start, end;

  int i, j;
  int mlen1 = strlen(msg1);
  int mlen2 = strlen(msg2);

  SECURITY_PARAMS sp;
  sp.mac_algorithm = EVP_sha256();
  sp.mac_length = SHA256_DIGEST_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;

  unsigned char id[10][sp.key_length];
  unsigned char secret[10][sp.key_length];

  for (j=0; j<sp.key_length; j++)
  {
    secret[0][j] = j;
    id[0][j] = sp.key_length - j;
  }

  APP_LOG2s("secret[0]", secret[0], sp.key_length);

  for (i=1; i<10; i++)
  {
    memcpy(secret[i], hash(&sp, secret[i-1], sp.key_length), sp.key_length);
    memcpy(id[i], hash(&sp, id[i-1], sp.key_length), sp.key_length);
  }

  for (i=0; i<10; i++)
  {
    printf("----- (%d) ID / Global MAC Key ------\n", i);
    APP_LOG2s("id", id[i], sp.key_length);
    APP_LOG2s("global MAC key", secret[i], sp.key_length);
    printf("\n");
  }

  start = get_current_microseconds();
  init_record(&mr, sp.mac_length);
  end = get_current_microseconds();

  APP_LOG1us("Elapsed time for Initializing Modification Record", end - start);

  start = get_current_microseconds();
  add_source_mac(&sp, mr, msg1, mlen1, secret[0], sp.key_length);
  end = get_current_microseconds();

  APP_LOG1us("Elapsed time for Adding Source MAC", end - start);

  free_record(mr);
  return 0;
}
