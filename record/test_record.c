/**
 * @file test_record.c
 * @author Hyunwoo Lee
 * @date 5 Mar 2018
 * @brief This file is a test application for the modification record
 */

#include "record.h"
#include "logs.h"
#include "errors.h"

int main(int argc, char *argv[])
{
  int num_of_ids = NUM_OF_IDS;

  if (argc == 2)
    num_of_ids = atoi(argv[1]);

  printf("Number of IDs: %d\n", num_of_ids);
  APP_LOG1d("Number of IDs", num_of_ids);

  MOD_RECORD *mr;
  unsigned char *msg1 = "test message";
  unsigned char *msg2 = "modified message";
  unsigned char *msg3 = "final message";
  unsigned long start, end;

  int i, j, verified;
  int mlen1 = strlen(msg1);
  int mlen2 = strlen(msg2);
  int mlen3 = strlen(msg3);

  SECURITY_PARAMS sp;
  sp.mac_algorithm = EVP_sha256();
  sp.mac_length = SHA256_DIGEST_LENGTH;
  sp.key_length = DEFAULT_KEY_LENGTH;

  unsigned char id[num_of_ids + 1][sp.key_length];
  unsigned char secret[num_of_ids + 1][sp.key_length];
  unsigned char msg[num_of_ids + 1][sp.key_length];
  unsigned char mlen[num_of_ids + 1];

  for (j=0; j<sp.key_length; j++)
  {
    secret[0][j] = j;
    id[0][j] = sp.key_length - j;
    msg[0][j] = 'a';
  }

  for (i=0; i<=num_of_ids; i++)
    mlen[i] = sp.key_length;

  APP_LOG2s("secret[0]", secret[0], sp.key_length);

  for (i=1; i<=num_of_ids; i++)
  {
    memcpy(secret[i], hash(&sp, secret[i-1], sp.key_length), sp.key_length);
    memcpy(id[i], hash(&sp, id[i-1], sp.key_length), sp.key_length);
    memcpy(msg[i], hash(&sp, msg[i-1], sp.key_length), sp.key_length);
  }

  APP_LOG("----- Initialize Modification Record -----");

  start = get_current_microseconds();
  init_record(&mr, sp.mac_length);
  end = get_current_microseconds();

  APP_LOG1us("Elapsed time for Initializing Modification Record", end - start);

  APP_LOG("----- Add Source MAC -----");
  start = get_current_microseconds();
  add_source_mac(&sp, mr, msg[0], mlen[0], secret[0], sp.key_length);
  end = get_current_microseconds();
  APP_LOG1us("Elapsed time for Adding Source MAC", end - start);

  for (i=1; i<=num_of_ids; i++)
  {
    APP_LOG("----- Add Global MAC -----");
    add_global_mac(&sp, mr, id[i], sp.mac_length, secret[i], sp.key_length, hash(&sp, msg[i-1], mlen[i-1]), sp.mac_length, msg[i], mlen[i]);
  }

  print_record(&sp, mr);

  int l;
  start = get_current_microseconds();
  unsigned char *tmp = serialize_record(&sp, mr, &l);
  end = get_current_microseconds();
  APP_LOG2s("Serialized", tmp, l+2);
  APP_LOG1us("Elapsed time for Serializing", end - start);

  start = get_current_microseconds();
  MOD_RECORD *m = deserialize_record(&sp, tmp, l+2);
  end = get_current_microseconds();
  print_record(&sp, m);
  APP_LOG1us("Elapsed time for Deserializing", end - start);

  start = get_current_microseconds();
  verified = verify_record(&sp, m, hash(&sp, msg[num_of_ids], mlen[num_of_ids]), id, secret, num_of_ids);
  end = get_current_microseconds();
  APP_LOG1us("Elapsed time for Verifying the modification record with writers", end - start);

  if (verified == SUCCESS)
  {
    printf("Verified: %d / Elapsed time with %d writers: %lu us\n", verified, num_of_ids, end - start);
    APP_LOG("Verify Success!");
  }
  else
  {
    printf("Verified: %d / Elapsed time with %d writer: %lu us\n", verified, num_of_ids, end - start);
    APP_LOG("Verify Failed!");
  }

  free_record(mr);
  free_record(m);

  return 0;
}
