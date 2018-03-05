/**
 * @file test_record.c
 * @author Hyunwoo Lee
 * @date 5 Mar 2018
 * @brief This file is a test application for the modification record
 */

#include "record.h"

int main(int argc, char *argv[])
{
  MOD_RECORD *mr;
  unsigned char *msg = "test message";
  int mlen = strlen(msg);

  APP_LOG1d("message length", msg_length);

  SECURITY_PARAMS sp;
  sp.mac_length = DEFAULT_MAC_LENGTH;

  init_record(&mr, sp.mac_length);

  add_endpoint_mac(&sp, mr, msg, mlen, key, klen);

  free_record(mr);
  return 0;
}
