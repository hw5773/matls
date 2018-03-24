#include <stdio.h>
#include <mssl/mssl.h>
#include <mssl/logs.h>

#define MSSL_CONFIG_FILE "config/mos.conf"

int main(int argc, char *argv[])
{
  if (mssl_init(MSSL_CONFIG_FILE) < 0)
  {
    MA_LOG("Error in init");
    return -1;
  }

  MA_LOG("Init Success");
  return 0;
}
