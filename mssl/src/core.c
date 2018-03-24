#include <unistd.h>

#include "../include/mssl/mssl.h"
#include "../include/mssl/logs.h"

int mssl_init()
{
  if (geteuid())
  {
    MA_LOG("Run the app as root!");
    exit(EXIT_FAILURE);
  }

  return 0;
}
