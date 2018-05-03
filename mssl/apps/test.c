#include <stdio.h>
#include <mssl/mssl_api.h>
#include <mssl/logs.h>

#define MAX_CORES 16
#define MSSL_CONFIG_FILE "config/mos.conf"

static int g_core_limit = 1;

int main(int argc, char *argv[])
{
  char *fname = MSSL_CONFIG_FILE;
  struct mssl_conf mcfg;
  mctx_t mctx_list[MAX_CORES];

  g_core_limit = get_num_cpus();

  MA_LOG1d("g_core_limit", g_core_limit);

  if (mssl_init(fname) < 0)
  {
    MA_LOG("Error in init");
    return -1;
  }

  MA_LOG("Init Success");

  mssl_create_context(0);

  return 0;
}
