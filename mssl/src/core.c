#include <unistd.h>
#include <assert.h>

#include "../include/mssl/mssl.h"
#include "../include/mssl/logs.h"

#include "include/config.h"
#include "include/cpu.h"
#include "include/mssl.h"

static int running[MAX_CPUS] = {0};
static int sigint_cnt[MAX_CPUS] = {0};

int mssl_init(const char *config_file)
{
  int i, ret;

  if (geteuid())
  {
    MA_LOG("Run the app as root!");
    exit(EXIT_FAILURE);
  }

  num_cpus = get_num_cpus();
  MA_LOG1d("num_cpus", num_cpus);
  assert(num_cpus >= 1);

  for (i=0; i<num_cpus; i++)
  {
    g_mssl[i] = NULL;
    running[i] = FALSE;
    sigint_cnt[i] = 0;
  }

  ret = load_configuration_upper_half(config_file);
  if (ret)
  {
    MA_LOG("Error occured while loading configuration");
    return -1;
  }

  return 0;
}
