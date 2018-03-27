#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <assert.h>
#ifndef DISABLE_NUMA
#include <numa.h>
#endif

#define MAX_FILE_NAME 1024

int get_num_cpus()
{
  return sysconf(_SC_NPROCESSORS_ONLN);
}
