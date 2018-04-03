#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <ctype.h>
#include "include/logs.h"
#include "include/tcp_rb.h"

#define FREE(X) do { free(x); x = NULL; } while (0)
#ifndef MIN
#define MIN(a, b) ((a)>(b)?(b):(a))
#endif
#ifndef MAX
#define MAX(a, b) ((a)>(b)?(a):(b))
#endif

inline loff_t seq2loff(tcprb_t *rb, uint32_t seq, uint32_t isn)
{
  loff_t off = seq - isn;

  while (off < rb->head)
    off += 0x100000000;

  return off;
}
