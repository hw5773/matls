#ifndef __MB_LOG__
#define __MB_LOG__

#ifdef DEBUG
#include <stdio.h>
int log_idx;
unsigned char ipb[4];
#define MB_LOG(msg) \
  printf("[MB] %s: %s\n", __func__, msg)
#define MB_LOG1d(msg, arg1) \
  printf("[MB] %s: %s: %d\n", __func__, msg, arg1);
#define MB_LOG1x(msg, arg1) \
  printf("[MB] %s: %s: %x\n", __func__, msg, arg1);
#define MB_LOG1s(msg, arg1) \
  printf("[MB] %s: %s: %s\n", __func__, msg, arg1);
#define MB_LOG1lu(msg, arg1) \
  printf("[MB] %s: %s: %lu\n", __func__, msg, arg1);
#define MB_LOGip(msg, ip) \
  ipb[0] = ip & 0xFF; \
  ipb[1] = (ip >> 8) & 0xFF; \
  ipb[2] = (ip >> 16) & 0xFF; \
  ipb[3] = (ip >> 24) & 0xFF; \
  printf("[MB] %s: %s: %d.%d.%d.%d\n", __func__, msg, ipb[0], ipb[1], ipb[2], ipb[3]);
#else
#define MB_LOG(msg)
#define MB_LOG1d(msg, arg1)
#define MB_LOG1x(msg, arg1)
#define MB_LOG1s(msg, arg1)
#define MB_LOG1lu(msg, arg1)
#define MB_LOGip(msg, ip)
#endif /* DEBUG */

unsigned long get_current_microseconds();

#endif /* __MB_LOG__ */
