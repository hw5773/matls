#ifndef __MB_LOG__
#define __MB_LOG__

#ifdef DEBUG
int log_idx;
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
#else
#define MB_LOG(msg)
#define MB_LOG1d(msg, arg1)
#define MB_LOG1x(msg, arg1)
#define MB_LOG1s(msg, arg1)
#define MB_LOG1lu(msg, arg1)
#endif /* DEBUG */

unsigned long get_current_microseconds();

#endif /* __MB_LOG__ */
