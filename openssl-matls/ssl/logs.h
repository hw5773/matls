/** 
 * @file logs.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define log messages
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>
#include <assert.h>
#include <errno.h>

#ifdef DEBUG
int log_idx;
unsigned char ipb[4];
#define MA_LOG(msg) \
  fprintf(stderr, "[matls] %s: %s\n", __func__, msg)
#define MA_LOG1d(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %d\n", __func__, msg, arg1);
#define MA_LOG1x(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %x\n", __func__, msg, arg1);
#define MA_LOG1p(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %p\n", __func__, msg, arg1);
#define MA_LOG1s(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %s\n", __func__, msg, arg1);
#define MA_LOG1lu(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %lu\n", __func__, msg, arg1);
#define MA_LOG1ld(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %ld\n", __func__, msg, arg1);
#define MA_LOG1u(msg, arg1) \
  fprintf(stderr, "[matls] %s: %s: %u\n", __func__, msg, arg1);
#define MA_LOGip(msg, ip) \
  ipb[0] = ip & 0xFF; \
  ipb[1] = (ip >> 8) & 0xFF; \
  ipb[2] = (ip >> 16) & 0xFF; \
  ipb[3] = (ip >> 24) & 0xFF; \
  fprintf(stderr, "[matls] %s: %s: %d.%d.%d.%d\n", __func__, msg, ipb[0], ipb[1], ipb[2], ipb[3]);
#define MA_LOG2s(msg, arg1, arg2) \
  fprintf(stderr, "[matls] %s: %s (%d bytes) ", __func__, msg, arg2); \
  for (log_idx=0; log_idx<arg2; log_idx++) \
  { \
    if (log_idx % 10 == 0) \
      fprintf(stderr, "\n"); \
    fprintf(stderr, "%02X ", arg1[log_idx]); \
  } \
  fprintf(stderr, "\n");
#define MA_LOGmac(msg, mac) \
  fprintf(stderr, "[matls] %s: %s: %x %x %x %x %x %x\n", __func__, msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#else
#define MA_LOG(msg)
#define MA_LOG1d(msg, arg1)
#define MA_LOG1x(msg, arg1)
#define MA_LOG1p(msg, arg1)
#define MA_LOG1s(msg, arg1)
#define MA_LOG1lu(msg, arg1)
#define MA_LOG1ld(msg, arg1)
#define MA_LOG1u(msg, arg1)
#define MA_LOGip(msg, ip)
#define MA_LOG2s(msg, arg1, arg2)
#define MA_LOGmac(msg, mac)
#endif /* DEBUG */

unsigned long get_current_microseconds();

#endif /* __MB_LOG__ */
