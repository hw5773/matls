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
  printf("[matls] %s: %s\n", __func__, msg)
#define MA_LOG1d(msg, arg1) \
  printf("[matls] %s: %s: %d\n", __func__, msg, arg1);
#define MA_LOG1x(msg, arg1) \
  printf("[matls] %s: %s: %x\n", __func__, msg, arg1);
#define MA_LOG1s(msg, arg1) \
  printf("[matls] %s: %s: %s\n", __func__, msg, arg1);
#define MA_LOG1lu(msg, arg1) \
  printf("[matls] %s: %s: %lu\n", __func__, msg, arg1);
#define MA_LOGip(msg, ip) \
  ipb[0] = ip & 0xFF; \
  ipb[1] = (ip >> 8) & 0xFF; \
  ipb[2] = (ip >> 16) & 0xFF; \
  ipb[3] = (ip >> 24) & 0xFF; \
  printf("[matls] %s: %s: %d.%d.%d.%d\n", __func__, msg, ipb[0], ipb[1], ipb[2], ipb[3]);
#define MA_LOG2s(msg, arg1, arg2) \
  printf("[matls] %s: %s (%d bytes) ", __func__, msg, arg2); \
  for (log_idx=0; log_idx<arg2; log_idx++) \
  { \
    if (log_idx % 10 == 0) \
      printf("\n"); \
    printf("%02X ", arg1[log_idx]); \
  } \
  printf("\n");
#define MA_LOGmac(msg, mac) \
  printf("[matls] %s: %s: %x %x %x %x %x %x\n", __func__, msg, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
#else
#define MA_LOG(msg)
#define MA_LOG1d(msg, arg1)
#define MA_LOG1x(msg, arg1)
#define MA_LOG1s(msg, arg1)
#define MA_LOG1lu(msg, arg1)
#define MA_LOGip(msg, ip)
#define MA_LOG2s(msg, arg1, arg2)
#define MA_LOGmac(msg, mac)
#endif /* DEBUG */

unsigned long get_current_microseconds();

#endif /* __MB_LOG__ */
