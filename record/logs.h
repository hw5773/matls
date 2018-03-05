/** 
 * @file logs.h
 * @author Hyunwoo Lee
 * @date 21 Feb 2018
 * @brief This file is to define log messages
 */

#ifndef __LOGS_H__
#define __LOGS_H__

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef DEBUG
int idx;
#define APP_LOG(msg) \
	printf("[matls] %s: %s\n", __func__, msg)
#define APP_LOG1d(msg, arg1) \
  printf("[matls] %s: %s: %d\n", __func__, msg, arg1)
#define APP_LOG1s(msg, arg1) \
  printf("[matls] %s: %s: %s\n", __func__, msg, arg1)
#define APP_LOG1lu(msg, arg1) \
  printf("[matls] %s: %s: %lu\n", __func__, msg, arg1)
#define APP_LOG1p(msg, arg1) \
  printf("[matls] %s: %s: %p\n", __func__, msg, arg1)
#define APP_LOG2s(msg, arg1, arg2) \
  printf("[matls] %s: %s (%d bytes) ", __func__, msg, arg2); \
  for(idx=0;idx<arg2;idx++) \
  { \
    if (idx % 10 == 0) \
      printf("\n"); \
    printf("%02X ", arg1[idx]); \
  } \
  printf("\n");
#else
#define APP_LOG(msg)
#define APP_LOG1d(msg, arg1)
#define APP_LOG1lu(msg, arg1)
#define APP_LOG1p(msg, arg1)
#define APP_LOG2s(msg, arg1, arg2)
#endif /* DEBUG */

unsigned long get_current_microseconds();

#endif /* __LOGS_H__ */
