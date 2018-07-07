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
#include <pthread.h>

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

#ifdef DEBUG
#define PRINTK(msg, arg1, arg2) \
  fprintf(stderr, "[matls] %s: %s (%d bytes) \n", __func__, msg, arg2); \
  for (idx=0; idx<arg2; idx++) \
  { \
    if (idx % 10 == 0) \
      fprintf(stderr, "\n"); \
    fprintf(stderr, "%02X ", arg1[idx]); \
  } \
  fprintf(stderr, "\n");
#else
#define PRINTK(msg, arg1, arg2) 
#endif /* DEBUG */

unsigned long get_current_microseconds();

#ifdef TIME_LOG
unsigned long mstart, mend;
#define MSTART(msg, side) \
	mstart = get_current_microseconds(); \
	printf("[TT] %s:%s:%d: %s) %s start\n", __FILE__, __func__, __LINE__, side, msg);
#define MEND(msg, side) \
	mend = get_current_microseconds(); \
	printf("[TT] %s:%s:%d: %s) %s end: %lu us\n", __FILE__, __func__, __LINE__, side, msg, mend - mstart);
#define MEASURE(msg, side) \
	printf("[TT] %s:%s:%d: %s) %s: %lu\n", __FILE__, __func__, __LINE__, side, msg, get_current_microseconds());
#else
#define MSTART(msg, side)
#define MEND(msg, side)
#define MEASURE(msg, side) 
#endif /* TIME_MEASURE */

#ifdef LOGGER
typedef struct log_record
{
  char *name;
  unsigned long time;
} log_t;

#define NUM_OF_LOGS 20
#define CLIENT_HANDSHAKE_START 1
#define CLIENT_HANDSHAKE_END 2
#define CLIENT_CERT_VALIDATION_START 3
#define CLIENT_CERT_VALIDATION_END 4
#define CLIENT_FETCH_HTML_START 5
#define CLIENT_FETCH_HTML_END 6
#define CLIENT_EXTENDED_FINISHED_START 7
#define CLIENT_EXTENDED_FINISHED_END 8
#define CLIENT_TCP_CONNECT_START 9
#define CLIENT_TCP_CONNECT_END 10
#define CLIENT_MODIFICATION_RECORD_START 11
#define CLIENT_MODIFICATION_RECORD_END 12

int lidx;
FILE *log_file;
pthread_mutex_t rlock;

#define INITIALIZE_LOG(arr) \
  pthread_mutex_init(&rlock, NULL); \
  for (lidx=0; lidx<NUM_OF_LOGS; lidx++) \
    arr[lidx].time = 0;

#define RECORD_LOG(arr, n) \
  pthread_mutex_lock(&rlock); \
  arr[n].name = #n; \
  arr[n].time = get_current_microseconds(); \
  pthread_mutex_unlock(&rlock);

#define PRINT_LOG(arr) ({ \
  for ((lidx)=0; (lidx) < (NUM_OF_LOGS); (lidx)++) \
    printf("%s: %lu\n", arr[lidx].name, arr[lidx].time); \
  })

#define INTERVAL(arr, a, b) \
  printf("Time from %s to %s: %lu\n", arr[a].name, arr[b].name, arr[b].time - arr[a].time);

#define MIDDLEBOX_LOG "/home/versatile/time_log/middlebox.csv"
#define SERVER_LOG "/home/versatile/time_log/server.csv"

#define FINALIZE_LOG(arr, fname) \
  log_file = fopen(fname, "r"); \
  for (lidx=0; lidx<NUM_OF_LOGS; lidx++) { \
    if (arr[lidx].time == 0) \
      continue; \
    fprintf(log_file, "%s, %d, %lu\n", arr[lidx].name, lidx, arr[lidx].time); \
  } \
  fclose(log_file);

extern log_t time_log[NUM_OF_LOGS];
#else
#define INITIALIZE_LOG(arr) 
#define RECORD_LOG(arr, n)
#define PRINT_LOG(arr)
#define INTERVAL(arr, a, b)
#define FINALIZE_LOG(arr, fname)
#endif /* TIME_LOG */

#endif /* __MB_LOG__ */
