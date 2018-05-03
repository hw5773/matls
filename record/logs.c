/**
 * @file logs.c
 * @author Hyunwoo Lee
 * @date 5 Mar 2018
 * @brief This file is to define log functions
 */

#include "logs.h"

unsigned long get_current_microseconds()
{
  struct timeval curr;
  gettimeofday(&curr, NULL);

  return curr.tv_sec * 1000000 + curr.tv_usec;
}
