#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdio.h>

unsigned long get_current_microseconds()
{
	struct timeval curr;
	gettimeofday(&curr, NULL);

	return curr.tv_sec * 1000000 + curr.tv_usec;
}

unsigned long get_process_nanoseconds()
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_nsec;
}
