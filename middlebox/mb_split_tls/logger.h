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
