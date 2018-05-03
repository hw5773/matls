#ifndef LOGGER
#define LOGGER

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>

#include "type.h"

extern FILE *fp;
extern char *filename;

//#define printLog(var) fprintf(fp, "%lu, %d, "#var"\n", getMicroSecond(), var); fflush(fp);

#define printLog(var) insertLog(var, #var);
#define log_close() fclose(fp);

int log_init(char *filen);
unsigned long getMicroSecond();
void insertLog(int var, char *tag);
void write_to_file();

#endif

